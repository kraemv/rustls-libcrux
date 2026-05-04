#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use alloc::sync::Arc;
use alloc::vec::Vec;
use libcrux::agent::signatures::{EcDsaP256PublicKey, Ed25519PublicKey};
use libcrux::libcrux::signature::{EcDsaP256, Ed25519};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::PrivateKeyDer;

use der::Any;
use der::oid::Arc as OidArc;
use der::asn1::{BitString, OctetString, SetOfRef};
use pkcs8::PrivateKeyInfo;
use x509_cert::attr::Attribute;

mod aead;
mod hash;
mod hmac;
#[cfg(feature = "std")]
pub mod hpke;
mod kx;
// mod pq;
pub mod sign;
mod verify;

pub fn provider() -> CryptoProvider {
    CryptoProvider {
        cipher_suites: ALL_CIPHER_SUITES.to_vec(),
        kx_groups: kx::ALL_KX_GROUPS.to_vec(),
        signature_verification_algorithms: verify::ALGORITHMS,
        secure_random: &Provider,
        key_provider: &Provider,
    }
}

#[derive(Debug)]
struct Provider;

impl rustls::crypto::SecureRandom for Provider {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        use rand_core::TryRngCore;
        rand_core::OsRng
            .try_fill_bytes(bytes)
            .map_err(|_| rustls::crypto::GetRandomFailed)
    }
}

impl rustls::crypto::KeyProvider for Provider {
    fn load_private_key(
        &self,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        match key_der {
            PrivateKeyDer::Pkcs8(der) => {
                type PkInfoType<'a> = PrivateKeyInfo<Any, OctetString, BitString, SetOfRef<'a, Attribute>>;

                let private_key_info: PkInfoType = pkcs8::PrivateKeyInfo::try_from(der.secret_pkcs8_der())?;
                let algo_oid_arcs: Vec<OidArc> = private_key_info.algorithm.oid.arcs().collect();

                let parameter_oid: ObjectIdentifier = private_key_info
                    .algorithm
                    .parameters
                    .ok_or(pkcs8::Error::KeyMalformed)?
                    .to_ref()
                    .try_into().map_err(|_| pkcs8::Error::KeyMalformed)?;

                let parameter_oid_arcs: Vec<OidArc> = parameter_oid.arcs().collect();

                let scheme = match parameter_oid_arcs.as_slice() {
                    [1, 2, 840, 10045, 3, 1, 7] => LibcruxSignatureScheme::EcDsaP256(ecdsa::DigestAlgorithm::Sha256),
                    // [1, 3, 132, 0, 34] => EcdsaSignatureScheme::ECDSA_NISTP384_SHA384,
                    // [1, 3, 132, 0, 35] => EcdsaSignatureScheme::ECDSA_NISTP521_SHA512,
                    _ => return Err(pkcs8::Error::KeyMalformed),
                };

                let attrs = private_key_info.attributes.ok_or(pkcs8::Error::KeyMalformed)?;
                let id = attrs.get(0).ok_or(pkcs8::Error::KeyMalformed)?;

                let id = match id.oid {
                    LOCAL_KEY_ID => &id.values.get(0).ok_or(pkcs8::Error::KeyMalformed)?,
                    _ => return Err(pkcs8::Error::KeyMalformed),
                };

                let id: [u8; 32] = match id.tag()  {
                    OctetString::TAG => id.value().try_into().map_err(|_| pkcs8::Error::KeyMalformed)?,
                    _ => return Err(pkcs8::Error::KeyMalformed),
                };

                let public_key = private_key_info.public_key.ok_or(pkcs8::Error::KeyMalformed)?;
                let public_key = public_key.as_bytes().ok_or(pkcs8::Error::KeyMalformed)?;

                match algo_oid_arcs.as_slice() {
                    // `id-ecPublicKey' from RFC 3279
                    [1, 2, 840, 10045, 2, 1] => Ok(Arc::new(sign::LibcruxKeyId::<EcDsaP256, EcDsaP256PublicKey>::try_from(key_der)
                        .map_err( |err| {rustls::OtherError(Arc::new(err))}))),
                    [1, 2, 840, 10045, 2, 1] => Ok(Arc::new(sign::LibcruxKeyId::<Ed25519, Ed25519PublicKey>::try_from(key_der)
                        .map_err( |err| {rustls::OtherError(Arc::new(err))}))),
                }
            }
            _ => Err(rustls::Error::General(alloc::format!("{}", pkcs8::Error::KeyMalformed))),
        }
        
    }
}

static ALL_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

pub static TLS13_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::Sha256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(&hmac::Sha256Hmac),
        aead_alg: &aead::Chacha20Poly1305,
        quic: None,
    });

pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::Sha256,
            confidentiality_limit: u64::MAX,
        },
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: &[
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ],
        prf_provider: &rustls::crypto::tls12::PrfUsingHmac(&hmac::Sha256Hmac),
        aead_alg: &aead::Chacha20Poly1305,
    });
