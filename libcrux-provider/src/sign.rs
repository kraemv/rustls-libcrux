use core::fmt::Debug;

use alloc::boxed::Box;
use alloc::vec::Vec;

use der::oid::Arc as OidArc;
use der::asn1::{BitString, OctetString, SetOfRef, UintRef};
use libcrux::agent::signatures::{EcDsaP256PublicKey, Ed25519PublicKey};
use pkcs8::{ObjectIdentifier, PrivateKeyInfo};
use x509_cert::attr::Attribute;
use pkcs8::der::{Tagged};
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use der::{Any, Encode, FixedTag};

use libcrux::algorithms::{ecdsa, ed25519};
use libcrux::libcrux::signature::{self as libcrux_api, EcDsaP256, Ed25519, Sig, SigningKeyID, VerificationKey};
use libcrux_api::SigningKey as LibcruxSigningKey;
use libcrux_api::SignatureScheme as LibcruxSignatureScheme;

#[derive(Clone, Debug, Copy)]
pub enum EcdsaSignatureScheme {
    /// ECDSA backed by the NIST P256 curve. Currently the only NIST curve supported by libcrux
    #[allow(non_camel_case_types)]
    ECDSA_NISTP256_SHA256,
}

const LOCAL_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.21");

impl<Scheme, Vk> LibcruxKeyId<Scheme, Vk> 
where 
    Scheme: Sig,
    Vk: VerificationKey
{
    fn new(id: [u8; 32], verification_key: Vec<u8>, )

    fn try_from(value: PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                type PkInfoType<'a> = PrivateKeyInfo<Any, OctetString, BitString, SetOfRef<'a, Attribute>>;

                let private_key_info: PkInfoType = pkcs8::PrivateKeyInfo::try_from(der.secret_pkcs8_der())?;
                let algo_oid_arcs: Vec<OidArc> = private_key_info.algorithm.oid.arcs().collect();

                match algo_oid_arcs.as_slice() {
                    // `id-ecPublicKey' from RFC 3279
                    [1, 2, 840, 10045, 2, 1] => {
                        
                        match scheme {
                            LibcruxSignatureScheme::EcDsaP256(ecdsa::DigestAlgorithm::Sha256) => {
                                let vk = decode_ecdsa_public_key(public_key.try_into().map_err(|_| pkcs8::Error::KeyMalformed)?)
                                    .map_err(|_| pkcs8::Error::KeyMalformed)?;
                                let sk = libcrux_api::SigningKeyID::<EcDsaP256, EcDsaP256PublicKey>::new(id, vk);
                                Ok(Self{sk})
                            }
                            LibcruxSignatureScheme::Ed25519 => {
                                let vk = Ed25519PublicKey::new(ed25519::VerificationKey::from_bytes(public_key.try_into().map_err(|_| pkcs8::Error::KeyMalformed)?));
                                let sk = libcrux_api::SigningKeyID::<Ed25519, Ed25519PublicKey>::new(id, vk);
                                Ok(Self{sk})
                            }
                            _ => Err(pkcs8::Error::KeyMalformed),
                        }
                    }
                    _ => Err(pkcs8::Error::KeyMalformed),
                }
            }
            _ => Err(pkcs8::Error::KeyMalformed),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LibcruxKeyId<Scheme, Vk> 
where 
    Scheme: Sig,
    Vk: VerificationKey
{
    sk: SigningKeyID<Scheme, Vk>
}

impl<Scheme, Vk> SigningKey for LibcruxKeyId<Scheme, Vk>
where
    Scheme: Sig + Debug + Sync + Send + Clone + 'static,
    Vk: VerificationKey + Clone + 'static,
{
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&Scheme) {
            let key: LibcruxKeyId<Scheme, Vk> = self.clone();
            Some(Box::new(key))
        } else {
            None
        }
    }

    // copied from rustls, where it wasn't public
    fn algorithm(&self) -> SignatureAlgorithm {
        match self.scheme() {
            SignatureScheme::RSA_PKCS1_SHA1
            | SignatureScheme::RSA_PKCS1_SHA256
            | SignatureScheme::RSA_PKCS1_SHA384
            | SignatureScheme::RSA_PKCS1_SHA512
            | SignatureScheme::RSA_PSS_SHA256
            | SignatureScheme::RSA_PSS_SHA384
            | SignatureScheme::RSA_PSS_SHA512 => SignatureAlgorithm::RSA,
            SignatureScheme::ECDSA_SHA1_Legacy
            | SignatureScheme::ECDSA_NISTP256_SHA256
            | SignatureScheme::ECDSA_NISTP384_SHA384
            | SignatureScheme::ECDSA_NISTP521_SHA512 => SignatureAlgorithm::ECDSA,
            SignatureScheme::ED25519 => SignatureAlgorithm::ED25519,
            SignatureScheme::ED448 => SignatureAlgorithm::ED448,
            _ => SignatureAlgorithm::Unknown(0),
        }
    }
}

fn signing_error(msg: &str) -> rustls::Error {
    rustls::Error::General(msg.into())
}

impl<Scheme: Debug + Sync + Send, Vk> Signer for LibcruxKeyId<Scheme, Vk> 
where 
    Scheme: Sig,
    Vk: VerificationKey,
    LibcruxKeyId<Scheme, Vk>: LibcruxSigningKey,
{
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let signature = LibcruxSigningKey::sign(self, message)
             .map_err(|_| signing_error("signing failed"))
             .map(|signature| signature.into_vec());

        match self.scheme() {
            SignatureScheme::ECDSA_NISTP256_SHA256 => {
                signature
                    .and_then(|signature| signature.try_into().map_err(|_| signing_error("Signing failed")))
                    .and_then(|signature: [u8; 64]| der_encode_ecdsa_signature(&ecdsa::p256::Signature::from_bytes(signature)).map_err(|_| signing_error("Error DER-encoding ECDSA signature")))
            }

            _ => signature,
        }
    }

    fn scheme(&self) -> SignatureScheme {
        match self.sk.scheme() {
            LibcruxSignatureScheme::EcDsaP256(ecdsa::DigestAlgorithm::Sha256) => SignatureScheme::ECDSA_NISTP256_SHA256,
            LibcruxSignatureScheme::Ed25519 => SignatureScheme::ED25519,
            _ => SignatureScheme::Unknown(0)
        }
    }
}

// copied from ecdsa crate, where it wasn't public
/// Create an ASN.1 DER encoded signature from big endian `r` and `s` scalar
/// components.
fn der_encode_ecdsa_signature(sig: &ecdsa::p256::Signature) -> der::Result<Vec<u8>> {
    let (r, s) = sig.as_bytes();
    let r = UintRef::new(r)?;
    let s = UintRef::new(s)?;

    let mut bytes = [0u8; 73];
    let mut writer = der::SliceWriter::new(&mut bytes);

    writer.sequence((r.encoded_len()? + s.encoded_len()?)?, |seq| {
        seq.encode(&r)?;
        seq.encode(&s)
    })?;

    Ok(writer.finish()?.to_vec())
}

fn decode_ecdsa_public_key(public_key: [u8; 65]) -> Result<libcrux::agent::signatures::EcDsaP256PublicKey, pkcs8::Error> {
    if public_key[0] != 4u8 {
        return Err(pkcs8::Error::KeyMalformed);
    } 
    ecdsa::p256::PublicKey::try_from(&public_key[1..])
        .map(|pk| libcrux::agent::signatures::EcDsaP256PublicKey::new(pk, ecdsa::DigestAlgorithm::Sha256))
        .map_err(|_| pkcs8::Error::KeyMalformed)
}
