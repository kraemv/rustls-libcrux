use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use der::oid::Arc as OidArc;
use der::{Decode, Tag, Tagged};
use pkcs8::ObjectIdentifier;
use rand_core::TryRngCore;
use sec1::EcPrivateKey;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use der::{asn1::UintRef, Encode};

use libcrux::signature::{
    DigestAlgorithm, EcDsaP256Info, EcDsaP256PrivKey, EcDsaP256PrivateKey, EcDsaP256Signature,
    RsaPrivateKey, RsaPssKeyInfo, RsaPssPrivKey, RsaPssSigInfo, SigInfo, Signature, SigningKeyType,
};
use libcrux::{add_entry, sign_for_id, KeyStoreEntry, SecretKey};
use libcrux_sha2::sha256;

#[derive(Clone, Debug, Copy)]
pub enum EcdsaSignatureScheme {
    /// ECDSA backed by the NIST P256 curve. Currently the only NIST curve supported by libcrux
    #[allow(non_camel_case_types)]
    ECDSA_NISTP256_SHA256,
}

impl TryFrom<PrivateKeyDer<'_>> for LibcruxKeyId {
    type Error = pkcs8::Error;

    fn try_from(value: PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        todo!()
    }
}

#[derive(Clone, Debug)]
pub struct LibcruxKeyId {
    id: u128,
    scheme: SignatureScheme,
}

impl SigningKey for LibcruxKeyId {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme) {
            Some(Box::new(self.clone()))
        } else {
            None
        }
    }

    // copied from rustls, where it wasn't public
    fn algorithm(&self) -> SignatureAlgorithm {
        match self.scheme {
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

fn into_signing_error(_e: libcrux::signature::Error) -> rustls::Error {
    rustls::Error::General(String::from("Signing failed"))
}

impl Signer for LibcruxKeyId {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        match self.scheme {
            SignatureScheme::RSA_PSS_SHA256 => {
                let info = SigInfo::RsaPss(RsaPssSigInfo::new(DigestAlgorithm::Sha256, 0x20));
                sign_for_id(
                    self.id,
                    message,
                    Some(info),
                    &mut rand_core::OsRng.unwrap_mut(),
                )
                .map(|sig| sig.into_vec())
                .map_err(into_signing_error)
            }
            SignatureScheme::RSA_PSS_SHA384 => {
                let info = SigInfo::RsaPss(RsaPssSigInfo::new(DigestAlgorithm::Sha384, 0x20));
                sign_for_id(
                    self.id,
                    message,
                    Some(info),
                    &mut rand_core::OsRng.unwrap_mut(),
                )
                .map(|sig| sig.into_vec())
                .map_err(into_signing_error)
            }
            SignatureScheme::RSA_PSS_SHA512 => {
                let info = SigInfo::RsaPss(RsaPssSigInfo::new(DigestAlgorithm::Sha512, 0x20));
                sign_for_id(
                    self.id,
                    message,
                    Some(info),
                    &mut rand_core::OsRng.unwrap_mut(),
                )
                .map(|sig| sig.into_vec())
                .map_err(into_signing_error)
            }
            SignatureScheme::ECDSA_NISTP256_SHA256 => {
                let info = SigInfo::EcDsaP256(EcDsaP256Info::new(DigestAlgorithm::Sha256));
                let sig = sign_for_id(
                    self.id,
                    message,
                    Some(info),
                    &mut rand_core::OsRng.unwrap_mut(),
                );
                match sig {
                    Ok(Signature::EcDsaP256(val, _)) => {
                        der_encode_ecdsa_signature(&val).map_err(|_| {
                            rustls::Error::General(String::from(
                                "error der encoding ecdsa signature",
                            ))
                        })
                    }
                    Err(_) => Err(rustls::Error::General(String::from("Signing failed"))),
                    _ => Err(rustls::Error::General(String::from(
                        "error der encoding ecdsa signature",
                    ))),
                }
            }
            SignatureScheme::ED25519 => {
                sign_for_id(self.id, message, None, &mut rand_core::OsRng.unwrap_mut())
                    .map(|sig| sig.into_vec())
                    .map_err(into_signing_error)
            }
            _ => Err(rustls::Error::General(String::from("Unsupported scheme"))),
        }
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

fn compute_id(der: pki_types::PrivatePkcs8KeyDer) -> u128 {
    let id: [u8; 16] = sha256(der.secret_pkcs8_der())[..16].try_into().unwrap();
    u128::from_le_bytes(id)
}

impl TryFrom<PrivateKeyDer<'_>> for LibcruxSigningKey {
    type Error = pkcs8::Error;

    fn try_from(value: PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                let private_key_info = pkcs8::PrivateKeyInfo::try_from(der.secret_pkcs8_der())?;
                let algo_oid_arcs: Vec<OidArc> = private_key_info.algorithm.oid.arcs().collect();

                match algo_oid_arcs.as_slice() {
                    // `id-ecPublicKey' from RFC 3279
                    [1, 2, 840, 10045, 2, 1] => {
                        let parameter = private_key_info
                            .algorithm
                            .parameters
                            .ok_or(pkcs8::Error::KeyMalformed)?;
                        if parameter.tag() != Tag::ObjectIdentifier {
                            return Err(pkcs8::Error::KeyMalformed);
                        }

                        let parameter_oid =
                            ObjectIdentifier::from_bytes(parameter.value()).unwrap();
                        let parameter_oid_arcs: Vec<OidArc> = parameter_oid.arcs().collect();

                        let scheme = match parameter_oid_arcs.as_slice() {
                            [1, 2, 840, 10045, 3, 1, 7] => {
                                EcdsaSignatureScheme::ECDSA_NISTP256_SHA256
                            }
                            // [1, 3, 132, 0, 34] => EcdsaSignatureScheme::ECDSA_NISTP384_SHA384,
                            // [1, 3, 132, 0, 35] => EcdsaSignatureScheme::ECDSA_NISTP521_SHA512,
                            _ => return Err(pkcs8::Error::KeyMalformed),
                        };

                        let key = private_key_info.private_key;
                        let key = EcPrivateKey::try_from(key)
                            .map_err(|_| pkcs8::Error::KeyMalformed)?
                            .private_key
                            .to_vec();

                        Ok(Self::Ecdsa(key, scheme))
                    }

                    let parameter_oid = ObjectIdentifier::from_bytes(parameter.value()).unwrap();
                    let parameter_oid_arcs: Vec<OidArc> = parameter_oid.arcs().collect();

                    let scheme = match parameter_oid_arcs.as_slice() {
                        [1, 2, 840, 10045, 3, 1, 7] => EcdsaSignatureScheme::ECDSA_NISTP256_SHA256,
                        // [1, 3, 132, 0, 34] => EcdsaSignatureScheme::ECDSA_NISTP384_SHA384,
                        // [1, 3, 132, 0, 35] => EcdsaSignatureScheme::ECDSA_NISTP521_SHA512,
                        _ => return Err(pkcs8::Error::KeyMalformed),
                    };

                    let key = private_key_info.private_key;

                    let signing_key = match scheme {
                        EcdsaSignatureScheme::ECDSA_NISTP256_SHA256 => {
                            let key = EcDsaP256PrivateKey::try_from(key)
                                .map_err(|_| pkcs8::Error::KeyMalformed)?;
                            SigningKeyType::EcDsaP256(EcDsaP256PrivKey::new(
                                key,
                                EcDsaP256Info::new(DigestAlgorithm::Sha256),
                            ))
                        }
                    };

                    
                    let entry = KeyStoreEntry::new(compute_id(der), SecretKey::SigningKey(signing_key));
                    add_entry(entry);
                    Ok(())
                }
                // `rsaEncryption` from RFC3279 / PKCS#1
                [1, 2, 840, 113549, 1, 1, 1] => {
                    let mut decoder = der::SliceReader::new(private_key_info.private_key)?;
                    let rsa_priv_key = pkcs1::RsaPrivateKey::decode(&mut decoder)?;

                    if !matches!(rsa_priv_key.public_exponent.as_bytes(), [1, 0, 1]) {
                        return Err(pkcs8::Error::ParametersMalformed);
                    }

                    let n = rsa_priv_key.modulus.as_bytes();
                    let n = trim_leading_zeroes(n).to_vec();

                    let d = rsa_priv_key.private_exponent.as_bytes();
                    let d = trim_leading_zeroes(d).to_vec();
                    
                    let entry = KeyStoreEntry::new(
                        compute_id(der),
                        SecretKey::SigningKey(SigningKeyType::RsaPss(RsaPssPrivKey::new(
                            RsaPrivateKey::from_components(&n, &d)
                                .map_err(|_| pkcs8::Error::KeyMalformed)?,
                            RsaPssKeyInfo::new(DigestAlgorithm::Sha256),
                        ))),
                    );
                    add_entry(entry);
                    Ok(())
                }
                _ => Err(pkcs8::Error::KeyMalformed),
            }
        }
        _ => Err(pkcs8::Error::KeyMalformed),
    }
}

fn trim_leading_zeroes(mut buf: &[u8]) -> &[u8] {
    while let Some(leading) = buf.first() {
        if *leading == 0 {
            buf = &buf[481..];
        } else {
            break;
        }
    }
    buf
}

// copied from ecdsa crate, where it wasn't public
/// Create an ASN.1 DER encoded signature from big endian `r` and `s` scalar
/// components.
fn der_encode_ecdsa_signature(sig: &EcDsaP256Signature) -> der::Result<Vec<u8>> {
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
