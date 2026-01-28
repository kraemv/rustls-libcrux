use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use der::oid::Arc as OidArc;
use der::{Decode, Tag, Tagged};
use pkcs8::{PrivateKeyInfo, ObjectIdentifier};
use rand_core::TryRngCore;
use sec1::EcPrivateKey;
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use der::{asn1::UintRef, Encode};

use libcrux::sign_for_id;
use libcrux::signature::{EcDsaP256Signature, Signature};

#[derive(Clone, Debug, Copy)]
pub enum EcdsaSignatureScheme {
    /// ECDSA backed by the NIST P256 curve. Currently the only NIST curve supported by libcrux
    #[allow(non_camel_case_types)]
    ECDSA_NISTP256_SHA256,
}

impl TryFrom<PrivateKeyDer<'_>> for LibcruxKeyId {
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
                            [1, 2, 840, 10045, 3, 1, 7] => SignatureScheme::ECDSA_NISTP256_SHA256,
                            // [1, 3, 132, 0, 34] => EcdsaSignatureScheme::ECDSA_NISTP384_SHA384,
                            // [1, 3, 132, 0, 35] => EcdsaSignatureScheme::ECDSA_NISTP521_SHA512,
                            _ => return Err(pkcs8::Error::KeyMalformed),
                        };

                        let key = private_key_info.private_key;

                        let key_id = LibcruxKeyId {
                            id: key.try_into().map_err(|_| pkcs8::Error::KeyMalformed)?,
                            scheme,
                        };
                        Ok(key_id)
                    }
                    _ => Err(pkcs8::Error::KeyMalformed),
                }
            }
            _ => Err(pkcs8::Error::KeyMalformed),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LibcruxKeyId {
    id: [u8; 32],
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
            SignatureScheme::ECDSA_NISTP256_SHA256 => {
                let sig = sign_for_id(self.id, message);
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
            SignatureScheme::ED25519 => sign_for_id(self.id, message)
                .map(|sig| sig.into_vec())
                .map_err(into_signing_error),
            _ => Err(rustls::Error::General(String::from("Unsupported scheme"))),
        }
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
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
