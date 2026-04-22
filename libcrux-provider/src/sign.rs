use core::fmt::Debug;

use alloc::boxed::Box;
use alloc::vec::Vec;

use der::oid::Arc as OidArc;
use der::asn1::{BitString, OctetString, SetOfRef, UintRef};
use pkcs8::{ObjectIdentifier, PrivateKeyInfo};
use x509_cert::attr::Attribute;
use pkcs8::der::{Tagged};
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use der::{Any, Encode, FixedTag};

use libcrux::algorithms::{ecdsa, ed25519};
use libcrux::libcrux::signature::{self as libcrux_api, SigningKeyID, VerificationKeyType};
use libcrux_api::SigningKey as LibcruxSigningKey;
use libcrux_api::SignatureScheme as LibcruxSignatureScheme;

#[derive(Clone, Debug, Copy)]
pub enum EcdsaSignatureScheme {
    /// ECDSA backed by the NIST P256 curve. Currently the only NIST curve supported by libcrux
    #[allow(non_camel_case_types)]
    ECDSA_NISTP256_SHA256,
}

const LOCAL_KEY_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.21");

impl<Scheme> TryFrom<PrivateKeyDer<'_>> for LibcruxKeyId<Scheme> {
    type Error = pkcs8::Error;

    fn try_from(value: PrivateKeyDer<'_>) -> Result<Self, Self::Error> {
        match value {
            PrivateKeyDer::Pkcs8(der) => {
                type PkInfoType<'a> = PrivateKeyInfo<Any, OctetString, BitString, SetOfRef<'a, Attribute>>;

                let private_key_info: PkInfoType = pkcs8::PrivateKeyInfo::try_from(der.secret_pkcs8_der())?;
                let algo_oid_arcs: Vec<OidArc> = private_key_info.algorithm.oid.arcs().collect();

                match algo_oid_arcs.as_slice() {
                    // `id-ecPublicKey' from RFC 3279
                    [1, 2, 840, 10045, 2, 1] => {
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

                        let public_key = private_key_info.public_key.ok_or(pkcs8::Error::KeyMalformed)?;
                        let public_key = public_key.as_bytes().ok_or(pkcs8::Error::KeyMalformed)?;
                        let public_key = match scheme {
                            LibcruxSignatureScheme::EcDsaP256(ecdsa::DigestAlgorithm::Sha256) => {
                                decode_ecdsa_public_key(public_key.try_into().map_err(|_| pkcs8::Error::KeyMalformed)?)
                                    .map(VerificationKeyType::EcDsaP256)
                                    .map_err(|_| pkcs8::Error::KeyMalformed)?
                            }
                            LibcruxSignatureScheme::Ed25519 => {
                                let pk: ed25519::VerificationKey = ed25519::VerificationKey::from_bytes(public_key.try_into().map_err(|_| pkcs8::Error::KeyMalformed)?);
                                VerificationKeyType::Ed25519(libcrux::agent::signatures::Ed25519PublicKey::new(pk))       
                            }
                            _ => return Err(pkcs8::Error::KeyMalformed),
                        };

                        let attrs = private_key_info.attributes.ok_or(pkcs8::Error::KeyMalformed)?;
                        let id = attrs.get(0).ok_or(pkcs8::Error::KeyMalformed)?;

                        let id = match id.oid {
                            LOCAL_KEY_ID => &id.values.get(0).ok_or(pkcs8::Error::KeyMalformed)?,
                            _ => return Err(pkcs8::Error::KeyMalformed),
                        };

                        let id = match id.tag()  {
                            OctetString::TAG => id.value().try_into().map_err(|_| pkcs8::Error::KeyMalformed)?,
                            _ => return Err(pkcs8::Error::KeyMalformed),
                        };

                        Ok(LibcruxKeyId(libcrux_api::SigningKeyID::new(id, scheme, public_key)))
                    }
                    _ => Err(pkcs8::Error::KeyMalformed),
                }
            }
            _ => Err(pkcs8::Error::KeyMalformed),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LibcruxKeyId<Scheme> {
    sk: SigningKeyID<Scheme>
}

impl<Scheme: Debug + Sync + Send> SigningKey for LibcruxKeyId<Scheme> where LibcruxKeyId<Scheme>: Signer {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme()) {
            Some(Box::new(self.clone()))
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

impl<Scheme: Debug + Sync + Send> Signer for LibcruxKeyId<Scheme> {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let signature = self.0.sign(message)
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
        match self.0.scheme() {
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
