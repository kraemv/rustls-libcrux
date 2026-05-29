use core::fmt::Debug;

use alloc::boxed::Box;
use alloc::vec::Vec;

use der::asn1::UintRef;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use der::Encode;

use libcrux::algorithms::ecdsa;
use libcrux::libcrux::signature::{self as libcrux_api, Sig, SigningKeyID, VerificationKey};
use libcrux_api::SigningKey as LibcruxSigningKey;
use libcrux_api::SignatureScheme as LibcruxSignatureScheme;

#[derive(Clone, Debug, Copy)]
pub enum EcdsaSignatureScheme {
    /// ECDSA backed by the NIST P256 curve. Currently the only NIST curve supported by libcrux
    #[allow(non_camel_case_types)]
    ECDSA_NISTP256_SHA256,
}

#[derive(Clone, Debug)]
pub struct LibcruxKeyId<Scheme, Vk, const N: usize> 
where 
    Scheme: Sig,
    Vk: VerificationKey
{
    sk: SigningKeyID<Scheme, Vk>
}

impl<Scheme, Vk, const N: usize> LibcruxKeyId<Scheme, Vk, N> 
where 
    Scheme: Sig,
    Vk: VerificationKey
{
    pub fn new(sk: SigningKeyID<Scheme, Vk>) -> Self {
        Self{sk}
    }
}

impl<Scheme, Vk, const N: usize> SigningKey for LibcruxKeyId<Scheme, Vk, N>
where
    Scheme: Sig + Debug + Sync + Send + Clone + 'static,
    Vk: VerificationKey + Clone + 'static,
    SigningKeyID<Scheme, Vk>: LibcruxSigningKey<N>,
{
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme()) {
            let key: LibcruxKeyId<Scheme, Vk, N> = self.clone();
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

impl<Scheme: Debug + Sync + Send, Vk, const N: usize> Signer for LibcruxKeyId<Scheme, Vk, N> 
where 
    Scheme: Sig,
    Vk: VerificationKey,
    SigningKeyID<Scheme, Vk>: LibcruxSigningKey<N>,
{
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let signature = self.sk.sign(message)
             .map_err(|_| signing_error("signing failed"))
             .map(|signature| signature.into());

        // TODO: Find smart fix
        match self.scheme() {
            SignatureScheme::ECDSA_NISTP256_SHA256 => {
                signature
                    .and_then(|signature| signature.to_vec().try_into().map_err(|_| signing_error("Signing failed")))
                    .and_then(|signature: [u8; 64]| der_encode_ecdsa_signature(&ecdsa::p256::Signature::from_bytes(signature)).map_err(|_| signing_error("Error DER-encoding ECDSA signature")))
            }

            _ => signature.map(|sig| sig.to_vec()),
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
