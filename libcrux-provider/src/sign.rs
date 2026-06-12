use core::fmt::Debug;

use alloc::boxed::Box;
use alloc::vec::Vec;

use der::asn1::UintRef;
use rustls::sign::{Signer, SigningKey};
use rustls::{SignatureAlgorithm, SignatureScheme};

use der::Encode;

use libcrux::algorithms::ecdsa;
use libcrux::libcrux::signature::{SigningKey as LibcruxSigningKey, SignatureScheme as LibcruxSignatureScheme};

#[derive(Clone, Debug)]
pub struct TLSSigningKey<const N: usize, T: LibcruxSigningKey<N>> {
    inner: T,
}

impl <const N: usize, T> TLSSigningKey<N, T>
where 
    T: LibcruxSigningKey<N>,

{
    pub fn new(sk: T) -> Self {
        Self { inner: sk }
    }
}

impl <const N: usize, T> SigningKey for TLSSigningKey<N, T>
where
    T: LibcruxSigningKey<N> + Clone + Debug + 'static,
{
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&self.scheme()) {
            let key: TLSSigningKey<N, T> = self.clone();
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

impl <const N: usize, T> Signer for TLSSigningKey<N, T>
where
    T: LibcruxSigningKey<N> + Debug,
{
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let signature = self.inner.sign(message)
            .map_err(|_| signing_error("signing failed"));

        // TODO: Find smart solution that avoids retyping
        match self.scheme() {
            SignatureScheme::ECDSA_NISTP256_SHA256 => {
                signature
                    .and_then(|signature| signature.as_ref().try_into().map_err(|_| signing_error("Signing failed")))
                    .and_then(|signature: [u8; 64]| der_encode_ecdsa_signature(&ecdsa::p256::Signature::from_bytes(signature)).map_err(|_| signing_error("Error DER-encoding ECDSA signature")))
            }

            _ => signature.map(|sig| sig.as_ref().to_vec()),
        }
    }

    fn scheme(&self) -> SignatureScheme {
        match T::SCHEME {
            LibcruxSignatureScheme::EcDsaP256(ecdsa::DigestAlgorithm::Sha256) => SignatureScheme::ECDSA_NISTP256_SHA256,
            LibcruxSignatureScheme::Ed25519 => SignatureScheme::ED25519,
            _ => SignatureScheme::Unknown(0)
        }
    }
}

fn signing_error(msg: &str) -> rustls::Error {
    rustls::Error::General(msg.into())
}

// copied from ecdsa crate, where it wasn't public
/// Create an ASN.1 DER encoded signature from big endian `r` and `s` scalar
/// components.
fn der_encode_ecdsa_signature(sig: &ecdsa::p256::Signature) -> der::Result<Vec<u8>> {
    let sig = sig.as_bytes();
    let r = UintRef::new(&sig[0..32])?;
    let s = UintRef::new(&sig[32..])?;

    let mut bytes = [0u8; 73];
    let mut writer = der::SliceWriter::new(&mut bytes);

    writer.sequence((r.encoded_len()? + s.encoded_len()?)?, |seq| {
        seq.encode(&r)?;
        seq.encode(&s)
    })?;

    Ok(writer.finish()?.to_vec())
}
