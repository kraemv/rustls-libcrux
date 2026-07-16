use core::fmt::Debug;
use core::marker::PhantomData;

use der::Reader;
use libcrux::agent::signatures::{EcDsaP256PublicKey, Ed25519PublicKey, SHA256};
use libcrux::libcrux::signature::{SignatureScheme as LibcruxSignatureScheme, VerificationKey};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{
    alg_id, AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm,
};
use rustls::SignatureScheme;
use webpki::aws_lc_rs::RSA_PKCS1_2048_8192_SHA256 as AWS_LC_RSA_PKCS1_SHA256;

use libcrux::algorithms::ecdsa;

pub static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[ED25519, ECDSA_P256_SHA256, AWS_LC_RSA_PKCS1_SHA256],
    mapping: &[
        (SignatureScheme::ED25519, &[ED25519]),
        (SignatureScheme::ECDSA_NISTP256_SHA256, &[ECDSA_P256_SHA256]),
        (
            SignatureScheme::RSA_PKCS1_SHA256,
            &[AWS_LC_RSA_PKCS1_SHA256],
        ),
    ],
};

static ED25519: &dyn SignatureVerificationAlgorithm = &Verify::<Ed25519PublicKey>::new();

static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm =
    &Verify::<EcDsaP256PublicKey<SHA256>>::new();

#[derive(Debug)]
struct Verify<T: VerificationKey> {
    marker: PhantomData<T>,
}

impl<T> Verify<T>
where
    T: VerificationKey,
{
    pub const fn new() -> Self {
        Self {
            marker: PhantomData,
        }
    }
}

impl<T> SignatureVerificationAlgorithm for Verify<T>
where
    T: VerificationKey + Debug,
{
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let pk = T::try_from(public_key).map_err(|_| InvalidSignature)?;
        let signature = match T::SCHEME {
            LibcruxSignatureScheme::EcDsaP256(_) => {
                let mut decoder = der::SliceReader::new(signature).map_err(|_| InvalidSignature)?;
                let der_sig: DerEcdsaSignature = decoder.decode().map_err(|_| InvalidSignature)?;
                let mut sig = [0u8; 64];
                let sig_r: [u8; 32] = der_sig
                    .r
                    .as_bytes()
                    .try_into()
                    .map_err(|_| InvalidSignature)?;
                let sig_s: [u8; 32] = der_sig
                    .s
                    .as_bytes()
                    .try_into()
                    .map_err(|_| InvalidSignature)?;
                sig[0..32].copy_from_slice(&sig_r);
                sig[32..].copy_from_slice(&sig_s);
                T::Signature::try_from(&sig).map_err(|_| InvalidSignature)?
            }
            _ => T::Signature::try_from(signature).map_err(|_| InvalidSignature)?,
        };
        pk.verify(message, &signature).map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        match T::SCHEME {
            LibcruxSignatureScheme::Ed25519 => alg_id::ED25519,
            LibcruxSignatureScheme::EcDsaP256(_) => alg_id::ECDSA_P256,
        }
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        match T::SCHEME {
            LibcruxSignatureScheme::Ed25519 => alg_id::ED25519,
            LibcruxSignatureScheme::EcDsaP256(ecdsa::DigestAlgorithm::Sha224) => unreachable!(),
            LibcruxSignatureScheme::EcDsaP256(ecdsa::DigestAlgorithm::Sha256) => {
                alg_id::ECDSA_SHA256
            }
            LibcruxSignatureScheme::EcDsaP256(ecdsa::DigestAlgorithm::Sha384) => {
                alg_id::ECDSA_SHA384
            }
            LibcruxSignatureScheme::EcDsaP256(ecdsa::DigestAlgorithm::Sha512) => {
                alg_id::ECDSA_SHA512
            }
        }
    }
}

struct DerEcdsaSignature {
    r: der::asn1::Int,
    s: der::asn1::Int,
}

impl<'a> der::Decode<'a> for DerEcdsaSignature {
    type Error = der::Error;

    fn decode<R: Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            Ok(Self {
                r: decoder.decode()?,
                s: decoder.decode()?,
            })
        })
    }
}
