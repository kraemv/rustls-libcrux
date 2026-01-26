use der::Reader;
use libcrux::signature::{
    DigestAlgorithm, EcDsaP256PubKey, EcDsaP256Signature, Ed25519PublicKey, Ed25519Signature,
    Signature, VerificationKey,
};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{alg_id, AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rustls::SignatureScheme;
use webpki::{aws_lc_rs::RSA_PKCS1_2048_8192_SHA256 as AWS_LC_RSA_PKCS1_SHA256};
use crate::std::vec::Vec;

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

static ED25519: &dyn SignatureVerificationAlgorithm = &Ed25519Verify;

static ECDSA_P256_SHA256: &dyn SignatureVerificationAlgorithm =
    &EcdsaP256Verify(DigestAlgorithm::Sha256);

#[derive(Debug, Clone, Copy)]
struct EcdsaP256Verify(DigestAlgorithm);

impl SignatureVerificationAlgorithm for EcdsaP256Verify {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let mut decoder = der::SliceReader::new(signature).map_err(|_| InvalidSignature)?;
        let sig: DerEcdsaSignature = decoder.decode().map_err(|_| InvalidSignature)?;
        let r: [u8; 32] = sig.r.as_bytes().try_into().map_err(|_| InvalidSignature)?;
        let s: [u8; 32] = sig.s.as_bytes().try_into().map_err(|_| InvalidSignature)?;
        let signature = Signature::EcDsaP256(EcDsaP256Signature::from_raw(r, s), self.0);
        let pk = EcDsaP256PubKey::new(public_key.try_into().map_err(|_| InvalidSignature)?, self.0);
        pk.verify(message, signature).map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        match self.0 {
            DigestAlgorithm::Sha224 => todo!(),
            DigestAlgorithm::Sha256 => alg_id::ECDSA_SHA256,
            DigestAlgorithm::Sha384 => alg_id::ECDSA_SHA384,
            DigestAlgorithm::Sha512 => alg_id::ECDSA_SHA512,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Ed25519Verify;

impl SignatureVerificationAlgorithm for Ed25519Verify {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let signature = Signature::Ed25519(
            Ed25519Signature::from_slice(signature).map_err(|_| InvalidSignature)?,
        );
        let pk = Ed25519PublicKey::from_bytes(public_key.try_into().map_err(|_| InvalidSignature)?);
        pk.verify(message, signature).map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ED25519
    }
}

struct DerEcdsaSignature {
    r: der::asn1::Int,
    s: der::asn1::Int,
}

impl<'a> der::Decode<'a> for DerEcdsaSignature {
    fn decode<R: Reader<'a>>(decoder: &mut R) -> der::Result<Self> {
        decoder.sequence(|decoder| {
            Ok(Self {
                r: decoder.decode()?,
                s: decoder.decode()?,
            })
        })
    }
}
