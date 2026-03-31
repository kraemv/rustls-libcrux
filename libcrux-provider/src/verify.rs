use der::Reader;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{alg_id, AlgorithmIdentifier, InvalidSignature, SignatureVerificationAlgorithm};
use rustls::SignatureScheme;
use webpki::{aws_lc_rs::RSA_PKCS1_2048_8192_SHA256 as AWS_LC_RSA_PKCS1_SHA256};

use libcrux::algorithms::ecdsa;
use libcrux::algorithms::ed25519;

pub static ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[
        ED25519,
        ECDSA_P256_SHA256,
        AWS_LC_RSA_PKCS1_SHA256,
    ],
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
    &EcdsaP256Verify(ecdsa::DigestAlgorithm::Sha256);

#[derive(Debug, Clone, Copy)]
struct EcdsaP256Verify(ecdsa::DigestAlgorithm);

impl SignatureVerificationAlgorithm for EcdsaP256Verify {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        let mut decoder = der::SliceReader::new(signature).map_err(|_| InvalidSignature)?;
        let sig: DerEcdsaSignature = decoder
            .decode()
            .map_err(|_| InvalidSignature)?;
        let r: [u8; 32] = sig
            .r
            .as_bytes()
            .try_into()
            .map_err(|_| InvalidSignature)?;
        let s: [u8; 32] = sig
            .s
            .as_bytes()
            .try_into()
            .map_err(|_| InvalidSignature)?;
        let signature = ecdsa::p256::Signature::from_raw(
            r,
            s,
        );
        let public_key = ecdsa::p256::PublicKey::try_from(public_key)
            .map_err(|_| InvalidSignature)?;
        let alg = ecdsa::DigestAlgorithm::Sha256;
        ecdsa::p256::verify(alg, message, &signature, &public_key).map_err(|_| InvalidSignature)
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        match self.0 {
            ecdsa::DigestAlgorithm::Sha224 => unreachable!(),
            ecdsa::DigestAlgorithm::Sha256 => alg_id::ECDSA_SHA256,
            ecdsa::DigestAlgorithm::Sha384 => alg_id::ECDSA_SHA384,
            ecdsa::DigestAlgorithm::Sha512 => alg_id::ECDSA_SHA512,
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
        let public_key: [u8; 32] = public_key.try_into().map_err(|_| InvalidSignature)?;
        let signature: [u8; 64] = signature.try_into().map_err(|_| InvalidSignature)?;
        let signature = ed25519::Signature::from_bytes(signature);
        ed25519::verify(message, &public_key, &signature).map_err(|_| InvalidSignature)
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