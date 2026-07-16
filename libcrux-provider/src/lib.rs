#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

use libcrux::agent::hmac::{HmacSha256Key, Sha2_256HMAC};
use libcrux::agent::KeyID;
use libcrux::algorithms::sha2::{Sha256, SHA256_LENGTH};
// use libcrux::algorithms::chacha20poly1305;
// use libcrux::libcrux::Lib;
use libcrux::libcrux::aead::ChaCha20Poly1305;
use libcrux::libcrux::hkdf::Hkdf;
use libcrux::libcrux::AgentLib;
use rustls::crypto::CryptoProvider;

mod aead;
mod hash;
mod hkdf;
mod hmac;
#[cfg(feature = "std")]
pub mod hpke;
mod key_provider;
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

static ALL_CIPHER_SUITES: &[rustls::SupportedCipherSuite] = &[
    TLS13_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

pub static TLS13_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls13(&rustls::Tls13CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::HashAlgo::<SHA256_LENGTH, Sha256>::new(),
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &hkdf::Hkdf::<_, KeyID<Sha2_256HMAC>>::new(Hkdf::<
            SHA256_LENGTH,
            Sha256,
            AgentLib,
        >::new()),
        // hkdf_provider: &hkdf::Hkdf::<_, HmacSha256Key>::new(Hkdf::<SHA256_LENGTH, Sha256, Lib>::new()),
        aead_alg: &aead::AeadAlgo::<_, KeyID<ChaCha20Poly1305>>::new(),
        // aead_alg: &aead::AeadAlgo::<_, chacha20poly1305::Key>::new(),
        quic: None,
    });

pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: rustls::SupportedCipherSuite =
    rustls::SupportedCipherSuite::Tls12(&rustls::Tls12CipherSuite {
        common: rustls::crypto::CipherSuiteCommon {
            suite: rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            hash_provider: &hash::HashAlgo::<SHA256_LENGTH, Sha256>::new(),
            confidentiality_limit: u64::MAX,
        },
        kx: rustls::crypto::KeyExchangeAlgorithm::ECDHE,
        sign: &[
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
        ],
        prf_provider: &rustls::crypto::tls12::PrfUsingHmac(&hmac::Hmac::<HmacSha256Key>::new()),
        aead_alg: &aead::Chacha20Poly1305,
    });
