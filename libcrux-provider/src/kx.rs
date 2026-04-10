use alloc::boxed::Box;
use alloc::string::String;

use rustls::crypto;
// use crate::pq::X25519MlKem768;
use libcrux::libcrux::kem::{self as libcrux_api, DecapsKey};


#[derive(Debug)]
pub struct KeyExchange {
    priv_key: libcrux_api::DecapsKeyID,
    pub_key: libcrux_api::EncapsKeyType,
}

impl crypto::ActiveKeyExchange for KeyExchange {
    fn complete(
        self: Box<KeyExchange>,
        peer: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        let ct = libcrux_api::EncapsulatedKey::new(self.priv_key.scheme(), peer).map_err(|_| rustls::Error::General(String::from("ecdh derive error")))?;
        let shared_secret = self.priv_key.decaps(ct).map_err(|_| rustls::Error::General(String::from("ecdh derive error")))?;

        Ok(crypto::SharedSecret::from(&shared_secret[..]))
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.to_bytes()
    }

    fn group(&self) -> rustls::NamedGroup {
        match self.priv_key.scheme() {
            libcrux_api::KemScheme::MlKem768 => rustls::NamedGroup::MLKEM768,
            libcrux_api::KemScheme::X25519 => rustls::NamedGroup::X25519,
        }
    }
}

pub const ALL_KX_GROUPS: &[&dyn crypto::SupportedKxGroup] = &[
    &MLKEM768 as &dyn crypto::SupportedKxGroup,
    &X25519 as &dyn crypto::SupportedKxGroup,
];

#[derive(Debug)]
pub struct X25519;

#[derive(Debug)]
pub struct MLKEM768;

impl crypto::SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let (priv_key, pub_key) = libcrux_api::DecapsKeyID::gen_x25519_key().map_err(|_| rustls::Error::General(String::from("ecdh keygen error")))?;

        Ok(Box::new(KeyExchange { priv_key, pub_key }))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

impl crypto::SupportedKxGroup for MLKEM768 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let (priv_key, pub_key) = libcrux_api::DecapsKeyID::gen_mlkem_768_key().map_err(|_| rustls::Error::General(String::from("ecdh keygen error")))?;

        Ok(Box::new(KeyExchange { priv_key, pub_key }))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::MLKEM768
    }
}
