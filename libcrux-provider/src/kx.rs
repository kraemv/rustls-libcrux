use alloc::boxed::Box;
use alloc::string::String;

use rustls::crypto;
// use crate::pq::X25519MlKem768;
use libcrux::libcrux::kem;
use libcrux::libcrux::kem::DecapsKey;
use libcrux::libcrux::nike;
use libcrux::libcrux::nike::NIKESecretKey;



#[derive(Debug)]
pub struct KemKeyExchange {
    priv_key: kem::DecapsKeyID,
    pub_key: kem::EncapsKeyType,
}

#[derive(Debug)]
pub struct Nike {
    priv_key: nike::NIKESecretKeyID,
    pub_key: nike::NIKEPublicKeyType,
}

impl crypto::ActiveKeyExchange for KemKeyExchange {
    fn complete(
        self: Box<KemKeyExchange>,
        peer: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        let ct = kem::EncapsulatedKey::new(self.priv_key.scheme(), peer).map_err(|_| rustls::Error::General(String::from("ecdh derive error")))?;
        let shared_secret = self.priv_key.decaps(ct).map_err(|_| rustls::Error::General(String::from("ecdh derive error")))?;

        Ok(crypto::SharedSecret::from(&shared_secret[..]))
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.to_bytes()
    }

    fn group(&self) -> rustls::NamedGroup {
        match self.priv_key.scheme() {
            kem::KemScheme::MlKem768 => rustls::NamedGroup::MLKEM768,
        }
    }
}

impl crypto::ActiveKeyExchange for Nike {
    fn complete(
        self: Box<Nike>,
        peer: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        let pk = nike::NIKEPublicKeyType::new(self.priv_key.scheme(), peer).map_err(|_| rustls::Error::General(String::from("ecdh derive error")))?;
        let shared_secret = self.priv_key.derive(pk).map_err(|_| rustls::Error::General(String::from("ecdh derive error")))?;

        Ok(crypto::SharedSecret::from(&shared_secret[..]))
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.to_bytes()
    }

    fn group(&self) -> rustls::NamedGroup {
        match self.priv_key.scheme() {
            nike::NIKEScheme::X25519 => rustls::NamedGroup::X25519,
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
        let (priv_key, pub_key) = nike::NIKESecretKeyID::gen_x25519_key().map_err(|_| rustls::Error::General(String::from("ecdh keygen error")))?;

        Ok(Box::new(Nike { priv_key, pub_key }))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

impl crypto::SupportedKxGroup for MLKEM768 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let (priv_key, pub_key) = kem::DecapsKeyID::gen_mlkem_768_key().map_err(|_| rustls::Error::General(String::from("ecdh keygen error")))?;

        Ok(Box::new(KemKeyExchange { priv_key, pub_key }))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::MLKEM768
    }
}
