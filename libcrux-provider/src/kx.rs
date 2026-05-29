use alloc::boxed::Box;
use alloc::string::String;

use libcrux::libcrux::kem::{Kem, MlKem768};
use rustls::crypto;
// use crate::pq::X25519MlKem768;
use libcrux::libcrux::kem;
use libcrux::libcrux::kem::DecapsKey;
use libcrux::libcrux::nike;
use libcrux::libcrux::nike::NIKESecretKey;



pub struct KemKeyExchange<Scheme: Kem> 
where  kem::DecapsKeyID<Scheme>: DecapsKey
{
    priv_key: kem::DecapsKeyID<Scheme>,
    pub_key: KemPublicKey<Scheme>,
}

#[derive(Debug)]
pub struct Nike<Scheme: nike::Nike>
where nike::NIKESecretKeyID<Scheme>: NIKESecretKey
{
    priv_key: nike::NIKESecretKeyID<Scheme>,
    pub_key:NikePublicKey<Scheme>,
}

type NikePublicKey<Scheme> = <nike::NIKESecretKeyID<Scheme> as NIKESecretKey>::PublicKey;
type KemPublicKey<Scheme> = <kem::DecapsKeyID<Scheme> as DecapsKey>::PublicKey;
type KemCiphertext<Scheme> = <kem::DecapsKeyID<Scheme> as DecapsKey>::Ciphertext;

impl<Scheme> crypto::ActiveKeyExchange for KemKeyExchange<Scheme> 
where 
    Scheme: Kem,
    kem::DecapsKeyID<Scheme>: DecapsKey
{
    fn complete(
        self: Box<KemKeyExchange<Scheme>>,
        peer: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        let ct = KemCiphertext::try_from(peer).map_err(|_| rustls::Error::General(String::from("ecdh derive error")))?;
        let shared_secret = self.priv_key.decaps(ct).map_err(|_| rustls::Error::General(String::from("ecdh derive error")))?;

        Ok(crypto::SharedSecret::from(shared_secret))
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_ref()
    }

    fn group(&self) -> rustls::NamedGroup {
        match self.priv_key.scheme() {
            kem::KemScheme::MlKem768 => rustls::NamedGroup::MLKEM768,
        }
    }
}

impl<Scheme> crypto::ActiveKeyExchange for Nike<Scheme> 
where 
    Scheme: nike::Nike,
    nike::NIKESecretKeyID<Scheme>: nike::NIKESecretKey,
{
    fn complete(
        self: Box<Nike<Scheme>>,
        peer: &[u8],
    ) -> Result<crypto::SharedSecret, rustls::Error> {
        let pk = NikePublicKey::try_from(peer).map_err(|_| rustls::Error::General(String::from("ecdh derive error")))?;
        let shared_secret = self.priv_key.derive(pk).map_err(|_| rustls::Error::General(String::from("ecdh derive error")))?;

        Ok(crypto::SharedSecret::from(&shared_secret[..]))
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_ref()
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
        let (priv_key, pub_key) = nike::NIKESecretKeyID::<nike::X25519>::keygen().map_err(|_| rustls::Error::General(String::from("ecdh keygen error")))?;

        Ok(Box::new(Nike { priv_key, pub_key }))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

impl crypto::SupportedKxGroup for MLKEM768 {
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, rustls::Error> {
        let (priv_key, pub_key) = kem::DecapsKeyID::<MlKem768>::keygen().map_err(|_| rustls::Error::General(String::from("MlKem keygen error")))?;

        Ok(Box::new(KemKeyExchange { priv_key, pub_key }))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::MLKEM768
    }
}
