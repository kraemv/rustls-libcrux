use core::marker::PhantomData;

use alloc::boxed::Box;
use alloc::string::String;

use libcrux::agent::KeyID;
use libcrux::agent::kx::X25519SecretKey;
use libcrux::libcrux::kem::{DecapsKey, EncapsKey, KemScheme, MlKem768};
use rustls::crypto;
use libcrux::libcrux::kem;
use libcrux::libcrux::nike::{self, NIKEScheme, NIKESecretKey, X25519};

type Error = rustls::Error;

pub struct KemKeyExchange<T: DecapsKey> {
    priv_key: T,
    pub_key: T::PublicKey,
}

#[derive(Debug)]
pub struct ActiveNike<T: nike::NIKESecretKey> {
    priv_key: T,
    pub_key: T::PublicKey,
}

impl<T> crypto::ActiveKeyExchange for KemKeyExchange<T>
where
    T: DecapsKey,
{
    fn complete(
        self: Box<KemKeyExchange<T>>,
        peer: &[u8],
    ) -> Result<crypto::SharedSecret, Error> {
        let ct = T::Ciphertext::try_from(peer)
            .map_err(|_| Error::General(String::from("ecdh derive error")))?;
        let shared_secret = self
            .priv_key
            .decaps(ct)
            .map_err(|_| Error::General(String::from("ecdh derive error")))?;

        let id_bytes = shared_secret.as_ref();
        Ok(crypto::SharedSecret::from(id_bytes))
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_ref()
    }

    fn group(&self) -> rustls::NamedGroup {
        match T::SCHEME {
            kem::KemScheme::MlKem768 => rustls::NamedGroup::MLKEM768,
        }
    }
}

impl<T: nike::NIKESecretKey> crypto::ActiveKeyExchange for ActiveNike<T> {
    fn complete(
        self: Box<ActiveNike<T>>,
        peer: &[u8],
    ) -> Result<crypto::SharedSecret, Error> {
        let pk = T::PublicKey::try_from(peer)
            .map_err(|_| Error::General("Invalid public key".into()))?;
        self.priv_key.derive(&pk)
            .map(|shk| crypto::SharedSecret::from(shk.as_ref()))
            .map_err(to_rustls_error)
    }

    fn pub_key(&self) -> &[u8] {
        self.pub_key.as_ref()
    }

    fn group(&self) -> rustls::NamedGroup {
        match T::SCHEME {
            nike::NIKEScheme::X25519 => rustls::NamedGroup::X25519,
        }
    }
}

pub const AGENT_KX_GROUPS: &[&dyn crypto::SupportedKxGroup] = &[
    &Kem::<KeyID<MlKem768>>(PhantomData),
    &Nike::<KeyID<X25519>>(PhantomData),
];

pub const LIB_KX_GROUPS: &[&dyn crypto::SupportedKxGroup] = &[
    &Nike::<X25519SecretKey>(PhantomData),
];

#[derive(Debug)]
pub struct Nike<T: NIKESecretKey>(PhantomData<T>);

#[derive(Debug)]
pub struct Kem<T: DecapsKey>(PhantomData<T>);

impl<T> crypto::SupportedKxGroup for Nike<T>
where
    T: NIKESecretKey + core::fmt::Debug + 'static,
{
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, Error> {
        let (priv_key, pub_key) = T::keygen().map_err(to_rustls_error)?;

        Ok(Box::new(ActiveNike { priv_key, pub_key }))
    }

    fn name(&self) -> rustls::NamedGroup {
        match T::SCHEME {
            NIKEScheme::X25519 => rustls::NamedGroup::X25519,
        }
    }
}

impl<T> crypto::SupportedKxGroup for Kem<T>
where
    T: DecapsKey + core::fmt::Debug + 'static,
{
    fn start(&self) -> Result<Box<dyn crypto::ActiveKeyExchange>, Error> {
        let (priv_key, pub_key) =
            T::keygen().map_err(|_| Error::General(String::from("MlKem keygen error")))?;

        Ok(Box::new(KemKeyExchange { priv_key, pub_key }))
    }

    fn start_and_complete(
        &self,
        peer_pub_key: &[u8],
    ) -> Result<crypto::CompletedKeyExchange, Error> {
        let pk = T::PublicKey::try_from(peer_pub_key)
            .map_err(|_| Error::General(String::from("MlKem pubkey error")))?;
        pk.encaps()
            .map_err(|_| Error::General(String::from("MlKem encaps error")))
            .map(|(shk, ct)| crypto::CompletedKeyExchange {
                group: self.name(),
                pub_key: ct.as_ref().to_vec(),
                secret: crypto::SharedSecret::from(shk.as_ref()),
            })
    }

    fn name(&self) -> rustls::NamedGroup {
        match T::SCHEME {
            KemScheme::MlKem768 => rustls::NamedGroup::MLKEM768,
        }
    }
}

fn to_rustls_error(err: libcrux::libcrux::nike::Error) -> Error {
    match err {
        libcrux::libcrux::nike::Error::Derive => Error::General("Derivation failed".into()),
        libcrux::libcrux::nike::Error::Internal(s) => Error::General(s),
    }
}