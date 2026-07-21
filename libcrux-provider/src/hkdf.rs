use core::marker::PhantomData;
use std::string::ToString;

use alloc::boxed::Box;

use libcrux::agent::hkdf::HkdfSha256PRK;
use libcrux::libcrux::hkdf::{Error, HKDFKey, RandomnessExtractor, SaltedRandomnessExtractor};
use libcrux::libcrux::mac::AuthenticationKey;
use rustls::crypto;

pub struct Hkdf<Extractor: RandomnessExtractor, Authenticator: AuthenticationKey> {
    extractor: Extractor,
    marker: PhantomData<Authenticator>,
}

impl<Extr: RandomnessExtractor, Auth: AuthenticationKey> Hkdf<Extr, Auth> {
    pub(crate) const fn new(hkdf: Extr) -> Self {
        Self {
            extractor: hkdf,
            marker: PhantomData,
        }
    }
}

impl<Extr, Auth> crypto::tls13::Hkdf for Hkdf<Extr, Auth>
where
    Extr: RandomnessExtractor + 'static,
    <Extr::SecretExtractor as SaltedRandomnessExtractor>::Key: for<'a> TryFrom<&'a [u8]>,
    <Extr::SecretExtractor as SaltedRandomnessExtractor>::Prk: for<'a> TryFrom<&'a [u8]>,
    <Extr::PublicExtractor as SaltedRandomnessExtractor>::Key: for<'a> TryFrom<&'a [u8]>,
    Auth: AuthenticationKey + Send + Sync,
{
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn crypto::tls13::HkdfExpander> {
        // This derives the master secret, hence the input is always the key ID from the key establishment(secret) or both inputs are zero for zero PSK

        match salt {
            Some(s) if s.len() == size_of::<Extr::Salt>() => {
                let salt = Extr::Salt::try_from(s)
                    .map_err(|_| Error::Internal("Invalid Salt".to_string()))
                    .unwrap();
                let prk = self
                    .extractor
                    .with_secret_salt(salt)
                    .extract_without_key()
                    .expect("Extraction failed");
                Box::new(Expander { inner: prk })
            }
            salt => {
                let prk = self
                    .extractor
                    .with_salt(salt)
                    .extract_without_key()
                    .expect("Extraction failed");
                Box::new(Expander { inner: prk })
            }
        }
    }

    fn extract_from_secret(
        &self,
        salt: Option<&[u8]>,
        secret: &[u8],
    ) -> Box<dyn crypto::tls13::HkdfExpander> {
        // This derives the input for a preshared key, the DH secret and for encrypted client hellos. Currently, it only supports DH secrets

        match salt {
            Some(s) if s.len() == size_of::<Extr::Salt>() => {
                let key =
                    <Extr::SecretExtractor as SaltedRandomnessExtractor>::Key::try_from(secret)
                        .map_err(|_| Error::Internal("Invalid ID".to_string()))
                        .unwrap();
                let salt = Extr::Salt::try_from(s)
                    .map_err(|_| Error::Internal("Invalid ID".to_string()))
                    .unwrap();
                let prk = self
                    .extractor
                    .with_secret_salt(salt)
                    .extract_with_key(key)
                    .expect("Extraction failed");
                Box::new(Expander { inner: prk })
            }
            salt => {
                let key =
                    <Extr::PublicExtractor as SaltedRandomnessExtractor>::Key::try_from(secret)
                        .map_err(|_| Error::Internal("Invalid ID".to_string()))
                        .unwrap();
                let extractor: <Extr as RandomnessExtractor>::PublicExtractor =
                    self.extractor.with_salt(salt);
                let prk = extractor.extract_with_key(key).expect("Extraction failed");
                Box::new(Expander { inner: prk })
            }
        }
    }

    fn expander_for_okm(
        &self,
        okm: &crypto::tls13::OkmBlock,
    ) -> Box<dyn crypto::tls13::HkdfExpander> {
        match <Extr::SecretExtractor as SaltedRandomnessExtractor>::Prk::try_from(okm.as_ref()) {
            Ok(prk) => Box::new(Expander { inner: prk }),
            Err(_) => {
                let prk: [u8; 32] = okm.as_ref().try_into().expect("Expansion from OKM failed");
                Box::new(Expander {
                    inner: HkdfSha256PRK::new(prk),
                })
            }
        }
    }

    fn hmac_sign(&self, key: &crypto::tls13::OkmBlock, message: &[u8]) -> crypto::hmac::Tag {
        let key = Auth::try_from(key.as_ref())
            .map_err(|_| Error::Internal("Invalid key".to_string()))
            .unwrap();
        let tag = key.authenticate(message).unwrap();
        crypto::hmac::Tag::new(tag.as_ref())
    }
}

struct Expander<T: HKDFKey> {
    inner: T,
}

impl<T> crypto::tls13::HkdfExpander for Expander<T>
where
    T: HKDFKey,
{
    fn expand_slice(
        &self,
        info: &[&[u8]],
        output: &mut [u8],
    ) -> Result<(), crypto::tls13::OutputLengthError> {
        let info = &info.concat();
        match output.len() {
            crypto::cipher::NONCE_LEN => self
                .inner
                .expand_declassify(crypto::cipher::NONCE_LEN, info)
                .map(|okm| output.copy_from_slice(okm.as_ref()))
                .map_err(|_| crypto::tls13::OutputLengthError),
            output_len => self
                .inner
                .expand(output_len, info)
                .map(|okm| output[..okm.as_ref().len()].copy_from_slice(okm.as_ref()))
                .map_err(|_| crypto::tls13::OutputLengthError),
        }
    }

    fn expand_block(&self, info: &[&[u8]]) -> crypto::tls13::OkmBlock {
        self.inner
            .expand(T::N, &info.concat())
            .map(|okm| crypto::tls13::OkmBlock::new(okm.as_ref()))
            .expect("info too long")
    }

    fn hash_len(&self) -> usize {
        T::N
    }
}
