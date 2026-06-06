use core::marker::PhantomData;
use std::string::ToString;

use alloc::boxed::Box;

use libcrux::libcrux::hkdf::{Error, HKDFKey, RandomnessExtractor, SaltedRandomnessExtractor};
use libcrux::libcrux::hmac::AuthenticationKey;
use rustls::crypto;
use libcrux::algorithms::hmac as hmac;
use libcrux::libcrux::{hkdf::Hkdf, AgentLib, hash::Hash};

pub struct HKDF<Extractor: RandomnessExtractor, Authenticator: AuthenticationKey> {
    extractor: Extractor,
    marker: PhantomData<Authenticator>,
}

const SHA2_256_LEN: usize = 32;

impl<Extr: RandomnessExtractor, Auth: AuthenticationKey> HKDF<Extr, Auth>{
    pub(crate) const fn new(hkdf: Extr) -> Self {
        Self { extractor: hkdf, marker: PhantomData }
    }    
}

type SecretSalt<const N: usize, Algo: Hash<N>> = <Hkdf<N, Algo, AgentLib> as RandomnessExtractor>::Salt;
type SecretKey<const N: usize, Algo: Hash<N>> = <<Hkdf<N, Algo, AgentLib> as RandomnessExtractor>::SecretExtractor as SaltedRandomnessExtractor>::Key;

impl<Extr, Auth> crypto::tls13::Hkdf for HKDF<Extr, Auth> 
where
    Extr: RandomnessExtractor,
    Auth: AuthenticationKey + Send + Sync,
{
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn crypto::tls13::HkdfExpander> {
        // This derives the master secret, hence the input is always the key ID from the key establishment(secret) or both inputs are zero for zero PSK
        
        let prk = match salt {
            Some(s) => {
                let salt = Extr::Salt::try_from(s).map_err(|_| Error::Internal("Invalid ID".to_string())).unwrap();        
                let prk = self.extractor.with_secret_salt(salt)
                    .extract_without_key()
                    .expect("Extraction failed");
                Box::new(Expander{inner: Box::new(prk)})
            }
            None => {
                let prk = self.extractor.with_salt(None)
                    .extract_without_key()
                    .expect("Extraction failed");
                Box::new(Expander{ inner: Box::new(prk)})
            }
        };
        prk
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn crypto::tls13::HkdfExpander> {
        // This derives the input for a preshared key, the DH secret and for encrypted client hellos. Currently, it only supports DH secrets
        let key = SecretKey::try_from(secret).map_err(|_| Error::Internal("Invalid ID".to_string())).unwrap();

        match salt {
            Some(s) if s.len() == size_of::<Extr::Salt>() => {
                let salt = Extr::Salt::try_from(s).map_err(|_| Error::Internal("Invalid ID".to_string())).unwrap();
                let extr = self.extractor.with_secret_salt(salt);
                let prk = extr.extract_with_key(key).map_err(|_| Error::Internal("Extraction failed".to_string())).unwrap();
                Box::new(Expander{ inner: Box::new(prk)})
            }
            salt => {
                let prk = self.extractor.with_salt(salt).extract_with_key(key).map_err(|_| Error::Internal("Extraction failed".to_string())).unwrap();
                Box::new(Expander{ inner: Box::new(prk)})
            }
        }
    }

    fn expander_for_okm(&self, okm: &crypto::tls13::OkmBlock) -> Box<dyn crypto::tls13::HkdfExpander> {
        todo!()
    }

    fn hmac_sign(&self, key: &crypto::tls13::OkmBlock, message: &[u8]) -> crypto::hmac::Tag {
        let result = hmac::hmac(hmac::Algorithm::Sha256, key.as_ref(), message, None);
        crypto::hmac::Tag::new(&result[..])
    }
}


struct Expander<T: HKDFKey>{inner: Box<T>}

impl<T> crypto::tls13::HkdfExpander for Expander<T> 
where
    T: HKDFKey
{
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), crypto::tls13::OutputLengthError> {
        self.inner.expand(output.len(), &info.concat()).map(|okm| output.copy_from_slice(&okm)).map_err(|_| crypto::tls13::OutputLengthError) 
    }

    fn expand_block(&self, info: &[&[u8]]) -> crypto::tls13::OkmBlock {

        self.inner.expand(T::N, &info.concat()).map(|okm| crypto::tls13::OkmBlock::new(&okm)).expect("info too long") 
    }

    fn hash_len(&self) -> usize {
        T::N
    }
}