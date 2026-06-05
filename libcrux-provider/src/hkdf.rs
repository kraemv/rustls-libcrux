use std::string::ToString;

use alloc::boxed::Box;

use libcrux::libcrux::hkdf::{Error, HKDFKey, HKDFKeyID, RandomnessExtractor, SaltedRandomnessExtractor};
use rustls::crypto;
use libcrux::algorithms::hmac as hmac;
use libcrux::libcrux::{hkdf::Hkdf, AgentLib, hash::Hash};

pub struct HKDF<const N: usize, Algo: Hash<N>>(pub(crate) Hkdf<N, Algo, AgentLib>);

const SHA2_256_LEN: usize = 32;

impl<const N: usize, Algo: Hash<N>> HKDF<N, Algo>{
    pub(crate) const fn new() -> Self {
        Self(Hkdf::<N, Algo, AgentLib>::new())
    }    
}

type SecretSalt<const N: usize, Algo: Hash<N>> = <Hkdf<N, Algo, AgentLib> as RandomnessExtractor>::Salt;

impl<const N: usize, Algo> crypto::tls13::Hkdf for HKDF<N, Algo> 
where
    Algo: Hash<N>,
    Hkdf<N, Algo, AgentLib>: RandomnessExtractor,

{
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn crypto::tls13::HkdfExpander> {
        // This derives the master secret, hence the input is always the key ID from the key establishment(secret) or both inputs are zero for zero PSK
        
        match salt {
            Some(s) => {
                let salt = SecretSalt::<N, Algo>::try_from(s).map_err(|_| Error::Internal("Invalid ID".to_string())).unwrap();
                let prk = self.0.with_secret_salt(salt)
                    .extract_without_key()
                    .expect("Extraction failed");
                Box::new(Expander{inner: prk})
            }
            None => Box::new(Expander{ inner: self.0.with_salt(None).extract_without_key().expect("Extraction failed")}),
        }
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn crypto::tls13::HkdfExpander> {
        let key = secret.into();
        
        match salt {
            Some(s) if s.len() == size_of::<HKDFKeyID>() => Box::new(self.0.with_secret_salt(s).extract_with_key(key)),
            salt => Box::new(self.0.with_salt(salt).extract_with_key(key)),
        }
    }

    fn expander_for_okm(&self, okm: &crypto::tls13::OkmBlock) -> Box<dyn crypto::tls13::HkdfExpander> {
        let key: [u8; 32] = okm.as_ref().try_into().unwrap();
        Box::new(Sha256HKDFKey(key))
    }

    fn hmac_sign(&self, key: &crypto::tls13::OkmBlock, message: &[u8]) -> crypto::hmac::Tag {
        let result = hmac::hmac(hmac::Algorithm::Sha256, key.as_ref(), message, None);
        crypto::hmac::Tag::new(&result[..])
    }
}


struct Expander<T: HKDFKey>{inner: T}

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