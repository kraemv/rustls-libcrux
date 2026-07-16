use alloc::boxed::Box;
use core::marker::PhantomData;
use std::string::ToString;

use libcrux::algorithms::hmac;
use libcrux::libcrux::hmac::{AuthenticationKey, Error};
use rustls::crypto;

pub struct Hmac<T: AuthenticationKey>(PhantomData<T>);
pub struct HmacKey<T: AuthenticationKey> {
    inner: T,
}

impl<T> Hmac<T>
where
    T: AuthenticationKey,
{
    pub(crate) const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<T> crypto::hmac::Hmac for Hmac<T>
where
    T: AuthenticationKey + 'static,
{
    fn with_key(&self, key: &[u8]) -> Box<dyn crypto::hmac::Key> {
        Box::new(HmacKey {
            inner: T::try_from(key)
                .map_err(|_| Error::Internal("Invalid ID".to_string()))
                .unwrap(),
        })
    }

    fn hash_output_len(&self) -> usize {
        size_of::<T::Tag>()
    }
}

impl<T> crypto::hmac::Key for HmacKey<T>
where
    T: AuthenticationKey,
{
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> crypto::hmac::Tag {
        let middle_len = middle.iter().fold(0, |acc, v| acc + v.len());
        let mut data = alloc::vec::Vec::with_capacity(first.len() + middle_len + last.len());
        data.extend_from_slice(first);
        for chunk in middle {
            data.extend_from_slice(chunk);
        }
        data.extend_from_slice(last);

        let tag = self.inner.authenticate(&data).unwrap();
        crypto::hmac::Tag::new(tag.as_ref())
    }

    fn tag_len(&self) -> usize {
        hmac::tag_size(hmac::Algorithm::Sha256)
    }
}
