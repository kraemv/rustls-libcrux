use alloc::boxed::Box;
use core::marker::PhantomData;

use libcrux::libcrux::hash::{Hash, HashAlgo as DigestAlgorithm};
use rustls::crypto::hash;

pub struct HashAlgo<const N: usize, T: Hash<N>>(PhantomData<T>);

impl<const N: usize, T> HashAlgo<N, T>
where
    T: Hash<N> + 'static,
{
    pub(crate) const fn new() -> Self {
        Self(PhantomData)
    }
}

impl<const N: usize, T> hash::Hash for HashAlgo<N, T>
where
    T: Hash<N> + 'static,
{
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(HashCtx(T::init()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        let out = T::hash(data);
        hash::Output::new(&out)
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        match T::SCHEME {
            DigestAlgorithm::Sha2_256 => hash::HashAlgorithm::SHA256,
        }
    }

    fn output_len(&self) -> usize {
        N
    }
}

pub struct HashCtx<const N: usize, T: Hash<N>>(T);

impl<const N: usize, T> hash::Context for HashCtx<N, T>
where
    T: Hash<N> + 'static,
{
    fn fork_finish(&self) -> hash::Output {
        let state = self.0.fork();
        let out = state.finalize();
        hash::Output::new(&out)
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(HashCtx(self.0.fork()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        (*self).fork_finish()
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}
