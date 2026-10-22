//! SHA-256 and SHA-384 for rustls, over `sha2`.

use rustls::crypto::hash::{Context, Hash, HashAlgorithm, Output};
use sha2::Digest;

pub(crate) struct Sha256;
pub(crate) struct Sha384;

impl Hash for Sha256 {
    fn start(&self) -> Box<dyn Context> {
        Box::new(Ctx(sha2::Sha256::new()))
    }
    fn hash(&self, data: &[u8]) -> Output {
        Output::new(&sha2::Sha256::digest(data)[..])
    }
    fn output_len(&self) -> usize {
        32
    }
    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }
}

impl Hash for Sha384 {
    fn start(&self) -> Box<dyn Context> {
        Box::new(Ctx(sha2::Sha384::new()))
    }
    fn hash(&self, data: &[u8]) -> Output {
        Output::new(&sha2::Sha384::digest(data)[..])
    }
    fn output_len(&self) -> usize {
        48
    }
    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA384
    }
}

struct Ctx<D>(D);

impl<D: Digest + Clone + Send + Sync + 'static> Context for Ctx<D> {
    fn fork_finish(&self) -> Output {
        Output::new(&self.0.clone().finalize()[..])
    }
    fn fork(&self) -> Box<dyn Context> {
        Box::new(Ctx(self.0.clone()))
    }
    fn finish(self: Box<Self>) -> Output {
        Output::new(&self.0.finalize()[..])
    }
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}
