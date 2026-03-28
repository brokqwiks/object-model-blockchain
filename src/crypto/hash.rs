pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};

    let mut hasher = Sha256::new();
    hasher.update(data);

    hasher.finalize().into()
}
