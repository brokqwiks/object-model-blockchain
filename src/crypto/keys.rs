use crate::core::address::Address;
use crate::crypto::hash::sha256;
use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::random;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keypair {
    verifying_key: [u8; 32],
    signing_key: [u8; 32],
}

impl Keypair {
    pub fn from_signing_key_bytes(signing_key_bytes: [u8; 32]) -> Keypair {
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let signing_key = signing_key.to_bytes();

        Keypair {
            verifying_key,
            signing_key,
        }
    }

    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.verifying_key
    }

    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let signing_key = SigningKey::from_bytes(&self.signing_key);
        signing_key.sign(message).to_bytes()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedOneTimeSigner {
    index: u64,
    account_address: Address,
    one_time_keypair: Keypair,
    merkle_proof: Vec<[u8; 32]>,
}

impl AuthorizedOneTimeSigner {
    pub fn index(&self) -> u64 {
        self.index
    }

    pub fn account_address(&self) -> Address {
        self.account_address
    }

    pub fn one_time_public_key(&self) -> [u8; 32] {
        self.one_time_keypair.verifying_key_bytes()
    }

    pub fn merkle_proof(&self) -> &[[u8; 32]] {
        &self.merkle_proof
    }

    pub fn sign_payload(&self, message: &[u8]) -> [u8; 64] {
        self.one_time_keypair.sign(message)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OneTimeKeyError {
    EmptyPool,
    KeyExhausted,
    InvalidMnemonic,
}

#[derive(Clone, Debug)]
pub struct MasterAccountKeyManager {
    master_secret: [u8; 32],
    account_address: Address,
    one_time_keys: Vec<Keypair>,
    tree_levels: Vec<Vec<[u8; 32]>>,
    next_index: u64,
}

impl MasterAccountKeyManager {
    pub fn new_random(network: u8, pool_size: usize) -> Result<Self, OneTimeKeyError> {
        Self::from_master_secret(random(), network, pool_size)
    }

    pub fn from_master_secret(
        master_secret: [u8; 32],
        network: u8,
        pool_size: usize,
    ) -> Result<Self, OneTimeKeyError> {
        if pool_size == 0 {
            return Err(OneTimeKeyError::EmptyPool);
        }

        let address_key = derive_32(&master_secret, b"ACCOUNT_ADDR_V1", 0);
        let account_address = Address::from_public_key(&address_key, network);

        let mut one_time_keys = Vec::with_capacity(pool_size);
        let mut leaves = Vec::with_capacity(pool_size);
        for index in 0..pool_size as u64 {
            let sk = derive_32(&master_secret, b"OTK_SIGNING_KEY_V1", index);
            let keypair = Keypair::from_signing_key_bytes(sk);
            let leaf = one_time_leaf_hash(account_address, index, &keypair.verifying_key_bytes());
            one_time_keys.push(keypair);
            leaves.push(leaf);
        }

        let tree_levels = build_merkle_tree(leaves);

        Ok(Self {
            master_secret,
            account_address,
            one_time_keys,
            tree_levels,
            next_index: 0,
        })
    }

    pub fn new_from_random_mnemonic(
        network: u8,
        pool_size: usize,
    ) -> Result<(String, Self), OneTimeKeyError> {
        let mnemonic = Mnemonic::generate_in(Language::English, 12)
            .map_err(|_| OneTimeKeyError::InvalidMnemonic)?;
        let phrase = mnemonic.to_string();
        let manager = Self::from_mnemonic_phrase(&phrase, network, pool_size)?;
        Ok((phrase, manager))
    }

    pub fn from_mnemonic_phrase(
        phrase: &str,
        network: u8,
        pool_size: usize,
    ) -> Result<Self, OneTimeKeyError> {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, phrase)
            .map_err(|_| OneTimeKeyError::InvalidMnemonic)?;
        let seed = mnemonic.to_seed_normalized("");
        let master_secret = sha256(&seed);
        Self::from_master_secret(master_secret, network, pool_size)
    }

    pub fn account_address(&self) -> Address {
        self.account_address
    }

    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    pub fn set_next_index(&mut self, next_index: u64) {
        self.next_index = next_index;
    }

    pub fn one_time_root(&self) -> [u8; 32] {
        self.tree_levels
            .last()
            .and_then(|level| level.first().copied())
            .unwrap_or([0u8; 32])
    }

    pub fn master_fingerprint(&self) -> String {
        let fp = sha256(&self.master_secret);
        hex::encode(&fp[..8])
    }

    pub fn issue_one_time_signer(&mut self) -> Result<AuthorizedOneTimeSigner, OneTimeKeyError> {
        let index = self.next_index as usize;
        if index >= self.one_time_keys.len() {
            return Err(OneTimeKeyError::KeyExhausted);
        }
        self.next_index = self.next_index.saturating_add(1);

        let one_time_keypair = self.one_time_keys[index].clone();
        let merkle_proof = merkle_proof(&self.tree_levels, index);

        Ok(AuthorizedOneTimeSigner {
            index: index as u64,
            account_address: self.account_address,
            one_time_keypair,
            merkle_proof,
        })
    }
}

pub fn one_time_leaf_hash(
    account_address: Address,
    index: u64,
    one_time_public_key: &[u8; 32],
) -> [u8; 32] {
    let mut payload = Vec::with_capacity(11 + 37 + 8 + 32);
    payload.extend_from_slice(b"OTK_LEAF_V1");
    payload.extend_from_slice(&account_address.as_bytes());
    payload.extend_from_slice(&index.to_le_bytes());
    payload.extend_from_slice(one_time_public_key);
    sha256(&payload)
}

pub fn verify_one_time_membership(
    root: [u8; 32],
    account_address: Address,
    index: u64,
    one_time_public_key: &[u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    let mut hash = one_time_leaf_hash(account_address, index, one_time_public_key);
    let mut node_index = index as usize;

    for sibling in proof {
        hash = if node_index.is_multiple_of(2) {
            hash_pair(hash, *sibling)
        } else {
            hash_pair(*sibling, hash)
        };
        node_index /= 2;
    }

    hash == root
}

pub fn verify_signature(
    verifying_key_bytes: &[u8; 32],
    message: &[u8],
    signature_bytes: &[u8; 64],
) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(verifying_key_bytes) else {
        return false;
    };

    let signature = Signature::from_bytes(signature_bytes);
    verifying_key.verify(message, &signature).is_ok()
}

fn derive_32(master_secret: &[u8; 32], domain: &[u8], index: u64) -> [u8; 32] {
    // HKDF-like derivation to avoid raw hash(key || data) construction.
    let mut ikm = Vec::with_capacity(32 + 8);
    ikm.extend_from_slice(master_secret);
    ikm.extend_from_slice(&index.to_le_bytes());

    let prk = hmac_sha256(domain, &ikm);
    let mut info = Vec::with_capacity(domain.len() + 13);
    info.extend_from_slice(domain);
    info.extend_from_slice(b"OTK_DERIVE_V2");
    hmac_sha256(&prk, &info)
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k0 = [0u8; BLOCK];
    if key.len() > BLOCK {
        let hashed = Sha256::digest(key);
        k0[..32].copy_from_slice(&hashed);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k0[i];
        opad[i] ^= k0[i];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&left);
    payload.extend_from_slice(&right);
    sha256(&payload)
}

fn build_merkle_tree(leaves: Vec<[u8; 32]>) -> Vec<Vec<[u8; 32]>> {
    let mut levels = vec![leaves];
    while levels.last().map(|l| l.len()).unwrap_or(0) > 1 {
        let current = levels.last().cloned().unwrap_or_default();
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut i = 0usize;
        while i < current.len() {
            let left = current[i];
            let right = if i + 1 < current.len() {
                current[i + 1]
            } else {
                current[i]
            };
            next.push(hash_pair(left, right));
            i += 2;
        }
        levels.push(next);
    }
    levels
}

fn merkle_proof(levels: &[Vec<[u8; 32]>], leaf_index: usize) -> Vec<[u8; 32]> {
    let mut proof = Vec::new();
    let mut index = leaf_index;
    for level in levels.iter().take(levels.len().saturating_sub(1)) {
        let sibling_index = if index.is_multiple_of(2) {
            if index + 1 < level.len() {
                index + 1
            } else {
                index
            }
        } else {
            index - 1
        };
        proof.push(level[sibling_index]);
        index /= 2;
    }
    proof
}

#[cfg(test)]
mod tests {
    use crate::core::address::NETWORK_TESTNET;
    use crate::crypto::keys::{MasterAccountKeyManager, verify_one_time_membership};

    #[test]
    fn one_time_signers_keep_same_account_address() {
        let mut manager =
            MasterAccountKeyManager::new_random(NETWORK_TESTNET, 16).expect("manager should build");
        let first = manager.issue_one_time_signer().expect("first signer");
        let second = manager.issue_one_time_signer().expect("second signer");

        assert_eq!(first.account_address(), second.account_address());
        assert_ne!(first.one_time_public_key(), second.one_time_public_key());
    }

    #[test]
    fn one_time_membership_verifies_against_root() {
        let mut manager =
            MasterAccountKeyManager::from_master_secret([7u8; 32], NETWORK_TESTNET, 16)
                .expect("manager should build");
        let root = manager.one_time_root();
        let signer = manager.issue_one_time_signer().expect("signer");
        assert!(verify_one_time_membership(
            root,
            signer.account_address(),
            signer.index(),
            &signer.one_time_public_key(),
            signer.merkle_proof(),
        ));
    }
}
