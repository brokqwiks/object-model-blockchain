use std::collections::{HashMap, HashSet};

use crate::core::{
    address::Address,
    object::{Object, Ownable, OwnershipError},
    object_address::ObjectAddress,
    owner::Owner,
    tx::{Effect, Transaction},
};
use crate::crypto::keys::verify_one_time_membership;
use crate::object_standards::token::Coin;
use rocksdb::{DB, Options};
use serde::{Deserialize, Serialize};

#[derive(Debug, Default)]
pub struct State {
    chain_id: u32,
    genesis_applied: bool,
    objects: HashMap<ObjectAddress, Object>,
    coins: HashMap<ObjectAddress, Coin>,
    nonces: HashMap<String, u64>,
    one_time_roots: HashMap<String, [u8; 32]>,
    used_one_time_indices: HashMap<String, HashSet<u64>>,
    next_tx_id: u64,
    tx_history: Vec<TxRecord>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateSummary {
    pub chain_id: u32,
    pub genesis_applied: bool,
    pub objects: usize,
    pub coins: usize,
    pub accounts_with_nonces: usize,
    pub accounts_with_roots: usize,
    pub transactions: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxRecord {
    pub id: u64,
    pub chain_id: u32,
    pub sender: String,
    pub nonce: u64,
    pub one_time_index: u64,
    pub effects_len: usize,
    pub effect_kinds: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateError {
    ChainIdMismatch { expected: u32, got: u32 },
    UnsupportedTxVersion(u16),
    InvalidSignature,
    OneTimeProofTooLarge,
    OneTimeRootAlreadyRegistered,
    OneTimeRootNotRegistered,
    InvalidOneTimeProof,
    OneTimeKeyAlreadyUsed,
    InvalidNonce { expected: u64, got: u64 },
    EmptyEffects,
    TooManyEffects,
    ObjectNotFound,
    CoinNotFound,
    InvalidCoinAmount,
    InsufficientCoinAmount,
    NotObjectOwner,
    NotCoinOwner,
    NoStateChange,
}

#[derive(Debug)]
pub enum StateStoreError {
    Db(rocksdb::Error),
    Codec(bincode::Error),
    ChainIdMismatch { expected: u32, got: u32 },
}

impl From<rocksdb::Error> for StateStoreError {
    fn from(value: rocksdb::Error) -> Self {
        Self::Db(value)
    }
}

impl From<bincode::Error> for StateStoreError {
    fn from(value: bincode::Error) -> Self {
        Self::Codec(value)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct StateSnapshot {
    chain_id: u32,
    genesis_applied: bool,
    objects: HashMap<ObjectAddress, Object>,
    coins: HashMap<ObjectAddress, Coin>,
    nonces: HashMap<String, u64>,
    one_time_roots: HashMap<String, [u8; 32]>,
    used_one_time_indices: HashMap<String, HashSet<u64>>,
    next_tx_id: u64,
    tx_history: Vec<TxRecord>,
}

const STATE_SNAPSHOT_KEY: &[u8] = b"state:snapshot:v1";

impl State {
    const MAX_EFFECTS: usize = 128;
    const MAX_PROOF_LEN: usize = 64;

    pub fn new() -> Self {
        Self {
            chain_id: 1,
            genesis_applied: false,
            ..Self::default()
        }
    }

    pub fn with_chain_id(chain_id: u32) -> Self {
        Self {
            chain_id,
            genesis_applied: false,
            ..Self::default()
        }
    }

    pub fn chain_id(&self) -> u32 {
        self.chain_id
    }

    pub fn summary(&self) -> StateSummary {
        StateSummary {
            chain_id: self.chain_id,
            genesis_applied: self.genesis_applied,
            objects: self.objects.len(),
            coins: self.coins.len(),
            accounts_with_nonces: self.nonces.len(),
            accounts_with_roots: self.one_time_roots.len(),
            transactions: self.tx_history.len(),
        }
    }

    pub fn is_genesis_applied(&self) -> bool {
        self.genesis_applied
    }

    pub fn mark_genesis_applied(&mut self) {
        self.genesis_applied = true;
    }

    pub fn load_or_create(db_path: &str, chain_id: u32) -> Result<Self, StateStoreError> {
        if let Some(state) = Self::load_from_db(db_path)? {
            if state.chain_id != chain_id {
                return Err(StateStoreError::ChainIdMismatch {
                    expected: chain_id,
                    got: state.chain_id,
                });
            }
            return Ok(state);
        }

        let state = Self::with_chain_id(chain_id);
        state.save_to_db(db_path)?;
        Ok(state)
    }

    pub fn load_from_db(db_path: &str) -> Result<Option<Self>, StateStoreError> {
        let db = open_db(db_path)?;
        let Some(bytes) = db.get(STATE_SNAPSHOT_KEY)? else {
            return Ok(None);
        };

        let snapshot: StateSnapshot = match bincode::deserialize(&bytes) {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
        Ok(Some(snapshot.into_state()))
    }

    pub fn save_to_db(&self, db_path: &str) -> Result<(), StateStoreError> {
        let db = open_db(db_path)?;
        let bytes = bincode::serialize(&self.to_snapshot())?;
        db.put(STATE_SNAPSHOT_KEY, bytes)?;
        Ok(())
    }

    pub fn register_one_time_root(
        &mut self,
        account: Address,
        root: [u8; 32],
    ) -> Result<(), StateError> {
        let key = account.to_hex();
        if self.one_time_roots.contains_key(&key) {
            return Err(StateError::OneTimeRootAlreadyRegistered);
        }
        self.one_time_roots.insert(key, root);
        Ok(())
    }

    pub fn insert_object(&mut self, object: Object) {
        self.objects.insert(object.object_address(), object);
    }

    pub fn insert_coin(&mut self, coin: Coin) {
        self.coins.insert(coin.object_address, coin);
    }

    pub fn get_object(&self, object_address: ObjectAddress) -> Option<&Object> {
        self.objects.get(&object_address)
    }

    pub fn get_coin(&self, coin_address: ObjectAddress) -> Option<&Coin> {
        self.coins.get(&coin_address)
    }

    pub fn balance_of(&self, owner: Address) -> u64 {
        self.coins
            .values()
            .filter(|coin| coin.owner == owner)
            .map(|coin| coin.amount)
            .sum()
    }

    pub fn nonce_of(&self, account: Address) -> u64 {
        *self.nonces.get(&account.to_hex()).unwrap_or(&0)
    }

    pub fn tx_history(&self, limit: usize) -> Vec<TxRecord> {
        let take = limit.min(self.tx_history.len());
        self.tx_history
            .iter()
            .rev()
            .take(take)
            .cloned()
            .collect()
    }

    pub fn tx_by_id(&self, id: u64) -> Option<TxRecord> {
        self.tx_history.iter().find(|tx| tx.id == id).cloned()
    }

    pub fn first_coin_covering(&self, owner: Address, min_amount: u64) -> Option<Coin> {
        self.coins
            .values()
            .find(|coin| coin.owner == owner && coin.amount >= min_amount)
            .copied()
    }

    pub fn apply_tx(&mut self, tx: &Transaction) -> Result<(), StateError> {
        if tx.chain_id != self.chain_id {
            return Err(StateError::ChainIdMismatch {
                expected: self.chain_id,
                got: tx.chain_id,
            });
        }
        if tx.tx_version != 1 {
            return Err(StateError::UnsupportedTxVersion(tx.tx_version));
        }
        if tx.effects.is_empty() {
            return Err(StateError::EmptyEffects);
        }
        if tx.effects.len() > Self::MAX_EFFECTS {
            return Err(StateError::TooManyEffects);
        }
        if tx.one_time_merkle_proof.len() > Self::MAX_PROOF_LEN {
            return Err(StateError::OneTimeProofTooLarge);
        }
        if !tx.verify_signature() {
            return Err(StateError::InvalidSignature);
        }

        let sender_key = tx.sender.to_hex();
        let root = *self
            .one_time_roots
            .get(&sender_key)
            .ok_or(StateError::OneTimeRootNotRegistered)?;

        if !verify_one_time_membership(
            root,
            tx.sender,
            tx.one_time_index,
            &tx.one_time_public_key,
            &tx.one_time_merkle_proof,
        ) {
            return Err(StateError::InvalidOneTimeProof);
        }

        let already_used = self
            .used_one_time_indices
            .get(&sender_key)
            .is_some_and(|set| set.contains(&tx.one_time_index));
        if already_used {
            return Err(StateError::OneTimeKeyAlreadyUsed);
        }

        let expected_nonce = *self.nonces.get(&sender_key).unwrap_or(&0);
        if tx.nonce != expected_nonce {
            return Err(StateError::InvalidNonce {
                expected: expected_nonce,
                got: tx.nonce,
            });
        }

        let mut applied_changes = 0usize;
        let mut rotated_root = false;
        for effect in &tx.effects {
            match effect {
                Effect::TransferObject {
                    object_address,
                    new_owner,
                } => {
                    let Some(object) = self.objects.get_mut(object_address) else {
                        return Err(StateError::ObjectNotFound);
                    };

                    let result = object.transfer_ownership(
                        Owner::Address(tx.sender),
                        Owner::Address(*new_owner),
                    );
                    match result {
                        Ok(()) => applied_changes = applied_changes.saturating_add(1),
                        Err(OwnershipError::NotOwner) => return Err(StateError::NotObjectOwner),
                        Err(OwnershipError::NoStateChange) => {}
                    }
                }
                Effect::TransferCoin {
                    coin_address,
                    new_owner,
                } => {
                    let Some(coin) = self.coins.get_mut(coin_address) else {
                        return Err(StateError::CoinNotFound);
                    };

                    let result = coin.transfer_ownership(
                        Owner::Address(tx.sender),
                        Owner::Address(*new_owner),
                    );
                    match result {
                        Ok(()) => applied_changes = applied_changes.saturating_add(1),
                        Err(OwnershipError::NotOwner) => return Err(StateError::NotCoinOwner),
                        Err(OwnershipError::NoStateChange) => {}
                    }
                }
                Effect::TransferCoinAmount {
                    from_coin_address,
                    amount,
                    recipient,
                    recipient_coin_address,
                    change_coin_address,
                } => {
                    if *amount == 0 {
                        return Err(StateError::InvalidCoinAmount);
                    }

                    let Some(source_coin) = self.coins.remove(from_coin_address) else {
                        return Err(StateError::CoinNotFound);
                    };
                    if source_coin.owner != tx.sender {
                        self.coins.insert(*from_coin_address, source_coin);
                        return Err(StateError::NotCoinOwner);
                    }
                    if source_coin.amount < *amount {
                        self.coins.insert(*from_coin_address, source_coin);
                        return Err(StateError::InsufficientCoinAmount);
                    }

                    let mut recipient_coin = source_coin;
                    recipient_coin.object_address = *recipient_coin_address;
                    recipient_coin.id = coin_id_from_address(*recipient_coin_address);
                    recipient_coin.owner = *recipient;
                    recipient_coin.amount = *amount;
                    recipient_coin.version = recipient_coin.version.saturating_add(1);
                    self.coins.insert(*recipient_coin_address, recipient_coin);

                    let change = source_coin.amount - *amount;
                    if change > 0 {
                        let Some(change_addr) = change_coin_address else {
                            return Err(StateError::InvalidCoinAmount);
                        };
                        let mut change_coin = source_coin;
                        change_coin.object_address = *change_addr;
                        change_coin.id = coin_id_from_address(*change_addr);
                        change_coin.owner = tx.sender;
                        change_coin.amount = change;
                        change_coin.version = change_coin.version.saturating_add(1);
                        self.coins.insert(*change_addr, change_coin);
                    }

                    applied_changes = applied_changes.saturating_add(1);
                }
                Effect::RotateOneTimeRoot { new_root } => {
                    self.one_time_roots.insert(sender_key.clone(), *new_root);
                    self.used_one_time_indices.insert(sender_key.clone(), HashSet::new());
                    rotated_root = true;
                    applied_changes = applied_changes.saturating_add(1);
                }
            }
        }

        if applied_changes == 0 {
            return Err(StateError::NoStateChange);
        }

        if !rotated_root {
            self.used_one_time_indices
                .entry(sender_key.clone())
                .or_default()
                .insert(tx.one_time_index);
        }
        self.nonces.insert(sender_key, expected_nonce + 1);
        self.record_tx(tx);
        Ok(())
    }

    fn record_tx(&mut self, tx: &Transaction) {
        let effect_kinds = tx
            .effects
            .iter()
            .map(|effect| match effect {
                Effect::TransferObject { .. } => "transfer_object".to_string(),
                Effect::TransferCoin { .. } => "transfer_coin".to_string(),
                Effect::TransferCoinAmount { .. } => "transfer_coin_amount".to_string(),
                Effect::RotateOneTimeRoot { .. } => "rotate_one_time_root".to_string(),
            })
            .collect::<Vec<_>>();

        let record = TxRecord {
            id: self.next_tx_id,
            chain_id: tx.chain_id,
            sender: tx.sender.to_hex(),
            nonce: tx.nonce,
            one_time_index: tx.one_time_index,
            effects_len: tx.effects.len(),
            effect_kinds,
        };
        self.next_tx_id = self.next_tx_id.saturating_add(1);
        self.tx_history.push(record);
    }
}

impl State {
    fn to_snapshot(&self) -> StateSnapshot {
        StateSnapshot {
            chain_id: self.chain_id,
            genesis_applied: self.genesis_applied,
            objects: self.objects.clone(),
            coins: self.coins.clone(),
            nonces: self.nonces.clone(),
            one_time_roots: self.one_time_roots.clone(),
            used_one_time_indices: self.used_one_time_indices.clone(),
            next_tx_id: self.next_tx_id,
            tx_history: self.tx_history.clone(),
        }
    }
}

impl StateSnapshot {
    fn into_state(self) -> State {
        State {
            chain_id: self.chain_id,
            genesis_applied: self.genesis_applied,
            objects: self.objects,
            coins: self.coins,
            nonces: self.nonces,
            one_time_roots: self.one_time_roots,
            used_one_time_indices: self.used_one_time_indices,
            next_tx_id: self.next_tx_id,
            tx_history: self.tx_history,
        }
    }
}

fn coin_id_from_address(address: ObjectAddress) -> u64 {
    let bytes = address.as_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(out)
}

fn open_db(db_path: &str) -> Result<DB, StateStoreError> {
    let mut options = Options::default();
    options.create_if_missing(true);
    Ok(DB::open(&options, db_path)?)
}

#[cfg(test)]
mod tests {
    use crate::core::{
        address::NETWORK_TESTNET,
        object::Object,
        owner::Owner,
        state::{State, StateError},
        tx::{Effect, Transaction},
    };
    use crate::crypto::keys::MasterAccountKeyManager;
    use crate::object_standards::token::{BasicToken, Coin};

    fn manager_with_seed(seed: u8) -> MasterAccountKeyManager {
        MasterAccountKeyManager::from_master_secret([seed; 32], NETWORK_TESTNET, 64)
            .expect("manager should build")
    }

    #[test]
    fn tx_transfer_object_updates_owner_and_version() {
        let mut sender_keys = manager_with_seed(3);
        let recipient_keys = manager_with_seed(4);
        let sender = sender_keys.account_address();
        let recipient = recipient_keys.account_address();
        let object = Object::new(Owner::Address(sender));
        let object_address = object.object_address();

        let mut state = State::new();
        state
            .register_one_time_root(sender, sender_keys.one_time_root())
            .expect("root register");
        state.insert_object(object);

        let signer = sender_keys.issue_one_time_signer().expect("signer");
        let tx = Transaction::new_unsigned(
            &signer,
            1,
            0,
            vec![Effect::TransferObject {
                object_address,
                new_owner: recipient,
            }],
        )
        .sign(&signer)
        .expect("sign should succeed");

        state.apply_tx(&tx).expect("transfer should be applied");
        let updated = state
            .get_object(object_address)
            .expect("object should exist");
        assert_eq!(updated.owner(), Owner::Address(recipient));
        assert_eq!(updated.version(), 1);
    }

    #[test]
    fn tx_transfer_coin_updates_owner() {
        let mut sender_keys = manager_with_seed(5);
        let recipient_keys = manager_with_seed(6);
        let sender = sender_keys.account_address();
        let recipient = recipient_keys.account_address();
        let mut token = BasicToken::new("Demo", "D", 9, "demo", None);
        let coin: Coin = token.mint(sender, 100).expect("mint should succeed");
        let coin_address = coin.object_address;

        let mut state = State::new();
        state
            .register_one_time_root(sender, sender_keys.one_time_root())
            .expect("root register");
        state.insert_coin(coin);

        let signer = sender_keys.issue_one_time_signer().expect("signer");
        let tx = Transaction::new_unsigned(
            &signer,
            1,
            0,
            vec![Effect::TransferCoin {
                coin_address,
                new_owner: recipient,
            }],
        )
        .sign(&signer)
        .expect("sign should succeed");

        state.apply_tx(&tx).expect("coin transfer should apply");
        let moved_coin = state.get_coin(coin_address).expect("coin should exist");
        assert_eq!(moved_coin.owner, recipient);
        assert_eq!(moved_coin.version, 1);
    }

    #[test]
    fn replay_tx_fails_on_one_time_reuse() {
        let mut sender_keys = manager_with_seed(7);
        let sender = sender_keys.account_address();
        let recipient = manager_with_seed(8).account_address();
        let object = Object::new(Owner::Address(sender));
        let object_address = object.object_address();
        let mut state = State::new();
        state
            .register_one_time_root(sender, sender_keys.one_time_root())
            .expect("root register");
        state.insert_object(object);

        let signer = sender_keys.issue_one_time_signer().expect("signer");
        let tx = Transaction::new_unsigned(
            &signer,
            1,
            0,
            vec![Effect::TransferObject {
                object_address,
                new_owner: recipient,
            }],
        )
        .sign(&signer)
        .expect("sign should succeed");

        state.apply_tx(&tx).expect("first tx should apply");
        let err = state
            .apply_tx(&tx)
            .expect_err("replayed tx should be rejected");
        assert_eq!(err, StateError::OneTimeKeyAlreadyUsed);
    }

    #[test]
    fn unregistered_root_is_rejected() {
        let mut sender_keys = manager_with_seed(9);
        let sender = sender_keys.account_address();
        let recipient = manager_with_seed(10).account_address();
        let object = Object::new(Owner::Address(sender));
        let object_address = object.object_address();
        let mut state = State::new();
        state.insert_object(object);

        let signer = sender_keys.issue_one_time_signer().expect("signer");
        let tx = Transaction::new_unsigned(
            &signer,
            1,
            0,
            vec![Effect::TransferObject {
                object_address,
                new_owner: recipient,
            }],
        )
        .sign(&signer)
        .expect("sign should succeed");

        let err = state.apply_tx(&tx).expect_err("must fail");
        assert_eq!(err, StateError::OneTimeRootNotRegistered);
    }

    #[test]
    fn root_cannot_be_registered_twice() {
        let sender_keys = manager_with_seed(50);
        let sender = sender_keys.account_address();
        let mut state = State::new();
        state
            .register_one_time_root(sender, sender_keys.one_time_root())
            .expect("first register");
        let err = state
            .register_one_time_root(sender, sender_keys.one_time_root())
            .expect_err("second register must fail");
        assert_eq!(err, StateError::OneTimeRootAlreadyRegistered);
    }

    #[test]
    fn tx_chain_id_mismatch_is_rejected() {
        let mut sender_keys = manager_with_seed(51);
        let sender = sender_keys.account_address();
        let recipient = manager_with_seed(52).account_address();
        let object = Object::new(Owner::Address(sender));
        let object_address = object.object_address();
        let mut state = State::with_chain_id(1);
        state
            .register_one_time_root(sender, sender_keys.one_time_root())
            .expect("root register");
        state.insert_object(object);

        let signer = sender_keys.issue_one_time_signer().expect("signer");
        let tx = Transaction::new_unsigned(
            &signer,
            2,
            0,
            vec![Effect::TransferObject {
                object_address,
                new_owner: recipient,
            }],
        )
        .sign(&signer)
        .expect("sign should succeed");

        let err = state.apply_tx(&tx).expect_err("must fail on chain id");
        assert_eq!(
            err,
            StateError::ChainIdMismatch {
                expected: 1,
                got: 2
            }
        );
    }

    #[test]
    fn root_rotation_effect_updates_root() {
        let mut sender_keys = manager_with_seed(53);
        let sender = sender_keys.account_address();
        let initial_root = sender_keys.one_time_root();
        let mut state = State::new();
        state
            .register_one_time_root(sender, initial_root)
            .expect("root register");

        let new_manager = manager_with_seed(54);
        let new_root = new_manager.one_time_root();
        let signer = sender_keys.issue_one_time_signer().expect("signer");
        let tx = Transaction::new_unsigned(
            &signer,
            1,
            0,
            vec![Effect::RotateOneTimeRoot { new_root }],
        )
        .sign(&signer)
        .expect("sign should succeed");

        state.apply_tx(&tx).expect("rotation should apply");
    }
}
