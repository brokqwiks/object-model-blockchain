use std::collections::HashMap;

use crate::core::{
    address::Address,
    object::{Object, Ownable, OwnershipError},
    object_address::ObjectAddress,
    owner::Owner,
    tx::{Effect, Transaction},
};
use crate::object_standards::token::Coin;

#[derive(Debug, Default)]
pub struct State {
    objects: HashMap<ObjectAddress, Object>,
    coins: HashMap<ObjectAddress, Coin>,
    nonces: HashMap<String, u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateError {
    InvalidSignature,
    SenderMismatch,
    InvalidNonce { expected: u64, got: u64 },
    EmptyEffects,
    TooManyEffects,
    ObjectNotFound,
    CoinNotFound,
    NotObjectOwner,
    NotCoinOwner,
    NoStateChange,
}

impl State {
    const MAX_EFFECTS: usize = 128;

    pub fn new() -> Self {
        Self::default()
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

    pub fn apply_tx(&mut self, tx: &Transaction) -> Result<(), StateError> {
        if tx.effects.is_empty() {
            return Err(StateError::EmptyEffects);
        }
        if tx.effects.len() > Self::MAX_EFFECTS {
            return Err(StateError::TooManyEffects);
        }
        if !tx.verify_signature() {
            return Err(StateError::InvalidSignature);
        }

        let expected_sender = Address::from_public_key(&tx.sender_public_key, tx.sender.network());
        if expected_sender != tx.sender {
            return Err(StateError::SenderMismatch);
        }

        let expected_nonce = *self.nonces.get(&tx.sender.to_hex()).unwrap_or(&0);
        if tx.nonce != expected_nonce {
            return Err(StateError::InvalidNonce {
                expected: expected_nonce,
                got: tx.nonce,
            });
        }

        let mut applied_changes = 0usize;
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
            }
        }

        if applied_changes == 0 {
            return Err(StateError::NoStateChange);
        }

        self.nonces.insert(tx.sender.to_hex(), expected_nonce + 1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::core::{
        address::{Address, NETWORK_TESTNET},
        object::Object,
        owner::Owner,
        state::{State, StateError},
        tx::{Effect, Transaction},
    };
    use crate::crypto::keys::Keypair;
    use crate::object_standards::token::{BasicToken, Coin};

    fn keypair_with_seed(seed: u8) -> Keypair {
        Keypair::from_signing_key_bytes([seed; 32])
    }

    fn address_for(seed: u8) -> Address {
        let kp = keypair_with_seed(seed);
        Address::from_public_key(&kp.verifying_key_bytes(), NETWORK_TESTNET)
    }

    #[test]
    fn address_roundtrip_and_checksum_validation() {
        let keypair = keypair_with_seed(1);
        let address = Address::from_public_key(&keypair.verifying_key_bytes(), NETWORK_TESTNET);
        let hex = address.to_hex();
        let parsed = Address::from_hex(&hex).expect("address should parse");
        assert!(parsed.is_valid());
        assert_eq!(parsed, address);
    }

    #[test]
    fn address_invalid_checksum_fails_validation() {
        let keypair = keypair_with_seed(2);
        let address = Address::from_public_key(&keypair.verifying_key_bytes(), NETWORK_TESTNET);
        let mut hex = address.to_hex();
        let last_char = hex.pop().expect("hex should not be empty");
        let flipped = if last_char == '0' { '1' } else { '0' };
        hex.push(flipped);

        let parsed = Address::from_hex(&hex);
        assert!(parsed.is_err());
    }

    #[test]
    fn tx_transfer_object_updates_owner_and_version() {
        let sender_keys = keypair_with_seed(3);
        let recipient_keys = keypair_with_seed(4);
        let sender = Address::from_public_key(&sender_keys.verifying_key_bytes(), NETWORK_TESTNET);
        let recipient =
            Address::from_public_key(&recipient_keys.verifying_key_bytes(), NETWORK_TESTNET);
        let object = Object::new(Owner::Address(sender));
        let object_address = object.object_address();

        let mut state = State::new();
        state.insert_object(object);

        let tx = Transaction::new_unsigned(
            sender_keys.verifying_key_bytes(),
            sender,
            0,
            vec![Effect::TransferObject {
                object_address,
                new_owner: recipient,
            }],
        )
        .sign(&sender_keys)
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
        let sender_keys = keypair_with_seed(5);
        let recipient_keys = keypair_with_seed(6);
        let sender = Address::from_public_key(&sender_keys.verifying_key_bytes(), NETWORK_TESTNET);
        let recipient =
            Address::from_public_key(&recipient_keys.verifying_key_bytes(), NETWORK_TESTNET);
        let mut token = BasicToken::new("Demo", "D", 9, "demo", None);
        let coin: Coin = token.mint(sender, 100).expect("mint should succeed");
        let coin_address = coin.object_address;

        let mut state = State::new();
        state.insert_coin(coin);

        let tx = Transaction::new_unsigned(
            sender_keys.verifying_key_bytes(),
            sender,
            0,
            vec![Effect::TransferCoin {
                coin_address,
                new_owner: recipient,
            }],
        )
        .sign(&sender_keys)
        .expect("sign should succeed");

        state.apply_tx(&tx).expect("coin transfer should apply");
        let moved_coin = state.get_coin(coin_address).expect("coin should exist");
        assert_eq!(moved_coin.owner, recipient);
        assert_eq!(moved_coin.version, 1);
    }

    #[test]
    fn replay_tx_fails_on_nonce_mismatch() {
        let sender_keys = keypair_with_seed(7);
        let sender = address_for(7);
        let recipient = address_for(8);
        let object = Object::new(Owner::Address(sender));
        let object_address = object.object_address();
        let mut state = State::new();
        state.insert_object(object);

        let tx = Transaction::new_unsigned(
            sender_keys.verifying_key_bytes(),
            sender,
            0,
            vec![Effect::TransferObject {
                object_address,
                new_owner: recipient,
            }],
        )
        .sign(&sender_keys)
        .expect("sign should succeed");

        state.apply_tx(&tx).expect("first tx should apply");
        let err = state
            .apply_tx(&tx)
            .expect_err("replayed tx should be rejected");
        assert_eq!(err, StateError::InvalidNonce { expected: 1, got: 0 });
    }

    #[test]
    fn attacker_cannot_steal_by_knowing_owner_address() {
        let owner_keys = keypair_with_seed(20);
        let attacker_keys = keypair_with_seed(21);
        let owner = Address::from_public_key(&owner_keys.verifying_key_bytes(), NETWORK_TESTNET);
        let attacker =
            Address::from_public_key(&attacker_keys.verifying_key_bytes(), NETWORK_TESTNET);
        let object = Object::new(Owner::Address(owner));
        let object_address = object.object_address();

        let mut state = State::new();
        state.insert_object(object);

        let fake_tx = Transaction::new_unsigned(
            attacker_keys.verifying_key_bytes(),
            owner,
            0,
            vec![Effect::TransferObject {
                object_address,
                new_owner: attacker,
            }],
        )
        .sign(&attacker_keys)
        .expect("sign should succeed");

        let err = state
            .apply_tx(&fake_tx)
            .expect_err("steal attempt must fail");
        assert_eq!(err, StateError::SenderMismatch);
    }

    #[test]
    fn empty_effects_are_rejected_as_spam() {
        let sender_keys = keypair_with_seed(30);
        let sender = address_for(30);
        let mut state = State::new();

        let tx = Transaction::new_unsigned(sender_keys.verifying_key_bytes(), sender, 0, vec![])
            .sign(&sender_keys)
            .expect("sign should succeed");

        let err = state.apply_tx(&tx).expect_err("empty tx should fail");
        assert_eq!(err, StateError::EmptyEffects);
    }

    #[test]
    fn no_op_effects_are_rejected_as_spam() {
        let sender_keys = keypair_with_seed(31);
        let sender = address_for(31);
        let object = Object::new(Owner::Address(sender));
        let object_address = object.object_address();
        let mut state = State::new();
        state.insert_object(object);

        let tx = Transaction::new_unsigned(
            sender_keys.verifying_key_bytes(),
            sender,
            0,
            vec![Effect::TransferObject {
                object_address,
                new_owner: sender,
            }],
        )
        .sign(&sender_keys)
        .expect("sign should succeed");

        let err = state.apply_tx(&tx).expect_err("no-op should fail");
        assert_eq!(err, StateError::NoStateChange);
    }
}
