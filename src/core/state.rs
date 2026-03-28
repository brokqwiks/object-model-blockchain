use std::collections::HashMap;

use crate::core::{
    address::Address,
    object::Object,
    owner::Owner,
    tx::TransferTx,
};

#[derive(Debug, Default)]
pub struct State {
    objects: HashMap<u64, Object>,
    nonces: HashMap<String, u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StateError {
    InvalidSignature,
    SenderMismatch,
    ObjectNotFound,
    NotObjectOwner,
    InvalidNonce { expected: u64, got: u64 },
}

impl State {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_object(&mut self, object: Object) {
        self.objects.insert(object.id(), object);
    }

    pub fn get_object(&self, object_id: u64) -> Option<&Object> {
        self.objects.get(&object_id)
    }

    pub fn apply_transfer_tx(&mut self, tx: &TransferTx) -> Result<(), StateError> {
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

        let Some(object) = self.objects.get_mut(&tx.object_id) else {
            return Err(StateError::ObjectNotFound);
        };

        if object.owner() != Owner::Address(tx.sender) {
            return Err(StateError::NotObjectOwner);
        }

        object.transfer(Owner::Address(tx.new_owner));
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
        tx::TransferTx,
    };
    use crate::crypto::keys::Keypair;

    fn keypair_with_seed(seed: u8) -> Keypair {
        Keypair::from_signing_key_bytes([seed; 32])
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
    fn transfer_updates_owner_and_version() {
        let sender_keys = keypair_with_seed(3);
        let recipient_keys = keypair_with_seed(4);

        let sender = Address::from_public_key(&sender_keys.verifying_key_bytes(), NETWORK_TESTNET);
        let recipient =
            Address::from_public_key(&recipient_keys.verifying_key_bytes(), NETWORK_TESTNET);

        let object = Object::new(42, Owner::Address(sender));
        let mut state = State::new();
        state.insert_object(object);

        let tx = TransferTx::new_unsigned(
            sender_keys.verifying_key_bytes(),
            sender,
            object.id(),
            recipient,
            0,
        )
        .sign(&sender_keys)
        .expect("sign should succeed");

        state
            .apply_transfer_tx(&tx)
            .expect("transfer should be applied");

        let updated = state.get_object(42).expect("object should exist");
        assert_eq!(updated.owner(), Owner::Address(recipient));
        assert_eq!(updated.version(), 1);
    }

    #[test]
    fn transfer_fails_when_sender_is_not_owner() {
        let real_owner_keys = keypair_with_seed(5);
        let attacker_keys = keypair_with_seed(6);
        let recipient_keys = keypair_with_seed(7);

        let real_owner =
            Address::from_public_key(&real_owner_keys.verifying_key_bytes(), NETWORK_TESTNET);
        let attacker = Address::from_public_key(&attacker_keys.verifying_key_bytes(), NETWORK_TESTNET);
        let recipient =
            Address::from_public_key(&recipient_keys.verifying_key_bytes(), NETWORK_TESTNET);

        let object = Object::new(7, Owner::Address(real_owner));
        let mut state = State::new();
        state.insert_object(object);

        let tx = TransferTx::new_unsigned(
            attacker_keys.verifying_key_bytes(),
            attacker,
            object.id(),
            recipient,
            0,
        )
        .sign(&attacker_keys)
        .expect("sign should succeed");

        let err = state.apply_transfer_tx(&tx).expect_err("transfer should fail");
        assert_eq!(err, StateError::NotObjectOwner);
    }

    #[test]
    fn replay_tx_fails_on_nonce_mismatch() {
        let sender_keys = keypair_with_seed(8);
        let recipient_keys = keypair_with_seed(9);

        let sender = Address::from_public_key(&sender_keys.verifying_key_bytes(), NETWORK_TESTNET);
        let recipient =
            Address::from_public_key(&recipient_keys.verifying_key_bytes(), NETWORK_TESTNET);

        let object = Object::new(8, Owner::Address(sender));
        let mut state = State::new();
        state.insert_object(object);

        let tx = TransferTx::new_unsigned(
            sender_keys.verifying_key_bytes(),
            sender,
            8,
            recipient,
            0,
        )
        .sign(&sender_keys)
        .expect("sign should succeed");

        state
            .apply_transfer_tx(&tx)
            .expect("first tx should be applied");

        let err = state
            .apply_transfer_tx(&tx)
            .expect_err("replay tx should fail");

        assert_eq!(err, StateError::InvalidNonce { expected: 1, got: 0 });
    }
}
