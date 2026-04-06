use crate::core::address::{ADDRESS_LEN, Address};
use crate::core::object_address::ObjectAddress;
use crate::crypto::keys::{Keypair, verify_signature};
use serde_json::json;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    TransferObject {
        object_address: ObjectAddress,
        new_owner: Address,
    },
    TransferCoin {
        coin_address: ObjectAddress,
        new_owner: Address,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub sender_public_key: [u8; 32],
    pub sender: Address,
    pub nonce: u64,
    pub effects: Vec<Effect>,
    pub signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxError {
    SenderDoesNotMatchKey,
}

impl Transaction {
    pub fn new_unsigned(
        sender_public_key: [u8; 32],
        sender: Address,
        nonce: u64,
        effects: Vec<Effect>,
    ) -> Self {
        Self {
            sender_public_key,
            sender,
            nonce,
            effects,
            signature: [0u8; 64],
        }
    }

    pub fn signing_payload(&self) -> Vec<u8> {
        let sender_bytes = self.sender.as_bytes();
        let mut payload = Vec::with_capacity(ADDRESS_LEN + 8 + 8 + self.effects.len() * 70);
        payload.extend_from_slice(&sender_bytes);
        payload.extend_from_slice(&self.nonce.to_le_bytes());
        payload.extend_from_slice(&(self.effects.len() as u64).to_le_bytes());

        for effect in &self.effects {
            match effect {
                Effect::TransferObject {
                    object_address,
                    new_owner,
                } => {
                    payload.push(0x01);
                    payload.extend_from_slice(&object_address.as_bytes());
                    payload.extend_from_slice(&new_owner.as_bytes());
                }
                Effect::TransferCoin {
                    coin_address,
                    new_owner,
                } => {
                    payload.push(0x02);
                    payload.extend_from_slice(&coin_address.as_bytes());
                    payload.extend_from_slice(&new_owner.as_bytes());
                }
            }
        }

        payload
    }

    pub fn sign(mut self, keypair: &Keypair) -> Result<Self, TxError> {
        if keypair.verifying_key_bytes() != self.sender_public_key {
            return Err(TxError::SenderDoesNotMatchKey);
        }

        let payload = self.signing_payload();
        self.signature = keypair.sign(&payload);
        Ok(self)
    }

    pub fn verify_signature(&self) -> bool {
        let payload = self.signing_payload();
        verify_signature(&self.sender_public_key, &payload, &self.signature)
    }

    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        let effects = self
            .effects
            .iter()
            .map(|effect| match effect {
                Effect::TransferObject {
                    object_address,
                    new_owner,
                } => {
                    json!({
                        "kind": "transfer_object",
                        "object_address": object_address.to_hex(),
                        "new_owner": new_owner.to_hex(),
                    })
                }
                Effect::TransferCoin {
                    coin_address,
                    new_owner,
                } => {
                    json!({
                        "kind": "transfer_coin",
                        "coin_address": coin_address.to_hex(),
                        "new_owner": new_owner.to_hex(),
                    })
                }
            })
            .collect::<Vec<_>>();

        let value = json!({
            "sender_public_key": hex::encode(self.sender_public_key),
            "sender": self.sender.to_hex(),
            "nonce": self.nonce,
            "effects": effects,
            "signature": hex::encode(self.signature),
        });
        serde_json::to_string_pretty(&value)
    }
}
