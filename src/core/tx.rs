use crate::core::address::{ADDRESS_LEN, Address};
use crate::crypto::keys::{Keypair, verify_signature};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferTx {
    pub sender_public_key: [u8; 32],
    pub sender: Address,
    pub object_id: u64,
    pub new_owner: Address,
    pub nonce: u64,
    pub signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxError {
    SenderDoesNotMatchKey,
}

impl TransferTx {
    pub fn new_unsigned(
        sender_public_key: [u8; 32],
        sender: Address,
        object_id: u64,
        new_owner: Address,
        nonce: u64,
    ) -> Self {
        Self {
            sender_public_key,
            sender,
            object_id,
            new_owner,
            nonce,
            signature: [0u8; 64],
        }
    }

    pub fn signing_payload(&self) -> Vec<u8> {
        let sender_bytes = self.sender.as_bytes();
        let new_owner_bytes = self.new_owner.as_bytes();

        let mut payload = Vec::with_capacity(ADDRESS_LEN * 2 + 8 + 8);
        payload.extend_from_slice(&sender_bytes);
        payload.extend_from_slice(&self.object_id.to_le_bytes());
        payload.extend_from_slice(&new_owner_bytes);
        payload.extend_from_slice(&self.nonce.to_le_bytes());
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
}
