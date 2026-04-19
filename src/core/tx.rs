use crate::core::address::{ADDRESS_LEN, Address};
use crate::core::object_address::ObjectAddress;
use crate::crypto::keys::{AuthorizedOneTimeSigner, verify_signature};
use crate::vm::bytecode::Instruction;
use serde_json::json;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Effect {
    TransferObject {
        object_address: ObjectAddress,
        new_owner: Address,
    },
    TransferCoin {
        coin_address: ObjectAddress,
        new_owner: Address,
    },
    TransferCoinAmount {
        from_coin_address: ObjectAddress,
        amount: u64,
        recipient: Address,
        recipient_coin_address: ObjectAddress,
        change_coin_address: Option<ObjectAddress>,
    },
    RotateOneTimeRoot {
        new_root: [u8; 32],
    },
    PublishContract {
        contract_address: ObjectAddress,
        code: ContractCode,
    },
    ExecuteContract {
        contract_address: ObjectAddress,
        max_steps: u32,
        call_args_json: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContractCode {
    Template {
        template_id: u8,
    },
    Custom {
        name: String,
        bytecode: Vec<Instruction>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transaction {
    pub chain_id: u32,
    pub tx_version: u16,
    pub sender: Address,
    pub one_time_public_key: [u8; 32],
    pub one_time_index: u64,
    pub one_time_merkle_proof: Vec<[u8; 32]>,
    pub nonce: u64,
    pub effects: Vec<Effect>,
    pub signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxError {
    SignerAccountMismatch,
    SignerOneTimeKeyMismatch,
    SignerIndexMismatch,
}

impl Transaction {
    pub fn new_unsigned(
        signer: &AuthorizedOneTimeSigner,
        chain_id: u32,
        nonce: u64,
        effects: Vec<Effect>,
    ) -> Self {
        Self {
            chain_id,
            tx_version: 1,
            sender: signer.account_address(),
            one_time_public_key: signer.one_time_public_key(),
            one_time_index: signer.index(),
            one_time_merkle_proof: signer.merkle_proof().to_vec(),
            nonce,
            effects,
            signature: [0u8; 64],
        }
    }

    pub fn signing_payload(&self) -> Vec<u8> {
        let sender_bytes = self.sender.as_bytes();
        let mut payload = Vec::with_capacity(
            11 + 4
                + 2
                + ADDRESS_LEN
                + 32
                + 8
                + 8
                + self.one_time_merkle_proof.len() * 32
                + self.effects.len() * 70,
        );
        payload.extend_from_slice(b"TX_INTENT_V1");
        payload.extend_from_slice(&self.chain_id.to_le_bytes());
        payload.extend_from_slice(&self.tx_version.to_le_bytes());
        payload.extend_from_slice(&sender_bytes);
        payload.extend_from_slice(&self.one_time_public_key);
        payload.extend_from_slice(&self.one_time_index.to_le_bytes());
        payload.extend_from_slice(&(self.one_time_merkle_proof.len() as u64).to_le_bytes());
        for node in &self.one_time_merkle_proof {
            payload.extend_from_slice(node);
        }
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
                Effect::TransferCoinAmount {
                    from_coin_address,
                    amount,
                    recipient,
                    recipient_coin_address,
                    change_coin_address,
                } => {
                    payload.push(0x04);
                    payload.extend_from_slice(&from_coin_address.as_bytes());
                    payload.extend_from_slice(&amount.to_le_bytes());
                    payload.extend_from_slice(&recipient.as_bytes());
                    payload.extend_from_slice(&recipient_coin_address.as_bytes());
                    match change_coin_address {
                        Some(addr) => {
                            payload.push(0x01);
                            payload.extend_from_slice(&addr.as_bytes());
                        }
                        None => payload.push(0x00),
                    }
                }
                Effect::RotateOneTimeRoot { new_root } => {
                    payload.push(0x03);
                    payload.extend_from_slice(new_root);
                }
                Effect::PublishContract {
                    contract_address,
                    code,
                } => {
                    payload.push(0x05);
                    payload.extend_from_slice(&contract_address.as_bytes());
                    match code {
                        ContractCode::Template { template_id } => {
                            payload.push(0x01);
                            payload.push(*template_id);
                        }
                        ContractCode::Custom { name, bytecode } => {
                            payload.push(0x02);
                            payload.extend_from_slice(&(name.len() as u64).to_le_bytes());
                            payload.extend_from_slice(name.as_bytes());
                            payload.extend_from_slice(&(bytecode.len() as u64).to_le_bytes());
                            for instruction in bytecode {
                                let encoded =
                                    serde_json::to_vec(instruction).expect("instruction encode");
                                payload.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
                                payload.extend_from_slice(&encoded);
                            }
                        }
                    }
                }
                Effect::ExecuteContract {
                    contract_address,
                    max_steps,
                    call_args_json,
                } => {
                    payload.push(0x06);
                    payload.extend_from_slice(&contract_address.as_bytes());
                    payload.extend_from_slice(&max_steps.to_le_bytes());
                    payload.extend_from_slice(&(call_args_json.len() as u64).to_le_bytes());
                    payload.extend_from_slice(call_args_json.as_bytes());
                }
            }
        }

        payload
    }

    pub fn sign(mut self, signer: &AuthorizedOneTimeSigner) -> Result<Self, TxError> {
        if signer.account_address() != self.sender {
            return Err(TxError::SignerAccountMismatch);
        }
        if signer.one_time_public_key() != self.one_time_public_key {
            return Err(TxError::SignerOneTimeKeyMismatch);
        }
        if signer.index() != self.one_time_index {
            return Err(TxError::SignerIndexMismatch);
        }

        let payload = self.signing_payload();
        self.signature = signer.sign_payload(&payload);
        Ok(self)
    }

    pub fn verify_signature(&self) -> bool {
        let payload = self.signing_payload();
        verify_signature(&self.one_time_public_key, &payload, &self.signature)
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
                Effect::TransferCoinAmount {
                    from_coin_address,
                    amount,
                    recipient,
                    recipient_coin_address,
                    change_coin_address,
                } => {
                    json!({
                        "kind": "transfer_coin_amount",
                        "from_coin_address": from_coin_address.to_hex(),
                        "amount": amount,
                        "recipient": recipient.to_hex(),
                        "recipient_coin_address": recipient_coin_address.to_hex(),
                        "change_coin_address": change_coin_address.map(|v| v.to_hex()),
                    })
                }
                Effect::RotateOneTimeRoot { new_root } => {
                    json!({
                        "kind": "rotate_one_time_root",
                        "new_root": hex::encode(new_root),
                    })
                }
                Effect::PublishContract {
                    contract_address,
                    code,
                } => match code {
                    ContractCode::Template { template_id } => json!({
                        "kind": "publish_contract",
                        "contract_address": contract_address.to_hex(),
                        "code_kind": "template",
                        "template_id": template_id,
                    }),
                    ContractCode::Custom { name, bytecode } => json!({
                        "kind": "publish_contract",
                        "contract_address": contract_address.to_hex(),
                        "code_kind": "custom",
                        "name": name,
                        "bytecode_len": bytecode.len(),
                    }),
                },
                Effect::ExecuteContract {
                    contract_address,
                    max_steps,
                    call_args_json,
                } => {
                    json!({
                        "kind": "execute_contract",
                        "contract_address": contract_address.to_hex(),
                        "max_steps": max_steps,
                        "call_args_json": call_args_json,
                    })
                }
            })
            .collect::<Vec<_>>();

        let proof = self
            .one_time_merkle_proof
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>();

        let value = json!({
            "sender": self.sender.to_hex(),
            "chain_id": self.chain_id,
            "tx_version": self.tx_version,
            "one_time_public_key": hex::encode(self.one_time_public_key),
            "one_time_index": self.one_time_index,
            "one_time_merkle_proof": proof,
            "nonce": self.nonce,
            "effects": effects,
            "signature": hex::encode(self.signature),
        });
        serde_json::to_string_pretty(&value)
    }
}
