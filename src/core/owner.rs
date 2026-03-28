use serde::{Deserialize, Serialize};
use crate::core::address::Address;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Owner {
    Address(Address),
    Object([u8; 32])
}

impl Owner {
    pub fn to_hex(&self) -> String {
        match self {
            Owner::Address(addr) => addr.to_hex(),
            Owner::Object(obj) => hex::encode(obj),
        }
    }
}
