use crate::crypto::hash::sha256;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};

pub const ADDRESS_HASH_LEN: usize = 32;
pub const ADDRESS_CHECKSUM_LEN: usize = 4;
pub const ADDRESS_LEN: usize = 1 + ADDRESS_HASH_LEN + ADDRESS_CHECKSUM_LEN;

pub const NETWORK_MAINNET: u8 = 0x00;
pub const NETWORK_TESTNET: u8 = 0x01;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    bytes: [u8; ADDRESS_LEN],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressError {
    InvalidLength,
    InvalidHex,
    InvalidChecksum,
}

impl core::fmt::Display for AddressError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AddressError::InvalidLength => write!(f, "invalid address length"),
            AddressError::InvalidHex => write!(f, "invalid address hex"),
            AddressError::InvalidChecksum => write!(f, "invalid address checksum"),
        }
    }
}

impl Address {
    pub fn from_public_key(verifying_key: &[u8; 32], network: u8) -> Self {
        let key_hash = sha256(verifying_key);
        let mut payload = [0u8; 1 + ADDRESS_HASH_LEN];
        payload[0] = network;
        payload[1..].copy_from_slice(&key_hash);

        let checksum = checksum(&payload);

        let mut bytes = [0u8; ADDRESS_LEN];
        bytes[..payload.len()].copy_from_slice(&payload);
        bytes[payload.len()..].copy_from_slice(&checksum);

        Self { bytes }
    }

    pub fn from_bytes(bytes: [u8; ADDRESS_LEN]) -> Result<Self, AddressError> {
        let payload_len = 1 + ADDRESS_HASH_LEN;
        let expected_checksum = checksum(&bytes[..payload_len]);
        let given_checksum = &bytes[payload_len..];

        if expected_checksum != given_checksum {
            return Err(AddressError::InvalidChecksum);
        }

        Ok(Self { bytes })
    }

    pub fn from_hex(hex: &str) -> Result<Self, AddressError> {
        let decoded = hex::decode(hex).map_err(|_| AddressError::InvalidHex)?;
        if decoded.len() != ADDRESS_LEN {
            return Err(AddressError::InvalidLength);
        }

        let mut bytes = [0u8; ADDRESS_LEN];
        bytes.copy_from_slice(&decoded);
        Self::from_bytes(bytes)
    }

    pub fn is_valid(&self) -> bool {
        Self::from_bytes(self.bytes).is_ok()
    }

    pub fn network(&self) -> u8 {
        self.bytes[0]
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    pub fn as_bytes(&self) -> [u8; ADDRESS_LEN] {
        self.bytes
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex = String::deserialize(deserializer)?;
        Address::from_hex(&hex).map_err(D::Error::custom)
    }
}

fn checksum(payload: &[u8]) -> [u8; ADDRESS_CHECKSUM_LEN] {
    let first = sha256(payload);
    let second = sha256(&first);
    let mut checksum = [0u8; ADDRESS_CHECKSUM_LEN];
    checksum.copy_from_slice(&second[..ADDRESS_CHECKSUM_LEN]);
    checksum
}
