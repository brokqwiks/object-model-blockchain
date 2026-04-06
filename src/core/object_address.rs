use crate::crypto::hash::sha256;
use rand::random;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static OBJECT_ADDRESS_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectAddress {
    bytes: [u8; 32],
}

impl ObjectAddress {
    pub fn new_unique() -> Self {
        let counter = OBJECT_ADDRESS_COUNTER.fetch_add(1, Ordering::Relaxed);
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let entropy: [u8; 32] = random();

        let mut seed = Vec::with_capacity(8 + 8 + 32);
        seed.extend_from_slice(&counter.to_le_bytes());
        seed.extend_from_slice(&now_nanos.to_le_bytes());
        seed.extend_from_slice(&entropy);

        let bytes = sha256(&seed);
        Self { bytes }
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }
}
