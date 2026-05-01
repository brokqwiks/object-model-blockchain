use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::core::tx::Transaction;
use crate::crypto::hash::sha256;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MempoolEntry {
    pub tx_id: String,
    pub received_at_ms: u128,
    pub tx: Transaction,
}

#[derive(Debug, Default)]
pub struct Mempool {
    order: VecDeque<String>,
    entries: HashMap<String, MempoolEntry>,
}

impl Mempool {
    pub fn insert(&mut self, tx: Transaction) -> String {
        let tx_id = tx_id(&tx);
        if self.entries.contains_key(&tx_id) {
            return tx_id;
        }
        let entry = MempoolEntry {
            tx_id: tx_id.clone(),
            received_at_ms: now_ms(),
            tx,
        };
        self.order.push_back(tx_id.clone());
        self.entries.insert(tx_id.clone(), entry);
        tx_id
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn all(&self) -> Vec<MempoolEntry> {
        self.order
            .iter()
            .filter_map(|id| self.entries.get(id).cloned())
            .collect()
    }

    pub fn pop_front(&mut self) -> Option<MempoolEntry> {
        while let Some(id) = self.order.pop_front() {
            if let Some(entry) = self.entries.remove(&id) {
                return Some(entry);
            }
        }
        None
    }
}

pub fn tx_id(tx: &Transaction) -> String {
    let mut bytes = tx.signing_payload();
    bytes.extend_from_slice(&tx.signature);
    hex::encode(sha256(&bytes))
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}
