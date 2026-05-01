use crate::core::tx::Transaction;

pub trait ConsensusAdapter: Send + Sync {
    fn on_mempool_tx(&self, tx: &Transaction);
}

#[derive(Default)]
pub struct NoopConsensus;

impl ConsensusAdapter for NoopConsensus {
    fn on_mempool_tx(&self, _tx: &Transaction) {}
}
