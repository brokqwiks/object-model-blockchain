use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::core::tx::Transaction;

use super::consensus::ConsensusAdapter;
use super::mempool::Mempool;

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub node_id: String,
    pub listen_addr: String,
    pub peers: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum WireMessage {
    Hello {
        node_id: String,
        listen_addr: String,
    },
    TxBroadcast {
        tx: Transaction,
    },
    Ping {
        node_id: String,
    },
}

pub struct NetworkService {
    node_id: String,
    listen_addr: String,
    peers: Arc<Mutex<HashSet<String>>>,
    mempool: Arc<Mutex<Mempool>>,
    consensus: Arc<dyn ConsensusAdapter>,
    running: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl NetworkService {
    pub fn start(
        config: NetworkConfig,
        mempool: Arc<Mutex<Mempool>>,
        consensus: Arc<dyn ConsensusAdapter>,
    ) -> Result<Self, String> {
        let listener = TcpListener::bind(&config.listen_addr)
            .map_err(|e| format!("bind {} failed: {e}", config.listen_addr))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("set_nonblocking failed: {e}"))?;

        let peers = Arc::new(Mutex::new(config.peers.into_iter().collect::<HashSet<_>>()));
        let running = Arc::new(AtomicBool::new(true));
        let worker_running = Arc::clone(&running);
        let worker_peers = Arc::clone(&peers);
        let worker_mempool = Arc::clone(&mempool);
        let worker_consensus = Arc::clone(&consensus);
        let listen_addr = config.listen_addr.clone();
        let node_id = config.node_id.clone();

        let worker = thread::spawn(move || {
            while worker_running.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = handle_connection(
                            stream,
                            &worker_peers,
                            &worker_mempool,
                            &worker_consensus,
                        );
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => {
                        thread::sleep(Duration::from_millis(50));
                    }
                }
            }
        });

        let service = Self {
            node_id,
            listen_addr,
            peers,
            mempool,
            consensus,
            running,
            worker: Some(worker),
        };

        let hello = WireMessage::Hello {
            node_id: service.node_id.clone(),
            listen_addr: service.listen_addr.clone(),
        };
        let _ = service.broadcast_raw(&hello);

        Ok(service)
    }

    pub fn broadcast_tx(&self, tx: &Transaction) {
        let msg = WireMessage::TxBroadcast { tx: tx.clone() };
        let _ = self.broadcast_raw(&msg);
    }

    pub fn add_peer(&self, addr: String) {
        if let Ok(mut peers) = self.peers.lock() {
            peers.insert(addr);
        }
    }

    pub fn status_line(&self) -> String {
        let peer_count = self.peers.lock().map(|p| p.len()).unwrap_or(0);
        let mempool_len = self.mempool.lock().map(|m| m.len()).unwrap_or(0);
        let _ = &self.consensus;
        format!(
            "node_id={} listen_addr={} peers={} mempool={}",
            self.node_id, self.listen_addr, peer_count, mempool_len
        )
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }

    fn broadcast_raw(&self, msg: &WireMessage) -> Result<(), String> {
        let payload = serde_json::to_string(msg).map_err(|e| format!("encode failed: {e}"))?;
        let peers = self
            .peers
            .lock()
            .map_err(|_| "peers lock poisoned".to_string())?
            .clone();

        for peer in peers {
            let _ = send_line(&peer, &payload);
        }
        Ok(())
    }
}

impl Drop for NetworkService {
    fn drop(&mut self) {
        self.stop();
    }
}

fn handle_connection(
    stream: TcpStream,
    peers: &Arc<Mutex<HashSet<String>>>,
    mempool: &Arc<Mutex<Mempool>>,
    consensus: &Arc<dyn ConsensusAdapter>,
) -> Result<(), String> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let bytes = reader
        .read_line(&mut line)
        .map_err(|e| format!("read_line failed: {e}"))?;
    if bytes == 0 {
        return Ok(());
    }

    let msg: WireMessage =
        serde_json::from_str(line.trim()).map_err(|e| format!("invalid wire message: {e}"))?;

    match msg {
        WireMessage::Hello {
            node_id: _,
            listen_addr,
        } => {
            if let Ok(mut p) = peers.lock() {
                p.insert(listen_addr);
            }
        }
        WireMessage::TxBroadcast { tx } => {
            if let Ok(mut mp) = mempool.lock() {
                mp.insert(tx.clone());
            }
            consensus.on_mempool_tx(&tx);
        }
        WireMessage::Ping { .. } => {}
    }

    Ok(())
}

fn send_line(addr: &str, payload: &str) -> Result<(), String> {
    let mut stream = TcpStream::connect(addr).map_err(|e| format!("connect {addr} failed: {e}"))?;
    stream
        .write_all(payload.as_bytes())
        .map_err(|e| format!("write failed: {e}"))?;
    stream
        .write_all(b"\n")
        .map_err(|e| format!("newline write failed: {e}"))?;
    Ok(())
}
