use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::{Prompter, TunnelSettings};

/// Per-session environment handed to an engine.
#[derive(Clone)]
pub struct SessionContext {
    pub name: String,
    pub prompter: Arc<dyn Prompter>,
    pub cancel: CancellationToken,
    pub stats: Arc<TunnelStats>,
}

#[derive(Debug, Default)]
pub struct TunnelStats {
    pub tx_packets: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
}

impl TunnelStats {
    pub fn record_tx(&self, len: usize) {
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(len as u64, Ordering::Relaxed);
    }

    pub fn record_rx(&self, len: usize) {
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes.fetch_add(len as u64, Ordering::Relaxed);
    }

    /// Adds counters reported by an engine process.
    pub fn add(&self, rx_bytes: u64, tx_bytes: u64, rx_packets: u64, tx_packets: u64) {
        self.rx_bytes.fetch_add(rx_bytes, Ordering::Relaxed);
        self.tx_bytes.fetch_add(tx_bytes, Ordering::Relaxed);
        self.rx_packets.fetch_add(rx_packets, Ordering::Relaxed);
        self.tx_packets.fetch_add(tx_packets, Ordering::Relaxed);
    }

    /// (rx bytes, tx bytes, rx packets, tx packets).
    pub fn snapshot(&self) -> (u64, u64, u64, u64) {
        (
            self.rx_bytes.load(Ordering::Relaxed),
            self.tx_bytes.load(Ordering::Relaxed),
            self.rx_packets.load(Ordering::Relaxed),
            self.tx_packets.load(Ordering::Relaxed),
        )
    }
}

/// IP packets exchanged between an engine and its tun interface.
pub struct PacketIo {
    /// Decapsulated packets to write to the tun interface.
    pub to_tun: mpsc::Sender<Bytes>,
    /// Packets read from the tun interface, to encapsulate.
    pub from_tun: mpsc::Receiver<Bytes>,
}

/// A VPN protocol implementation. One instance drives one session.
///
/// Lifecycle: `connect` (authenticate, negotiate) → the session manager
/// creates the tun interface from the returned settings → `run` until the
/// tunnel ends or `ctx.cancel` fires → `disconnect` (best-effort logout).
#[async_trait]
pub trait Engine: Send {
    async fn connect(&mut self, ctx: &SessionContext) -> anyhow::Result<TunnelSettings>;
    async fn run(&mut self, ctx: &SessionContext, io: PacketIo) -> anyhow::Result<()>;
    async fn disconnect(&mut self) -> anyhow::Result<()>;
}
