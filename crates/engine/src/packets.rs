//! Windows: the interface stays in the daemon, which relays its packets
//! on a pipe ([`vpn_core::engine_ipc::write_packet`]); and the daemon
//! accepts the session owner's prompt clients, whose connections it hands
//! over, announcing each one's handle on another pipe.

use std::os::windows::io::RawHandle;
use std::sync::Arc;

use bytes::Bytes;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader, ReadHalf, WriteHalf};
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use vpn_core::PacketIo;
use vpn_core::engine_ipc::{MAX_PACKET, read_packet, write_packet};

use crate::PromptHub;

const QUEUE: usize = 512;

/// The packet pipe, used by one attempt at a time.
pub(crate) struct Interfaces {
    read: Arc<Mutex<ReadHalf<NamedPipeClient>>>,
    write: Arc<Mutex<WriteHalf<NamedPipeClient>>>,
}

impl Interfaces {
    pub(crate) fn new(pipe: NamedPipeClient) -> Self {
        let (read, write) = tokio::io::split(pipe);
        Self { read: Arc::new(Mutex::new(read)), write: Arc::new(Mutex::new(write)) }
    }

    /// The packets of the attempt's interface; the first value keeps them
    /// moving.
    pub(crate) async fn attach(
        &self,
        _mtu: u16,
        cancel: CancellationToken,
    ) -> anyhow::Result<(Box<dyn Send>, PacketIo)> {
        let (to_tun, mut to_tun_rx) = mpsc::channel::<Bytes>(QUEUE);
        let (from_tun_tx, from_tun) = mpsc::channel::<Bytes>(QUEUE);
        let reader = {
            let (read, cancel) = (self.read.clone(), cancel.clone());
            tokio::spawn(async move {
                let mut read = read.lock().await;
                let mut buf = vec![0u8; MAX_PACKET];
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        packet = read_packet(&mut *read, &mut buf) => match packet {
                            Ok(Some(n)) => {
                                if from_tun_tx.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                                    break;
                                }
                            }
                            Ok(None) => break,
                            Err(e) => {
                                tracing::warn!("packet pipe: {e}");
                                break;
                            }
                        },
                    }
                }
            })
        };
        let writer = {
            let write = self.write.clone();
            tokio::spawn(async move {
                let mut write = write.lock().await;
                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => break,
                        packet = to_tun_rx.recv() => match packet {
                            Some(packet) => {
                                if let Err(e) = write_packet(&mut *write, &packet).await {
                                    tracing::warn!("packet pipe: {e}");
                                    break;
                                }
                            }
                            None => break,
                        },
                    }
                }
            })
        };
        Ok((Box::new(Pumps([reader, writer])), PacketIo { to_tun, from_tun }))
    }
}

/// Stopped with the attempt: the pipe is the next attempt's.
struct Pumps([JoinHandle<()>; 2]);

impl Drop for Pumps {
    fn drop(&mut self) {
        for pump in &self.0 {
            pump.abort();
        }
    }
}

/// The prompt clients handed over by the daemon: one handle per line.
pub(crate) async fn clients(pipe: NamedPipeClient, hub: Arc<PromptHub>) {
    let mut lines = BufReader::new(pipe);
    loop {
        let mut line = String::new();
        match (&mut lines).take(64).read_line(&mut line).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let Ok(handle) = line.trim().parse::<usize>() else {
            tracing::warn!("invalid client handle from the daemon");
            return;
        };
        // SAFETY: a connected pipe handle the daemon gave this process,
        // owned from now on.
        match unsafe { NamedPipeServer::from_raw_handle(handle as RawHandle) } {
            Ok(client) => hub.attach(client),
            Err(e) => tracing::warn!("prompt client: {e}"),
        }
    }
}
