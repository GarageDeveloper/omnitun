use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tun_rs::{AsyncDevice, DeviceBuilder};
use vpn_core::{PacketIo, TunnelSettings};

const QUEUE: usize = 512;

/// A tun interface bridged to an engine through channels.
pub struct TunInterface {
    pub name: String,
    device: Arc<AsyncDevice>,
    pumps: Vec<JoinHandle<()>>,
}

/// A tun interface created by the daemon for an engine process: the daemon
/// configures routes and DNS on `name` and hands the descriptor over.
pub struct TunDevice {
    pub name: String,
    /// Windows: read by the packet relay to the engine (not written yet).
    #[cfg_attr(windows, allow(dead_code))]
    device: tun_rs::SyncDevice,
}

#[cfg(unix)]
impl TunDevice {
    pub fn fd(&self) -> std::os::fd::RawFd {
        std::os::fd::AsRawFd::as_raw_fd(&self.device)
    }
}

/// Creates the interface for a session's settings, without moving packets.
pub fn create_device(settings: &TunnelSettings) -> anyhow::Result<TunDevice> {
    let device = builder(settings)?.build_sync()?;
    Ok(TunDevice { name: device.name()?, device })
}

/// Creates the interface for a session and returns the engine side of the
/// packet channels. Pumps stop when `cancel` fires or a channel closes.
pub fn create(settings: &TunnelSettings, cancel: CancellationToken) -> anyhow::Result<(TunInterface, PacketIo)> {
    let device = builder(settings)?.build_async()?;
    bridge(device, settings.mtu, cancel)
}

/// A point-to-point interface with the tunnel's address. On Windows, a
/// Wintun adapter: the destination would be a default route's gateway
/// there, and `wintun.dll` is the one next to this program.
fn builder(settings: &TunnelSettings) -> anyhow::Result<DeviceBuilder> {
    let peer = if cfg!(windows) { None } else { Some(settings.address) };
    let builder = DeviceBuilder::new().ipv4(settings.address, 32, peer).mtu(settings.mtu);
    #[cfg(windows)]
    let builder = {
        let dll = std::env::current_exe()?.with_file_name("wintun.dll");
        builder.wintun_file(dll.display().to_string()).description(vpn_core::brand::PRODUCT)
    };
    Ok(builder)
}

/// Moves packets for an interface received from the daemon (engine side).
#[cfg(unix)]
pub fn attach(
    fd: std::os::fd::OwnedFd,
    mtu: u16,
    cancel: CancellationToken,
) -> anyhow::Result<(TunInterface, PacketIo)> {
    use std::os::fd::IntoRawFd;
    // SAFETY: `fd` is a tun descriptor owned by this process; the device
    // takes over closing it.
    let device = unsafe { AsyncDevice::from_fd(fd.into_raw_fd())? };
    bridge(device, mtu, cancel)
}

fn bridge(device: AsyncDevice, mtu: u16, cancel: CancellationToken) -> anyhow::Result<(TunInterface, PacketIo)> {
    let device = Arc::new(device);
    let name = device.name()?;

    let (to_tun_tx, mut to_tun_rx) = mpsc::channel::<Bytes>(QUEUE);
    let (from_tun_tx, from_tun_rx) = mpsc::channel::<Bytes>(QUEUE);

    let reader = {
        let device = device.clone();
        let cancel = cancel.clone();
        let mtu = mtu as usize;
        tokio::spawn(async move {
            let mut buf = vec![0u8; mtu + 64];
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    res = device.recv(&mut buf) => match res {
                        Ok(0) => continue,
                        Ok(n) => {
                            if from_tun_tx.send(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("tun read: {e}");
                            break;
                        }
                    },
                }
            }
        })
    };
    let writer = {
        let device = device.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    pkt = to_tun_rx.recv() => match pkt {
                        Some(pkt) => {
                            if let Err(e) = device.send(&pkt).await {
                                tracing::warn!("tun write: {e}");
                            }
                        }
                        None => break,
                    },
                }
            }
        })
    };

    let io = PacketIo { to_tun: to_tun_tx, from_tun: from_tun_rx };
    Ok((TunInterface { name, device, pumps: vec![reader, writer] }, io))
}

impl TunInterface {
    pub fn index(&self) -> Option<u32> {
        self.device.if_index().ok()
    }
}

impl Drop for TunInterface {
    fn drop(&mut self) {
        for pump in &self.pumps {
            pump.abort();
        }
    }
}
