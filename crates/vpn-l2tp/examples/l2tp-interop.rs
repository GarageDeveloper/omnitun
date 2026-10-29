//! Connects to a real L2TP/IPsec server with one profile of a profiles
//! file, pings an address through the tunnel, then disconnects: the
//! interoperability check run by `interop/l2tp/run.sh`.
//!
//! `cargo run -p vpn-l2tp --example l2tp-interop -- <profiles.toml> <name> <ip>`
//!
//! Answers come from the environment: `INTEROP_PSK`, `INTEROP_USERNAME`,
//! `INTEROP_PASSWORD`.
//!
//! `INTEROP_DURATION=<seconds>` keeps the tunnel up that long, pinging
//! every second (across a rekey, say); 90% of the pings must be answered.
//! `INTEROP_EXPECT` lists, separated by commas, what the server must have
//! given: `dns=<address>`, `route=<network>`, `full-tunnel`.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use vpn_core::{Engine, PacketIo, ProfileFile, Prompt, Prompter, ProtocolConfig, SessionContext, TunnelSettings};
use vpn_l2tp::L2tpEngine;

struct EnvPrompter;

#[async_trait]
impl Prompter for EnvPrompter {
    async fn ask(&self, prompt: Prompt) -> anyhow::Result<zeroize::Zeroizing<String>> {
        // The test answers, erased like real ones.
        let answer: anyhow::Result<String> = async {
            let var = match prompt.key.as_str() {
                "psk" => "INTEROP_PSK",
                "username" => "INTEROP_USERNAME",
                "password" => "INTEROP_PASSWORD",
                other => bail!("unexpected question {other:?}: {}", prompt.message),
            };
            std::env::var(var).with_context(|| format!("{var} is not set"))
        }
        .await;
        answer.map(zeroize::Zeroizing::new)
    }

    async fn open_url(&self, _: &str) -> anyhow::Result<()> {
        bail!("no browser")
    }
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = data.chunks(2).map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]))).sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn echo_request(src: Ipv4Addr, dst: Ipv4Addr, seq: u16) -> Vec<u8> {
    let mut icmp = vec![8, 0, 0, 0, 0x4f, 0x54];
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(b"omnitun interop");
    let sum = checksum(&icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());
    let mut ip = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 1, 0, 0];
    ip[2..4].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let sum = checksum(&ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
    ip.extend_from_slice(&icmp);
    ip
}

/// The sequence number of an echo reply from `from`.
fn echo_reply(packet: &[u8], from: Ipv4Addr) -> Option<u16> {
    let reply = packet.len() >= 28 && packet[9] == 1 && packet[12..16] == from.octets() && packet[20] == 0;
    reply.then(|| u16::from_be_bytes([packet[26], packet[27]]))
}

/// What `INTEROP_EXPECT` asks for and the server did not give.
fn missing_settings(settings: &TunnelSettings, expect: &str) -> Vec<String> {
    let mut missing = Vec::new();
    for item in expect.split([',', ' ']).filter(|i| !i.is_empty()) {
        let (kind, value) = item.split_once('=').unwrap_or((item, ""));
        let found = match kind {
            "full-tunnel" => settings.full_tunnel,
            "route" => value.parse().is_ok_and(|net| settings.routes.contains(&net)),
            "dns" => value.parse().is_ok_and(|ip| settings.dns.servers.contains(&ip)),
            _ => false,
        };
        if !found {
            missing.push(item.to_string());
        }
    }
    missing
}

/// Pings `target` once a second for `seconds` (or until the first answer
/// when 0, five tries); returns the pings sent and answered.
async fn ping(
    tun_tx: &mpsc::Sender<Bytes>,
    tun_rx: &mut mpsc::Receiver<Bytes>,
    src: Ipv4Addr,
    target: Ipv4Addr,
    seconds: u16,
) -> anyhow::Result<(usize, usize)> {
    let mut answered = BTreeSet::new();
    let count = if seconds == 0 { 5 } else { seconds };
    let mut sent = 0;
    for seq in 1..=count {
        tun_tx.send(Bytes::from(echo_request(src, target, seq))).await?;
        sent += 1;
        let next = Instant::now() + Duration::from_secs(1);
        while let Ok(Some(packet)) = tokio::time::timeout_at(next, tun_rx.recv()).await {
            if let Some(seq) = echo_reply(&packet, target) {
                answered.insert(seq);
            }
        }
        if seconds == 0 && !answered.is_empty() {
            break;
        }
    }
    Ok((sent, answered.len()))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into())).init();
    let args: Vec<String> = std::env::args().collect();
    let [_, file, name, target] = args.as_slice() else {
        bail!("usage: l2tp-interop <profiles.toml> <name> <ip to ping>");
    };
    let target: Ipv4Addr = target.parse()?;
    let seconds: u16 = std::env::var("INTEROP_DURATION").ok().filter(|s| !s.is_empty()).map_or(Ok(0), |s| s.parse())?;
    let file: ProfileFile = toml::from_str(&std::fs::read_to_string(file)?)?;
    let profile = file.profiles.into_iter().find(|p| &p.name == name).with_context(|| format!("no profile {name}"))?;
    profile.validate()?;
    let ProtocolConfig::L2tp(l2tp) = profile.protocol else { bail!("{name} is not an L2TP profile") };

    let ctx = SessionContext {
        name: name.clone(),
        prompter: Arc::new(EnvPrompter),
        cancel: CancellationToken::new(),
        stats: Arc::default(),
    };
    let mut engine = L2tpEngine::new(l2tp);
    // IKE phase 1 and 2, then L2TP and PPP: longer than the other engines.
    let settings = tokio::time::timeout(Duration::from_secs(45), engine.connect(&ctx)).await.context("timeout")??;
    println!(
        "connected: address {}, mtu {}, routes {:?}, full tunnel {}, dns {:?}",
        settings.address, settings.mtu, settings.routes, settings.full_tunnel, settings.dns
    );

    let (to_tun, mut tun_rx) = mpsc::channel(16);
    let (tun_tx, from_tun) = mpsc::channel(16);
    let run_ctx = ctx.clone();
    let runner = tokio::spawn(async move {
        let result = engine.run(&run_ctx, PacketIo { to_tun, from_tun }).await;
        engine.disconnect().await.ok();
        result
    });
    let (sent, answered) = ping(&tun_tx, &mut tun_rx, settings.address, target, seconds).await?;
    let stats = &ctx.stats;
    let count = |c: &std::sync::atomic::AtomicU64| c.load(std::sync::atomic::Ordering::Relaxed);
    println!("packets sent {}, received {}", count(&stats.tx_packets), count(&stats.rx_packets));
    ctx.cancel.cancel();
    runner.await??;
    let missing = missing_settings(&settings, &std::env::var("INTEROP_EXPECT").unwrap_or_default());
    if !missing.is_empty() {
        bail!("not given by the server: {}", missing.join(", "));
    }
    if answered == 0 || (seconds > 0 && answered * 10 < sent * 9) {
        bail!("{answered} of {sent} pings to {target} answered through the tunnel");
    }
    println!("ping {target} through the tunnel: ok ({answered} of {sent} answered)");
    Ok(())
}
