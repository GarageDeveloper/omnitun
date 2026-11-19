//! Brings a WireGuard profile up as a real tunnel, in this process: the
//! system's interface, routes and DNS, as the daemon would set them, for
//! the time given; then everything is removed. A check of the platform
//! layer by hand (`ping`, `Resolve-DnsName`, `route print` meanwhile),
//! run as an administrator (root, or SYSTEM on Windows, with `wintun.dll`
//! next to this program).
//!
//! `cargo run -p vpn-wireguard --example wg-tunnel -- <profiles.toml> <name> <seconds>`
//!
//! The keys come from the environment: `INTEROP_PRIVATE_KEY`,
//! `INTEROP_PSK`.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use vpn_core::{Engine, ProfileFile, Prompt, Prompter, ProtocolConfig, SessionContext};
use vpn_wireguard::WireGuardEngine;

struct EnvPrompter;

#[async_trait]
impl Prompter for EnvPrompter {
    async fn ask(&self, prompt: Prompt) -> anyhow::Result<zeroize::Zeroizing<String>> {
        let var = match prompt.key.as_str() {
            "private_key" => "INTEROP_PRIVATE_KEY",
            "psk" => "INTEROP_PSK",
            other => bail!("unexpected question {other:?}: {}", prompt.message),
        };
        std::env::var(var).map(zeroize::Zeroizing::new).with_context(|| format!("{var} is not set"))
    }

    async fn open_url(&self, _: &str) -> anyhow::Result<()> {
        bail!("no browser")
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into())).init();
    let args: Vec<String> = std::env::args().collect();
    let [_, file, name, seconds] = args.as_slice() else {
        bail!("usage: wg-tunnel <profiles.toml> <name> <seconds>");
    };
    let seconds: u64 = seconds.parse().context("seconds")?;
    let file: ProfileFile = toml::from_str(&std::fs::read_to_string(file)?)?;
    let profile = file.profiles.into_iter().find(|p| &p.name == name).with_context(|| format!("no profile {name}"))?;
    profile.validate()?;
    let ProtocolConfig::WireGuard(wireguard) = profile.protocol else { bail!("{name} is not a WireGuard profile") };

    let ctx = SessionContext {
        name: name.clone(),
        prompter: Arc::new(EnvPrompter),
        cancel: CancellationToken::new(),
        stats: Arc::default(),
    };
    let mut engine = WireGuardEngine::new(wireguard);
    let settings = tokio::time::timeout(Duration::from_secs(30), engine.connect(&ctx)).await.context("timeout")??;
    vpn_platform::prepare_runtime_dir()?;
    let (tun, io) = vpn_platform::create(&settings, ctx.cancel.clone()).context("cannot create the interface")?;
    let mut applied = vpn_platform::apply("wg-tunnel", &tun.name, &settings, None).await?;
    println!(
        "up on {} (index {:?}): address {}, routes {:?}, full tunnel {}, dns {:?}; for {seconds} s",
        tun.name,
        tun.index(),
        settings.address,
        settings.routes,
        settings.full_tunnel,
        settings.dns
    );

    let run_ctx = ctx.clone();
    let runner = tokio::spawn(async move {
        let result = engine.run(&run_ctx, io).await;
        engine.disconnect().await.ok();
        result
    });
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(seconds)) => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    applied.revert().await;
    ctx.cancel.cancel();
    runner.await??;
    let count = |c: &std::sync::atomic::AtomicU64| c.load(std::sync::atomic::Ordering::Relaxed);
    println!("down: packets sent {}, received {}", count(&ctx.stats.tx_packets), count(&ctx.stats.rx_packets));
    Ok(())
}
