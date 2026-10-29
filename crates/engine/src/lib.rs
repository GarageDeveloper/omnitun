//! A session's protocol work, outside the daemon: TLS, SAML, IKE and ESP
//! run here, unprivileged and sandboxed. The daemon starts one engine per
//! session and one attempt per `Start`, and hands it the tun interface;
//! the user's answers come straight from the client on the prompt socket.

mod prompts;

use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use vpn_core::engine_ipc::{EngineError, FromEngine, MAX_LINE, ToEngine};
use vpn_core::{Engine, Profile, ProtocolConfig, SessionContext, TunnelStats};

pub use prompts::PromptHub;

const STATS_EVERY: Duration = Duration::from_secs(1);
const LOGOUT_TIMEOUT: Duration = Duration::from_secs(5);

/// Serves the daemon until it closes the control socket: `control` carries
/// messages, `fds` the tun descriptors, `prompts` the owner's clients.
pub async fn serve(control: UnixStream, fds: StdUnixStream, prompts: UnixListener, owner: u32) -> anyhow::Result<()> {
    let (read, mut write) = control.into_split();
    let (out, mut out_rx) = mpsc::channel::<FromEngine>(64);
    let writer = tokio::spawn(async move {
        while let Some(message) = out_rx.recv().await {
            let mut line = serde_json::to_vec(&message).expect("messages serialize");
            line.push(b'\n');
            if write.write_all(&line).await.is_err() {
                break;
            }
        }
    });
    let hub = Arc::new(PromptHub::default());
    let (messages_tx, mut messages) = mpsc::channel::<ToEngine>(16);
    let stopper = hub.clone();
    let reader = tokio::spawn(async move {
        let mut lines = BufReader::new(read);
        loop {
            match next(&mut lines).await {
                Ok(Some(message)) => {
                    // Here, not in the attempt's loop: a signature asked from
                    // inside a TLS handshake holds the attempt's thread.
                    if matches!(message, ToEngine::Stop) {
                        stopper.stop_questions();
                    }
                    if messages_tx.send(message).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    tracing::warn!("control: {e:#}");
                    break;
                }
            }
        }
    });

    let listener = tokio::spawn(hub.clone().listen(prompts, owner));
    let fds = Arc::new(fds);
    while let Some(message) = messages.recv().await {
        let ToEngine::Start { profile, attach_wait_ms } = message else {
            tracing::debug!("ignoring {message:?} between attempts");
            continue;
        };
        hub.set_attach_wait(Duration::from_millis(attach_wait_ms));
        let stats = Arc::new(TunnelStats::default());
        let ctx = SessionContext {
            name: profile.name.clone(),
            prompter: hub.clone(),
            cancel: CancellationToken::new(),
            stats: stats.clone(),
        };
        let span = tracing::info_span!("engine", session = profile.name);
        let result = {
            let _enter = span.enter();
            attempt(&profile, &ctx, &out, &mut messages, fds.clone()).await
        };
        ctx.cancel.cancel();
        let error = result.err().map(|e| {
            tracing::info!(session = profile.name, "attempt ended: {e:#}");
            EngineError { failure: vpn_core::failure::kind_of(&e), message: format!("{e:#}") }
        });
        report_stats(&stats, &out, &mut (0, 0, 0, 0)).await;
        if out.send(FromEngine::Ended { error }).await.is_err() {
            break;
        }
    }
    listener.abort();
    reader.abort();
    drop(out);
    let _ = writer.await;
    Ok(())
}

/// One connection attempt; returns when it ends or the daemon stops it.
async fn attempt(
    profile: &Profile,
    ctx: &SessionContext,
    out: &mpsc::Sender<FromEngine>,
    messages: &mut mpsc::Receiver<ToEngine>,
    fds: Arc<StdUnixStream>,
) -> anyhow::Result<()> {
    let mut engine = make_engine(profile);
    // None: stopped by the daemon.
    let connected = {
        let connect = engine.connect(ctx);
        tokio::pin!(connect);
        loop {
            tokio::select! {
                res = &mut connect => break Some(res),
                message = messages.recv() => match message {
                    Some(ToEngine::Stop) | None => break None,
                    Some(other) => tracing::warn!("unexpected {other:?} while connecting"),
                },
            }
        }
    };
    let settings = match connected {
        Some(Ok(settings)) => settings,
        // Possibly logged in already (a FortiGate session cookie): closed
        // on the gateway too.
        ended => {
            logout(engine.as_mut()).await;
            return ended.map_or(Ok(()), |res| res.map(drop));
        }
    };
    let mtu = settings.mtu;
    out.send(FromEngine::Connected { settings }).await.context("daemon gone")?;

    // The daemon validates the settings, creates the interface and sends it.
    let name = loop {
        match messages.recv().await {
            Some(ToEngine::Tun { name }) => break name,
            Some(ToEngine::Stop) | None => {
                logout(engine.as_mut()).await;
                return Ok(());
            }
            Some(other) => tracing::warn!("unexpected {other:?} while waiting for the interface"),
        }
    };
    let fd = tokio::task::spawn_blocking(move || vpn_platform::fdpass::recv_fd(&*fds))
        .await?
        .context("no interface descriptor")?;
    let (interface, io) = vpn_platform::attach(fd, mtu, ctx.cancel.clone())?;
    tracing::info!("running on {name}");

    let reporter = {
        let (stats, out) = (ctx.stats.clone(), out.clone());
        tokio::spawn(async move {
            let mut last = (0, 0, 0, 0);
            loop {
                tokio::time::sleep(STATS_EVERY).await;
                report_stats(&stats, &out, &mut last).await;
            }
        })
    };
    let result = {
        let run = engine.run(ctx, io);
        tokio::pin!(run);
        loop {
            tokio::select! {
                res = &mut run => break match res {
                    Ok(()) => Err(anyhow::anyhow!("tunnel closed by the gateway")),
                    Err(e) => Err(e),
                },
                message = messages.recv() => match message {
                    Some(ToEngine::Stop) | None => break Ok(()),
                    Some(other) => tracing::warn!("unexpected {other:?} while running"),
                },
            }
        }
    };
    reporter.abort();
    ctx.cancel.cancel();
    drop(interface);
    logout(engine.as_mut()).await;
    result
}

/// Sends the counters since the last report.
async fn report_stats(stats: &TunnelStats, out: &mpsc::Sender<FromEngine>, last: &mut (u64, u64, u64, u64)) {
    let now = stats.snapshot();
    if now == *last {
        return;
    }
    let message = FromEngine::Stats {
        rx_bytes: now.0 - last.0,
        tx_bytes: now.1 - last.1,
        rx_packets: now.2 - last.2,
        tx_packets: now.3 - last.3,
    };
    *last = now;
    let _ = out.send(message).await;
}

async fn logout(engine: &mut dyn Engine) {
    match tokio::time::timeout(LOGOUT_TIMEOUT, engine.disconnect()).await {
        Ok(Err(e)) => tracing::debug!("logout failed: {e:#}"),
        Err(_) => tracing::debug!("logout timed out"),
        Ok(Ok(())) => {}
    }
}

fn make_engine(profile: &Profile) -> Box<dyn Engine> {
    match &profile.protocol {
        ProtocolConfig::FortiSsl(p) => Box::new(vpn_fortissl::FortiSslEngine::new(p.clone())),
        ProtocolConfig::Ipsec(p) => Box::new(vpn_ipsec::IpsecEngine::new(p.clone())),
        ProtocolConfig::OpenVpn(p) => Box::new(vpn_openvpn::OpenVpnEngine::new(p.clone())),
        ProtocolConfig::L2tp(p) => Box::new(vpn_l2tp::L2tpEngine::new(p.clone())),
        ProtocolConfig::WireGuard(p) => Box::new(vpn_wireguard::WireGuardEngine::new(p.clone())),
    }
}

async fn next(lines: &mut BufReader<tokio::net::unix::OwnedReadHalf>) -> anyhow::Result<Option<ToEngine>> {
    let mut line = String::new();
    let n = (&mut *lines).take(MAX_LINE as u64).read_line(&mut line).await?;
    if n == 0 {
        return Ok(None);
    }
    if !line.ends_with('\n') {
        bail!("control line too long");
    }
    Ok(Some(serde_json::from_str(&line)?))
}
