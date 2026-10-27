//! Connection to `omnitund`'s control socket: newline-delimited JSON,
//! starting with the `hello` handshake.

use anyhow::{Context, bail};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use vpn_core::ipc::{Event, PROTOCOL_VERSION, Request, SessionInfo};
use vpn_core::{FailureExt, FailureKind, brand};
use zeroize::Zeroizing;

use crate::printable;

pub struct Daemon {
    lines: tokio::io::Lines<BufReader<OwnedReadHalf>>,
    write: OwnedWriteHalf,
    version: String,
    features: Vec<String>,
}

impl Daemon {
    /// Connects and greets the daemon as `client` (shown in its logs).
    pub async fn open(client: &str) -> anyhow::Result<Self> {
        let path = vpn_core::ipc::socket_path();
        let stream = UnixStream::connect(&path)
            .await
            .with_context(|| format!("cannot reach {} at {path} (is it running, are you in its group?)", brand::DAEMON))
            .kind(FailureKind::ServiceUnavailable)?;
        let (read, write) = stream.into_split();
        let mut daemon =
            Self { lines: BufReader::new(read).lines(), write, version: String::new(), features: Vec::new() };
        daemon
            .send(&Request::Hello { protocol: PROTOCOL_VERSION, client: client.into(), version: vpn_core::version() })
            .await?;
        match daemon.next().await? {
            Event::Hello { version, features, .. } => {
                daemon.version = version;
                daemon.features = features;
                Ok(daemon)
            }
            Event::Error { message, .. } => {
                Err(vpn_core::failure(FailureKind::ServiceUnavailable, printable(&message)))
            }
            other => bail!("unexpected answer to hello: {other:?}"),
        }
    }

    /// The daemon's version.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Optional capabilities announced by the daemon.
    pub fn supports(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }

    pub async fn send(&mut self, request: &Request) -> anyhow::Result<()> {
        // The line may carry a secret answer.
        let mut line = Zeroizing::new(serde_json::to_vec(request)?);
        line.push(b'\n');
        self.write.write_all(&line).await?;
        Ok(())
    }

    pub async fn next(&mut self) -> anyhow::Result<Event> {
        let line = self.lines.next_line().await?.with_context(|| format!("{} closed the connection", brand::DAEMON))?;
        Ok(serde_json::from_str(&line)?)
    }

    /// Sends `request` and waits for `Done`.
    async fn until_done(mut self, request: Request) -> anyhow::Result<()> {
        self.send(&request).await?;
        loop {
            match self.next().await? {
                Event::Done => return Ok(()),
                Event::Error { message, failure } => return Err(error(message, failure)),
                _ => {}
            }
        }
    }

    pub async fn status(mut self) -> anyhow::Result<Vec<SessionInfo>> {
        self.send(&Request::Status).await?;
        loop {
            match self.next().await? {
                Event::Status { sessions } => return Ok(sessions),
                Event::Error { message, failure } => return Err(error(message, failure)),
                _ => {}
            }
        }
    }

    /// `id`: the session's profile id.
    pub async fn disconnect(self, id: &str) -> anyhow::Result<()> {
        self.until_done(Request::Disconnect { id: id.to_owned() }).await
    }

    /// Closes every session and stops the daemon (its service manager
    /// starts it again).
    pub async fn shutdown(self) -> anyhow::Result<()> {
        self.until_done(Request::Shutdown).await
    }

    /// Subscribes to the state changes of the user's sessions; read them
    /// with [`Daemon::next`], starting with a `Status`.
    pub async fn watch(mut self) -> anyhow::Result<Self> {
        self.send(&Request::Watch).await?;
        Ok(self)
    }
}

/// An `Error` event as an error that keeps its kind.
pub(crate) fn error(message: String, failure: Option<vpn_core::FailureKind>) -> anyhow::Error {
    let message = printable(&message);
    match failure {
        Some(kind) => vpn_core::failure(kind, message),
        None => anyhow::anyhow!(message),
    }
}
