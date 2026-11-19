//! A Unix socket owned by root and one group, mode 0660; the peer's uid
//! comes from the socket (`SO_PEERCRED`, `getpeereid`).

use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::Context;
use tokio::net::{UnixListener, UnixStream};
use vpn_core::User;

use crate::Stream;

pub struct Listener {
    inner: UnixListener,
    path: String,
}

impl Listener {
    /// Listens at `path`, for root and the members of `group`. A socket
    /// left by a process that is gone is replaced.
    pub fn bind(path: &str, group: &str) -> anyhow::Result<Self> {
        if Path::new(path).exists() {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                anyhow::bail!("another {} is already listening on {path}", vpn_core::brand::DAEMON);
            }
            std::fs::remove_file(path)?;
        }
        let gid = nix::unistd::Group::from_name(group)?
            .with_context(|| format!("group {group} does not exist (use --group)"))?
            .gid;
        // Created with no access, then opened to root and the group.
        let old_mask = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o177));
        let listener = UnixListener::bind(path);
        nix::sys::stat::umask(old_mask);
        let inner = listener.with_context(|| format!("cannot bind {path}"))?;
        let listener = Self { inner, path: path.to_owned() };
        // Tests run as a user, who can only give it to one of its groups.
        let owner = nix::unistd::geteuid().is_root().then_some(0);
        std::os::unix::fs::chown(path, owner, Some(gid.as_raw()))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        Ok(listener)
    }

    /// The next connection, and its user.
    pub async fn accept(&mut self) -> io::Result<(Stream, User)> {
        let (stream, _) = self.inner.accept().await?;
        let uid = stream.peer_cred()?.uid();
        Ok((split(stream), User::uid(uid)))
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub async fn connect(path: &str) -> io::Result<Stream> {
    Ok(split(UnixStream::connect(path).await?))
}

/// The user this process runs as.
pub fn current_user() -> io::Result<User> {
    Ok(User::uid(nix::unistd::geteuid().as_raw()))
}

fn split(stream: UnixStream) -> Stream {
    let (read, write) = stream.into_split();
    Stream { read: Box::new(read), write: Box::new(write) }
}
