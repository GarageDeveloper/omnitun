//! The byte stream to the daemon and to a session's prompt socket. Unix
//! sockets on macOS and Linux; Windows has no transport yet.

use std::io;

use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) type ReadHalf = Box<dyn AsyncRead + Send + Unpin>;
pub(crate) type WriteHalf = Box<dyn AsyncWrite + Send + Unpin>;

/// Connects to the socket at `path`.
#[cfg(unix)]
pub(crate) async fn connect(path: &str) -> io::Result<(ReadHalf, WriteHalf)> {
    let (read, write) = tokio::net::UnixStream::connect(path).await?.into_split();
    Ok((Box::new(read), Box::new(write)))
}

#[cfg(windows)]
pub(crate) async fn connect(_path: &str) -> io::Result<(ReadHalf, WriteHalf)> {
    Err(io::Error::new(io::ErrorKind::Unsupported, "the service connection is not supported on Windows yet"))
}

/// Both ends of an in-memory stream (tests).
#[cfg(test)]
pub(crate) fn pair() -> ((ReadHalf, WriteHalf), (ReadHalf, WriteHalf)) {
    let (ours, theirs) = tokio::io::duplex(64 * 1024);
    let (our_read, our_write) = tokio::io::split(ours);
    let (their_read, their_write) = tokio::io::split(theirs);
    ((Box::new(our_read), Box::new(our_write)), (Box::new(their_read), Box::new(their_write)))
}
