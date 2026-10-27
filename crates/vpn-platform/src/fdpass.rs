//! Passing a descriptor (the tun interface) from the daemon to an engine
//! over a Unix socket (SCM_RIGHTS). Blocking calls, on a socket used only
//! for this.

use std::io::{self, IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};

pub fn send_fd(socket: &impl AsRawFd, fd: RawFd) -> io::Result<()> {
    sendmsg::<()>(
        socket.as_raw_fd(),
        &[IoSlice::new(b"T")],
        &[ControlMessage::ScmRights(&[fd])],
        MsgFlags::empty(),
        None,
    )
    .map_err(io::Error::from)?;
    Ok(())
}

/// Waits for one descriptor; fails if the peer sent anything else.
pub fn recv_fd(socket: &impl AsRawFd) -> io::Result<OwnedFd> {
    let mut byte = [0u8; 1];
    let mut space = nix::cmsg_space!([RawFd; 1]);
    let mut iov = [IoSliceMut::new(&mut byte)];
    let msg =
        recvmsg::<()>(socket.as_raw_fd(), &mut iov, Some(&mut space), MsgFlags::empty()).map_err(io::Error::from)?;
    let mut received = Vec::new();
    for cmsg in msg.cmsgs().map_err(io::Error::from)? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            received.extend(fds);
        }
    }
    // SAFETY: descriptors received through SCM_RIGHTS belong to this process.
    let mut owned: Vec<OwnedFd> = received.into_iter().map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }).collect();
    // Not inherited by anything this process starts (no MSG_CMSG_CLOEXEC on macOS).
    for fd in &owned {
        nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC))
            .map_err(io::Error::from)?;
    }
    match (msg.bytes, owned.len()) {
        (0, _) => Err(io::Error::new(io::ErrorKind::UnexpectedEof, "descriptor socket closed")),
        (_, 1) => Ok(owned.remove(0)),
        (_, n) => Err(io::Error::other(format!("expected one descriptor, got {n}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    #[test]
    fn a_descriptor_crosses_the_socket() {
        let (a, b) = UnixStream::pair().unwrap();
        let (mut ours, theirs) = UnixStream::pair().unwrap();
        send_fd(&a, theirs.as_raw_fd()).unwrap();
        drop(theirs);
        let received = recv_fd(&b).unwrap();
        let mut received = UnixStream::from(received);
        received.write_all(b"hello").unwrap();
        let mut buf = [0u8; 5];
        ours.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"hello");
        drop(a);
        assert!(recv_fd(&b).is_err(), "closed socket");
    }
}
