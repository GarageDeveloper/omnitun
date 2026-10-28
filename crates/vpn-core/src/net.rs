//! Socket errors shared by the UDP engines.

use std::io::{Error, ErrorKind};

/// Errors a datagram socket gets from the network rather than from itself:
/// an ICMP unreachable, an interface down while roaming, a full interface
/// queue. Retransmission and dead peer detection decide whether the peer
/// is gone; these only lose a datagram.
pub fn transient(e: &Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::NetworkUnreachable
            | ErrorKind::HostUnreachable
            | ErrorKind::NetworkDown
            | ErrorKind::AddrNotAvailable
    ) || matches!(e.raw_os_error(), Some(libc::EHOSTDOWN | libc::ENOBUFS | libc::EAGAIN))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_errors_are_transient() {
        for errno in [libc::ECONNREFUSED, libc::EHOSTDOWN, libc::ENOBUFS, libc::EAGAIN, libc::ENETDOWN] {
            assert!(transient(&Error::from_raw_os_error(errno)), "{errno}");
        }
        for errno in [libc::EBADF, libc::EINVAL, libc::EMSGSIZE] {
            assert!(!transient(&Error::from_raw_os_error(errno)), "{errno}");
        }
    }
}
