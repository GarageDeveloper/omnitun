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
    ) || e.raw_os_error().is_some_and(|code| TRANSIENT_CODES.contains(&code))
}

#[cfg(unix)]
const TRANSIENT_CODES: &[i32] = &[libc::EHOSTDOWN, libc::ENOBUFS, libc::EAGAIN];

/// Winsock codes: WSAEHOSTDOWN, WSAENOBUFS, WSAEWOULDBLOCK, and
/// WSAENETRESET, which a UDP socket gets after an ICMP time exceeded.
#[cfg(windows)]
const TRANSIENT_CODES: &[i32] = &[10064, 10055, 10035, 10052];

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn network_errors_are_transient() {
        for errno in [libc::ECONNREFUSED, libc::EHOSTDOWN, libc::ENOBUFS, libc::EAGAIN, libc::ENETDOWN] {
            assert!(transient(&Error::from_raw_os_error(errno)), "{errno}");
        }
        for errno in [libc::EBADF, libc::EINVAL, libc::EMSGSIZE] {
            assert!(!transient(&Error::from_raw_os_error(errno)), "{errno}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn network_errors_are_transient() {
        // WSAECONNREFUSED, WSAEHOSTDOWN, WSAENOBUFS, WSAEWOULDBLOCK,
        // WSAENETDOWN, WSAECONNRESET, WSAENETRESET.
        for code in [10061, 10064, 10055, 10035, 10050, 10054, 10052] {
            assert!(transient(&Error::from_raw_os_error(code)), "{code}");
        }
        // WSAEBADF, WSAEINVAL, WSAEMSGSIZE.
        for code in [10009, 10022, 10040] {
            assert!(!transient(&Error::from_raw_os_error(code)), "{code}");
        }
    }
}
