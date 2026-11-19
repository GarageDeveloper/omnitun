//! Local channels between the service and its clients: Unix sockets on
//! macOS and Linux, named pipes on Windows. Only administrators and one
//! group may connect, and the listener learns which user did.

use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(windows)]
mod handoff;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub use handoff::{HandoffListener, pipe_pair};
#[cfg(unix)]
pub use unix::{Listener, connect, current_user};
#[cfg(windows)]
pub use windows::{Listener, connect, current_user};

pub type ReadHalf = Box<dyn AsyncRead + Send + Unpin>;
pub type WriteHalf = Box<dyn AsyncWrite + Send + Unpin>;

/// Both directions of a connection.
pub struct Stream {
    pub read: ReadHalf,
    pub write: WriteHalf,
}

impl Stream {
    fn split<S: AsyncRead + AsyncWrite + Send + 'static>(stream: S) -> Self {
        let (read, write) = tokio::io::split(stream);
        Self { read: Box::new(read), write: Box::new(write) }
    }

    /// Both ends of an in-memory connection (tests).
    pub fn pair() -> (Self, Self) {
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        (Self::split(ours), Self::split(theirs))
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    use super::*;

    /// A path or pipe name of its own for each test.
    pub(crate) fn address(test: &str) -> String {
        let name = format!("vpn-transport-{test}-{}", std::process::id());
        if cfg!(windows) {
            format!(r"\\.\pipe\{name}")
        } else {
            std::env::temp_dir().join(format!("{name}.sock")).display().to_string()
        }
    }

    /// A group the user running the tests belongs to.
    fn my_group() -> String {
        #[cfg(unix)]
        return nix::unistd::Group::from_gid(nix::unistd::getgid()).unwrap().unwrap().name;
        // BUILTIN\Users.
        #[cfg(windows)]
        return "S-1-5-32-545".to_owned();
    }

    #[tokio::test]
    async fn the_listener_knows_who_connected() {
        let address = address("who");
        let mut listener = Listener::bind(&address, &my_group()).unwrap();
        // Several clients in a row: the next one gets in after the first.
        for n in 0..3 {
            let client = tokio::spawn({
                let address = address.clone();
                async move {
                    let mut stream = connect(&address).await.unwrap();
                    stream.write.write_all(format!("hello {n}\n").as_bytes()).await.unwrap();
                    let mut line = String::new();
                    BufReader::new(stream.read).read_line(&mut line).await.unwrap();
                    line
                }
            });
            let (stream, user) = listener.accept().await.unwrap();
            assert_eq!(user, current_user().unwrap());
            let mut line = String::new();
            let mut read = BufReader::new(stream.read);
            read.read_line(&mut line).await.unwrap();
            assert_eq!(line, format!("hello {n}\n"));
            let mut write = stream.write;
            write.write_all(b"welcome\n").await.unwrap();
            assert_eq!(client.await.unwrap(), "welcome\n");
        }
    }

    #[tokio::test]
    async fn one_listener_per_address() {
        let address = address("twice");
        let _first = Listener::bind(&address, &my_group()).unwrap();
        let second = Listener::bind(&address, &my_group()).err().expect("a second listener");
        assert!(second.to_string().contains("already listening"), "{second:#}");
    }

    #[tokio::test]
    async fn nobody_listening() {
        assert!(connect(&address("nobody")).await.is_err());
    }
}
