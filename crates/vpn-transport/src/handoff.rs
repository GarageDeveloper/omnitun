//! Pipes whose other end, or whose connections, go to a child process
//! (Windows has no descriptor passing): the service's channels to an
//! engine, and a session's prompt pipe, whose clients the engine serves.
//!
//! What goes to the child is never bound to this process's completion
//! port: a handle may be bound to one port only, and the child binds it to
//! its own.

use std::future::Future;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Context;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use vpn_core::User;
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_FLAGS_AND_ATTRIBUTES, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES,
};
use windows_sys::Win32::System::Threading::{CreateEventW, INFINITE, SetEvent, WaitForMultipleObjects};

use crate::windows::{CLIENT_RIGHTS, Descriptor, account_sid, pipe_client_user, wide};

const BUFFER: u32 = 64 * 1024;

/// A private channel to a child: the server end for this process, and the
/// client end, opened already, for the child to inherit. `overlapped`: the
/// child does asynchronous I/O on it (an engine's channels); otherwise
/// plain writes (its standard error).
pub fn pipe_pair(overlapped: bool) -> io::Result<(NamedPipeServer, OwnedHandle)> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let name =
        format!(r"\\.\pipe\{}-{}-{}", vpn_core::brand::ID, std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed));
    // Only this process's account (the creator owns the pipe); the first
    // instance, so a pipe someone made first under this name is an error.
    let descriptor = Descriptor::from_sddl("D:P(A;;FA;;;OW)")?;
    let mut attributes = attributes(&descriptor);
    // SAFETY: the attributes and their descriptor outlive the call.
    let server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .max_instances(1)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(&name, (&raw mut attributes).cast())
    }?;
    let flags = if overlapped { FILE_FLAG_OVERLAPPED } else { 0 };
    // SAFETY: a NUL-terminated name; the handle is owned below.
    let client = unsafe {
        CreateFileW(wide(&name).as_ptr(), GENERIC_READ | GENERIC_WRITE, 0, null(), OPEN_EXISTING, flags, null_mut())
    };
    if client == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a handle just opened.
    let client = unsafe { OwnedHandle::from_raw_handle(client as RawHandle) };
    // The client is there: the server's connection completes at once
    // (ERROR_PIPE_CONNECTED), and tokio reads and writes after it only.
    let ready = {
        let mut connected = std::pin::pin!(server.connect());
        connected.as_mut().poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    };
    match ready {
        std::task::Poll::Ready(result) => result?,
        std::task::Poll::Pending => return Err(io::Error::other("the pipe's client is not connected")),
    }
    Ok((server, client))
}

/// A pipe for one user (and SYSTEM, the Administrators), whose connections
/// are handed to another process.
pub struct HandoffListener {
    name: String,
    descriptor: Arc<Descriptor>,
    /// The instance waiting for the next client.
    next: Option<OwnedHandle>,
    /// Set when the listener goes: a pending wait gives up.
    closed: Arc<OwnedHandle>,
}

impl HandoffListener {
    /// Listens on `name` for `user` (a SID, or an account name).
    pub fn bind(name: &str, user: &str) -> anyhow::Result<Self> {
        let user = if user.starts_with("S-1-") { user.to_owned() } else { account_sid(user)? };
        let descriptor = Arc::new(
            Descriptor::from_sddl(&format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;{CLIENT_RIGHTS:#x};;;{user})"))
                .with_context(|| format!("invalid user {user}"))?,
        );
        let next = instance(name, &descriptor, true).map_err(|e| {
            if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
                anyhow::anyhow!("{name} exists already")
            } else {
                anyhow::Error::from(e).context(format!("cannot create {name}"))
            }
        })?;
        // SAFETY: an unnamed manual-reset event, owned below.
        let closed = unsafe { CreateEventW(null(), 1, 0, null()) };
        if closed.is_null() {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: a handle just created.
        let closed = Arc::new(unsafe { OwnedHandle::from_raw_handle(closed as RawHandle) });
        Ok(Self { name: name.to_owned(), descriptor, next: Some(next), closed })
    }

    /// The next connection, and its user. Not cancellation-safe: dropping
    /// the future loses the waiting instance (a new one is made).
    pub async fn accept(&mut self) -> io::Result<(OwnedHandle, User)> {
        let pipe = match self.next.take() {
            Some(pipe) => pipe,
            None => instance(&self.name, &self.descriptor, false)?,
        };
        let closed = self.closed.clone();
        let pipe = tokio::task::spawn_blocking(move || connect(pipe, &closed)).await??;
        // The next instance exists before this one is handed over, so a
        // client never finds the pipe missing.
        self.next = Some(instance(&self.name, &self.descriptor, false)?);
        let user = pipe_client_user(pipe.as_raw_handle() as HANDLE)?;
        Ok((pipe, user))
    }
}

impl Drop for HandoffListener {
    fn drop(&mut self) {
        // SAFETY: an event handle this value owns.
        unsafe { SetEvent(self.closed.as_raw_handle() as HANDLE) };
    }
}

/// Waits for a client on `pipe`, or for `closed`.
fn connect(pipe: OwnedHandle, closed: &OwnedHandle) -> io::Result<OwnedHandle> {
    let handle = pipe.as_raw_handle() as HANDLE;
    // SAFETY: an unnamed manual-reset event, owned below.
    let event = unsafe { CreateEventW(null(), 1, 0, null()) };
    if event.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a handle just created.
    let event = unsafe { OwnedHandle::from_raw_handle(event as RawHandle) };
    let mut overlapped = OVERLAPPED { hEvent: event.as_raw_handle() as HANDLE, ..Default::default() };
    // SAFETY: `overlapped` stays in place until the operation is over
    // (completed, or cancelled and waited for).
    unsafe {
        if ConnectNamedPipe(handle, &mut overlapped) != 0 {
            return Ok(pipe);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error().map(|e| e as u32) {
            Some(ERROR_PIPE_CONNECTED) => return Ok(pipe),
            Some(ERROR_IO_PENDING) => {}
            _ => return Err(error),
        }
        let events = [event.as_raw_handle() as HANDLE, closed.as_raw_handle() as HANDLE];
        let woken = WaitForMultipleObjects(2, events.as_ptr(), 0, INFINITE);
        if woken != WAIT_OBJECT_0 {
            CancelIoEx(handle, &overlapped);
        }
        let mut transferred = 0;
        if GetOverlappedResult(handle, &overlapped, &mut transferred, 1) == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(pipe)
}

fn instance(name: &str, descriptor: &Descriptor, first: bool) -> io::Result<OwnedHandle> {
    let attributes = attributes(descriptor);
    let first = if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
    // SAFETY: a NUL-terminated name and attributes valid for the call.
    let pipe = unsafe {
        CreateNamedPipeW(
            wide(name).as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | first as FILE_FLAGS_AND_ATTRIBUTES,
            PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER,
            BUFFER,
            0,
            &attributes,
        )
    };
    if pipe == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a handle just created.
    Ok(unsafe { OwnedHandle::from_raw_handle(pipe as RawHandle) })
}

fn attributes(descriptor: &Descriptor) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    }
}

#[cfg(test)]
mod tests {
    use std::os::windows::io::IntoRawHandle;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::windows::named_pipe::NamedPipeClient;

    use super::*;

    #[tokio::test]
    async fn a_pair_carries_both_ways() {
        let (mut server, client) = pipe_pair(true).unwrap();
        // As the child would.
        let mut client = unsafe { NamedPipeClient::from_raw_handle(client.into_raw_handle()) }.unwrap();
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        server.write_all(b"pong").await.unwrap();
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    }

    /// The connection comes out unbound, ready for another process (here,
    /// this one's runtime, as a child's would bind it).
    #[tokio::test]
    async fn connections_are_handed_over() {
        let name = crate::tests::address("handoff");
        let me = crate::current_user().unwrap();
        let mut listener = HandoffListener::bind(&name, &me.id.to_string()).unwrap();
        let client = tokio::spawn({
            let name = name.clone();
            async move {
                let mut stream = crate::connect(&name).await.unwrap();
                stream.write.write_all(b"answer").await.unwrap();
            }
        });
        let (pipe, user) = listener.accept().await.unwrap();
        assert_eq!(user.id, me.id);
        let mut server = unsafe { NamedPipeServer::from_raw_handle(pipe.into_raw_handle()) }.unwrap();
        let mut buf = [0; 6];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"answer");
        client.await.unwrap();
    }

    /// Dropping the listener ends a pending wait.
    #[tokio::test]
    async fn a_pending_accept_ends_with_the_listener() {
        let name = crate::tests::address("handoff-drop");
        let me = crate::current_user().unwrap();
        let mut listener = HandoffListener::bind(&name, &me.id.to_string()).unwrap();
        let waiting = tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept()).await;
        assert!(waiting.is_err());
        drop(listener);
        // The pipe is gone once its instances are.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(crate::connect(&name).await.is_err());
    }
}
