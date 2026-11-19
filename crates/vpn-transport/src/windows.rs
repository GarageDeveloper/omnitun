//! A named pipe whose ACL admits SYSTEM, the Administrators and one group.
//! The server learns the client's account from its token (impersonation at
//! identification level, which is all a client grants). The client checks
//! that the pipe belongs to SYSTEM, the Administrators or itself: a user
//! who created the pipe first cannot pose as the service. Clients get no
//! right to create instances of the pipe, so they cannot add one either.

use std::ffi::c_void;
use std::io;
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use anyhow::Context;
use tokio::net::windows::named_pipe::{NamedPipeClient, NamedPipeServer, ServerOptions};
use vpn_core::{User, UserId};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_PIPE_BUSY, HANDLE, INVALID_HANDLE_VALUE,
    LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, IsWellKnownSid, LookupAccountNameW,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, RevertToSelf, SECURITY_ATTRIBUTES, SECURITY_MAX_SID_SIZE,
    SID_NAME_USE, TOKEN_QUERY, TOKEN_USER, TokenUser, WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid,
    WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_OVERLAPPED, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_DATA, OPEN_EXISTING,
    READ_CONTROL, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, SYNCHRONIZE,
};
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken};

use crate::Stream;

/// What a client may do with the pipe: read, write, read its owner.
/// Not `FILE_GENERIC_WRITE`, whose `FILE_APPEND_DATA` is, on a pipe, the
/// right to create an instance.
pub(crate) const CLIENT_RIGHTS: u32 =
    FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;

/// How long a client waits while every instance is busy.
const BUSY_WAIT: Duration = Duration::from_secs(5);

pub struct Listener {
    name: String,
    descriptor: Descriptor,
    /// The instance waiting for the next client.
    next: NamedPipeServer,
}

impl Listener {
    /// Listens on the pipe `name`, for SYSTEM, the Administrators and
    /// `group` (a name, or a SID such as `S-1-5-32-545`).
    pub fn bind(name: &str, group: &str) -> anyhow::Result<Self> {
        let group = if group.starts_with("S-1-") {
            group.to_owned()
        } else {
            account_sid(group).with_context(|| format!("group {group} does not exist (use --group)"))?
        };
        // OW: the pipe's owner, its creator (SYSTEM for the service), may
        // add instances.
        let descriptor =
            Descriptor::from_sddl(&format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;{CLIENT_RIGHTS:#x};;;{group})"))
                .with_context(|| format!("invalid group {group}"))?;
        let next = create(name, &descriptor, true).map_err(|e| {
            if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) {
                anyhow::anyhow!("another {} is already listening on {name}", vpn_core::brand::DAEMON)
            } else {
                anyhow::Error::from(e).context(format!("cannot create {name}"))
            }
        })?;
        Ok(Self { name: name.to_owned(), descriptor, next })
    }

    /// The next connection, and its user.
    pub async fn accept(&mut self) -> io::Result<(Stream, User)> {
        self.next.connect().await?;
        // The next instance exists before this one is handed over, so a
        // client never finds the pipe missing.
        let fresh = match create(&self.name, &self.descriptor, false) {
            Ok(fresh) => fresh,
            Err(e) => {
                let _ = self.next.disconnect();
                return Err(e);
            }
        };
        let pipe = std::mem::replace(&mut self.next, fresh);
        let user = client_user(&pipe)?;
        Ok((Stream::split(pipe), user))
    }
}

fn create(name: &str, descriptor: &Descriptor, first: bool) -> io::Result<NamedPipeServer> {
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: the attributes and the descriptor they point to outlive the
    // call, which copies them.
    unsafe {
        ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(name, (&raw mut attributes).cast::<c_void>())
    }
}

/// The account of the client on the other end of `pipe`.
fn client_user(pipe: &NamedPipeServer) -> io::Result<User> {
    pipe_client_user(pipe.as_raw_handle() as HANDLE)
}

/// The account of the client on the other end of the pipe `handle`.
pub(crate) fn pipe_client_user(handle: HANDLE) -> io::Result<User> {
    // SAFETY: the thread takes the client's identity only between these
    // calls, and gets its own back before anything else runs on it.
    let token = unsafe {
        if ImpersonateNamedPipeClient(handle) == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut token: HANDLE = null_mut();
        let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token);
        let error = io::Error::last_os_error();
        if RevertToSelf() == 0 {
            // Going on would serve every later request as this client.
            std::process::abort();
        }
        if opened == 0 {
            return Err(error);
        }
        Token(token)
    };
    let sid = token.user_sid()?;
    // An impersonation token: membership as the client has it, so an
    // administrator without elevation is not one.
    let admin = sid.is_well_known(WinLocalSystemSid) || token.is_member(well_known(WinBuiltinAdministratorsSid)?)?;
    Ok(User { id: UserId::Sid(sid.to_string()?), admin })
}

/// The user this process runs as; an administrator only when elevated.
pub fn current_user() -> io::Result<User> {
    let mut token: HANDLE = null_mut();
    // SAFETY: plain handle query on this process.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = Token(token);
    let sid = token.user_sid()?;
    let admin =
        sid.is_well_known(WinLocalSystemSid) || Token::current_is_member(well_known(WinBuiltinAdministratorsSid)?)?;
    Ok(User { id: UserId::Sid(sid.to_string()?), admin })
}

/// Connects to the pipe `name` once it belongs to the service (or to this
/// user), waiting a little while every instance is busy.
pub async fn connect(name: &str) -> io::Result<Stream> {
    let wide = wide(name);
    let deadline = Instant::now() + BUSY_WAIT;
    let handle = loop {
        // SAFETY: `wide` is a NUL-terminated string that outlives the call.
        // Identification level: the service may read the token, not act
        // as this user.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                CLIENT_RIGHTS,
                0,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            break handle;
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_PIPE_BUSY as i32) || Instant::now() > deadline {
            return Err(error);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    // SAFETY: an overlapped pipe handle this function owns; the client
    // closes it from now on.
    let client = unsafe { NamedPipeClient::from_raw_handle(handle as RawHandle) }.inspect_err(|_| {
        // SAFETY: still ours, as the client was not made.
        unsafe { CloseHandle(handle) };
    })?;
    check_owner(handle, name)?;
    Ok(Stream::split(client))
}

/// The pipe was created by SYSTEM, an administrator or this user.
fn check_owner(handle: HANDLE, name: &str) -> io::Result<()> {
    let mut owner: PSID = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: `owner` points into `descriptor`, freed below.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let descriptor = Descriptor(descriptor);
    let owner = SidRef(owner);
    let trusted = owner.is_well_known(WinLocalSystemSid)
        || owner.is_well_known(WinBuiltinAdministratorsSid)
        || owner.to_string()? == current_user()?.id.to_string();
    drop(descriptor);
    if trusted {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{name} does not belong to the service")))
    }
}

/// The SID of an account or group, in string form.
pub(crate) fn account_sid(name: &str) -> io::Result<String> {
    let wide = wide(name);
    let (mut sid_len, mut domain_len, mut kind) = (0u32, 0u32, SID_NAME_USE::default());
    // SAFETY: a size query, with no buffers.
    unsafe {
        LookupAccountNameW(null(), wide.as_ptr(), null_mut(), &mut sid_len, null_mut(), &mut domain_len, &mut kind)
    };
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(error);
    }
    let mut sid = vec![0u64; (sid_len as usize).div_ceil(8)];
    let mut domain = vec![0u16; domain_len as usize];
    // SAFETY: both buffers have the sizes just returned.
    let found = unsafe {
        LookupAccountNameW(
            null(),
            wide.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    };
    if found == 0 {
        return Err(io::Error::last_os_error());
    }
    SidRef(sid.as_mut_ptr().cast()).to_string()
}

/// A well-known SID, in a buffer aligned for it.
fn well_known(kind: WELL_KNOWN_SID_TYPE) -> io::Result<Vec<u64>> {
    let mut size = SECURITY_MAX_SID_SIZE;
    let mut sid = vec![0u64; (SECURITY_MAX_SID_SIZE as usize).div_ceil(8)];
    // SAFETY: the buffer holds `size` bytes.
    if unsafe { CreateWellKnownSid(kind, null_mut(), sid.as_mut_ptr().cast(), &mut size) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sid)
}

/// A SID owned by someone else (a token, a security descriptor).
struct SidRef(PSID);

impl SidRef {
    fn is_well_known(&self, kind: WELL_KNOWN_SID_TYPE) -> bool {
        // SAFETY: a valid SID.
        unsafe { IsWellKnownSid(self.0, kind) != 0 }
    }

    fn to_string(&self) -> io::Result<String> {
        let mut text = null_mut();
        // SAFETY: a valid SID; the string is freed below.
        if unsafe { ConvertSidToStringSidW(self.0, &mut text) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: NUL-terminated, from the call above.
        let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
        let string = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
        unsafe { LocalFree(text.cast()) };
        Ok(string)
    }
}

struct Token(HANDLE);

impl Token {
    /// The token's user; the SID lives in the returned buffer.
    fn user_sid(&self) -> io::Result<OwnedSid> {
        let mut len = 0u32;
        // SAFETY: a size query.
        unsafe { GetTokenInformation(self.0, TokenUser, null_mut(), 0, &mut len) };
        let mut buffer = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: the buffer holds `len` bytes, aligned for TOKEN_USER.
        if unsafe { GetTokenInformation(self.0, TokenUser, buffer.as_mut_ptr().cast(), len, &mut len) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(OwnedSid(buffer))
    }

    fn is_member(&self, mut group: Vec<u64>) -> io::Result<bool> {
        let mut member = 0;
        // SAFETY: an impersonation token and a valid SID.
        if unsafe { CheckTokenMembership(self.0, group.as_mut_ptr().cast(), &mut member) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(member != 0)
    }

    /// Membership as this process has it (its primary token).
    fn current_is_member(mut group: Vec<u64>) -> io::Result<bool> {
        let mut member = 0;
        // SAFETY: a null token means this thread's or process's.
        if unsafe { CheckTokenMembership(null_mut(), group.as_mut_ptr().cast(), &mut member) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(member != 0)
    }
}

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: a token handle this value owns.
        unsafe { CloseHandle(self.0) };
    }
}

/// A `TOKEN_USER` buffer.
struct OwnedSid(Vec<u64>);

impl OwnedSid {
    fn sid(&self) -> SidRef {
        // SAFETY: the buffer holds a TOKEN_USER, whose SID points into it.
        SidRef(unsafe { (*self.0.as_ptr().cast::<TOKEN_USER>()).User.Sid })
    }

    fn is_well_known(&self, kind: WELL_KNOWN_SID_TYPE) -> bool {
        self.sid().is_well_known(kind)
    }

    fn to_string(&self) -> io::Result<String> {
        self.sid().to_string()
    }
}

/// A security descriptor allocated by the system.
pub(crate) struct Descriptor(pub(crate) PSECURITY_DESCRIPTOR);

// SAFETY: an immutable block of memory once made.
unsafe impl Send for Descriptor {}
unsafe impl Sync for Descriptor {}

impl Descriptor {
    pub(crate) fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide = wide(sddl);
        let mut descriptor = null_mut();
        // SAFETY: `wide` is NUL-terminated; the descriptor is freed on drop.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by the system with LocalAlloc.
        unsafe { LocalFree(self.0) };
    }
}

pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
