//! Engines on Windows: run as LocalService (the service logs it on), the
//! account that owns nothing of the users' or the system's, as `_omnitun`
//! does on Unix; then restricted further. Every group but the everyday
//! ones (Everyone, Users, Authenticated Users) only denies access, every
//! privilege but change-notify is gone, the integrity level is low
//! (nothing at medium or above may be written), and a job object forbids
//! child processes, takes the desktop away and kills the engine with the
//! service. The engine inherits exactly the handles given, no other.
//!
//! The user itself cannot only deny: a process whose own account may not
//! open its objects does not get past its initialization. Not as SYSTEM
//! (the tests), the account stays the current user's.

use std::ffi::c_void;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::Arc;

use windows_sys::Win32::Foundation::{
    DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, HANDLE_FLAG_INHERIT, LocalFree, SetHandleInformation,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, EqualSid, GetTokenInformation, IsWellKnownSid, LOGON32_LOGON_SERVICE,
    LOGON32_PROVIDER_DEFAULT, LogonUserW, PSID, SID_AND_ATTRIBUTES, SetTokenInformation, TOKEN_ADJUST_DEFAULT,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_GROUPS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER, TokenGroups,
    TokenIntegrityLevel, TokenUser, WinLocalSystemSid,
};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
    JOB_OBJECT_UILIMIT_EXITWINDOWS, JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES,
    JOB_OBJECT_UILIMIT_READCLIPBOARD, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS, JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicUIRestrictions,
    JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows_sys::Win32::System::SystemServices::SE_GROUP_INTEGRITY;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList,
    OpenProcessToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
};

/// Groups left as they are: what any user has, needed to load the system's
/// libraries and use the network.
const KEPT_GROUPS: [&str; 3] = ["S-1-1-0", "S-1-5-32-545", "S-1-5-11"];
const LOW_INTEGRITY: &str = "S-1-16-4096";

/// A restricted process; dropping it kills it (its job closes).
pub struct Child {
    process: Arc<OwnedHandle>,
    _job: OwnedHandle,
}

impl Child {
    /// Starts `path` with `args`, restricted: it inherits `inherit` (which
    /// must not be inheritable already) and writes its errors to `stderr`.
    pub fn spawn(path: &Path, args: &[String], inherit: &[RawHandle], stderr: RawHandle) -> io::Result<Self> {
        let token = restricted_token()?;
        let job = job()?;
        let mut handles: Vec<HANDLE> = inherit.iter().map(|h| *h as HANDLE).collect();
        handles.push(stderr as HANDLE);
        for handle in &handles {
            // SAFETY: handles the caller owns.
            check(unsafe { SetHandleInformation(*handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) })?;
        }
        let spawned = create(&token, &job, path, args, &handles, stderr as HANDLE);
        for handle in &handles {
            // SAFETY: as above.
            unsafe { SetHandleInformation(*handle, HANDLE_FLAG_INHERIT, 0) };
        }
        Ok(Self { process: Arc::new(spawned?), _job: job })
    }

    /// Gives the process a copy of `handle`, whose value it returns (for
    /// the process to be told).
    pub fn give(&self, handle: RawHandle) -> io::Result<usize> {
        let mut theirs: HANDLE = null_mut();
        // SAFETY: valid handles; the copy belongs to the child.
        check(unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                handle as HANDLE,
                self.process.as_raw_handle() as HANDLE,
                &mut theirs,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        })?;
        Ok(theirs as usize)
    }

    pub fn kill(&self) {
        // SAFETY: a process handle with every right.
        unsafe { TerminateProcess(self.process.as_raw_handle() as HANDLE, 1) };
    }

    /// Waits for the process to end; returns its exit code.
    pub async fn wait(&self) -> io::Result<u32> {
        let process = self.process.clone();
        tokio::task::spawn_blocking(move || {
            let handle = process.as_raw_handle() as HANDLE;
            let mut code = 0;
            // SAFETY: a process handle kept alive by `process`.
            unsafe {
                WaitForSingleObject(handle, INFINITE);
                check(GetExitCodeProcess(handle, &mut code))?;
            }
            Ok(code)
        })
        .await?
    }
}

fn create(
    token: &OwnedHandle,
    job: &OwnedHandle,
    path: &Path,
    args: &[String],
    handles: &[HANDLE],
    stderr: HANDLE,
) -> io::Result<OwnedHandle> {
    let attributes = Attributes::new(2)?;
    let job_handle = job.as_raw_handle() as HANDLE;
    // SAFETY: the values outlive the list, which is deleted on drop.
    unsafe {
        check(UpdateProcThreadAttribute(
            attributes.0.as_ptr() as *mut c_void,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            handles.as_ptr().cast(),
            size_of_val(handles),
            null_mut(),
            null(),
        ))?;
        check(UpdateProcThreadAttribute(
            attributes.0.as_ptr() as *mut c_void,
            0,
            PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
            (&raw const job_handle).cast(),
            size_of::<HANDLE>(),
            null_mut(),
            null(),
        ))?;
    }
    let mut info: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    info.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    info.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    // Engines write nothing to their output; other programs, to the log.
    info.StartupInfo.hStdOutput = stderr;
    info.StartupInfo.hStdError = stderr;
    info.lpAttributeList = attributes.0.as_ptr() as *mut c_void;

    let application = wide(&path.display().to_string());
    let mut command_line = wide(&command_line(path, args));
    let mut environment = environment();
    let mut process = PROCESS_INFORMATION::default();
    // SAFETY: every pointer is valid for the call; the command line is
    // writable, as the function requires.
    check(unsafe {
        CreateProcessAsUserW(
            token.as_raw_handle() as HANDLE,
            application.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            environment.as_mut_ptr().cast(),
            null(),
            &info.StartupInfo,
            &mut process,
        )
    })?;
    // SAFETY: handles returned by the call, now ours.
    unsafe {
        drop(OwnedHandle::from_raw_handle(process.hThread as RawHandle));
        Ok(OwnedHandle::from_raw_handle(process.hProcess as RawHandle))
    }
}

/// LocalService's token (this process's when not SYSTEM), restricted as
/// the module says.
fn restricted_token() -> io::Result<OwnedHandle> {
    let token = account_token()?;
    let raw = token.as_raw_handle() as HANDLE;

    let kept: Vec<Sid> = KEPT_GROUPS.iter().map(|s| Sid::parse(s)).collect::<io::Result<_>>()?;
    let groups = information(raw, TokenGroups)?;
    // SAFETY: a buffer filled by GetTokenInformation for this class.
    let groups = unsafe {
        let groups = &*groups.as_ptr().cast::<TOKEN_GROUPS>();
        std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize)
    };
    let mut disabled = Vec::new();
    for group in groups {
        let integrity = group.Attributes & SE_GROUP_INTEGRITY as u32 != 0;
        // SAFETY: valid SIDs.
        let everyday = kept.iter().any(|k| unsafe { EqualSid(k.0, group.Sid) } != 0);
        if !integrity && !everyday {
            disabled.push(SID_AND_ATTRIBUTES { Sid: group.Sid, Attributes: 0 });
        }
    }
    let mut restricted: HANDLE = null_mut();
    // SAFETY: the SIDs point into buffers alive for the call.
    check(unsafe {
        CreateRestrictedToken(
            raw,
            DISABLE_MAX_PRIVILEGE,
            disabled.len() as u32,
            disabled.as_ptr(),
            0,
            null(),
            0,
            null(),
            &mut restricted,
        )
    })?;
    // SAFETY: a handle just created.
    let restricted = unsafe { OwnedHandle::from_raw_handle(restricted as RawHandle) };
    let raw = restricted.as_raw_handle() as HANDLE;

    let low = Sid::parse(LOW_INTEGRITY)?;
    let label =
        TOKEN_MANDATORY_LABEL { Label: SID_AND_ATTRIBUTES { Sid: low.0, Attributes: SE_GROUP_INTEGRITY as u32 } };
    // SAFETY: a label whose SID outlives the call.
    check(unsafe {
        SetTokenInformation(
            raw,
            TokenIntegrityLevel,
            (&raw const label).cast(),
            (size_of::<TOKEN_MANDATORY_LABEL>() + sid_length(low.0)) as u32,
        )
    })?;
    Ok(restricted)
}

/// LocalService's, logged on by SYSTEM; this process's own otherwise.
fn account_token() -> io::Result<OwnedHandle> {
    let mut token: HANDLE = null_mut();
    // SAFETY: plain query of this process's token.
    check(unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
            &mut token,
        )
    })?;
    // SAFETY: a handle just opened.
    let own = unsafe { OwnedHandle::from_raw_handle(token as RawHandle) };
    let user = information(own.as_raw_handle() as HANDLE, TokenUser)?;
    // SAFETY: a TOKEN_USER buffer.
    let system = unsafe { IsWellKnownSid((*user.as_ptr().cast::<TOKEN_USER>()).User.Sid, WinLocalSystemSid) } != 0;
    if !system {
        return Ok(own);
    }
    let mut service: HANDLE = null_mut();
    // SAFETY: NUL-terminated strings; no password for this account.
    check(unsafe {
        LogonUserW(
            wide("LocalService").as_ptr(),
            wide("NT AUTHORITY").as_ptr(),
            null(),
            LOGON32_LOGON_SERVICE,
            LOGON32_PROVIDER_DEFAULT,
            &mut service,
        )
    })?;
    // SAFETY: a handle just returned.
    Ok(unsafe { OwnedHandle::from_raw_handle(service as RawHandle) })
}

/// No child processes, no desktop, killed with the service.
fn job() -> io::Result<OwnedHandle> {
    // SAFETY: an anonymous job with the default security.
    let job = unsafe { CreateJobObjectW(null(), null()) };
    if job.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a handle just created.
    let owned = unsafe { OwnedHandle::from_raw_handle(job as RawHandle) };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: JOB_OBJECT_UILIMIT_DESKTOP
            | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
            | JOB_OBJECT_UILIMIT_EXITWINDOWS
            | JOB_OBJECT_UILIMIT_GLOBALATOMS
            | JOB_OBJECT_UILIMIT_HANDLES
            | JOB_OBJECT_UILIMIT_READCLIPBOARD
            | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
            | JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
    };
    // SAFETY: structures of the sizes given.
    unsafe {
        check(SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            size_of_val(&limits) as u32,
        ))?;
        check(SetInformationJobObject(
            job,
            JobObjectBasicUIRestrictions,
            (&raw const ui).cast(),
            size_of_val(&ui) as u32,
        ))?;
    }
    Ok(owned)
}

/// The environment of an engine: the system's directory (Winsock needs
/// it) and the log filter.
fn environment() -> Vec<u16> {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let log = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into());
    let mut block = Vec::new();
    for variable in [format!("SystemRoot={root}"), format!("RUST_LOG={log}")] {
        block.extend(variable.encode_utf16());
        block.push(0);
    }
    block.push(0);
    block
}

/// Every argument quoted: they hold no quotes (paths, numbers, SIDs).
fn command_line(path: &Path, args: &[String]) -> String {
    std::iter::once(path.display().to_string())
        .chain(args.iter().cloned())
        .map(|a| format!("\"{a}\""))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A token information buffer, aligned for its structure.
fn information(token: HANDLE, class: i32) -> io::Result<Vec<u64>> {
    let mut len = 0u32;
    // SAFETY: a size query.
    unsafe { GetTokenInformation(token, class, null_mut(), 0, &mut len) };
    let mut buffer = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: the buffer holds `len` bytes.
    check(unsafe { GetTokenInformation(token, class, buffer.as_mut_ptr().cast(), len, &mut len) })?;
    Ok(buffer)
}

fn sid_length(sid: PSID) -> usize {
    // SAFETY: a valid SID.
    unsafe { windows_sys::Win32::Security::GetLengthSid(sid) as usize }
}

/// A SID allocated by the system.
struct Sid(PSID);

impl Sid {
    fn parse(text: &str) -> io::Result<Self> {
        let mut sid = null_mut();
        // SAFETY: a NUL-terminated string; freed on drop.
        check(unsafe { ConvertStringSidToSidW(wide(text).as_ptr(), &mut sid) })?;
        Ok(Self(sid))
    }
}

impl Drop for Sid {
    fn drop(&mut self) {
        // SAFETY: allocated by the system.
        unsafe { LocalFree(self.0) };
    }
}

/// A process attribute list.
struct Attributes(Vec<u64>);

impl Attributes {
    fn new(count: u32) -> io::Result<Self> {
        let mut size = 0;
        // SAFETY: a size query.
        unsafe { InitializeProcThreadAttributeList(null_mut(), count, 0, &mut size) };
        let mut buffer = vec![0u64; size.div_ceil(8)];
        // SAFETY: a buffer of the size asked.
        check(unsafe { InitializeProcThreadAttributeList(buffer.as_mut_ptr().cast(), count, 0, &mut size) })?;
        Ok(Self(buffer))
    }
}

impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: initialized in `new`.
        unsafe { DeleteProcThreadAttributeList(self.0.as_mut_ptr().cast()) };
    }
}

fn check(ok: i32) -> io::Result<()> {
    if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    /// The token as the child sees it, and its exit code.
    fn run(program: &str, args: &[&str]) -> (String, u32) {
        let (mut read, write) = std::io::pipe().unwrap();
        let write = OwnedHandle::from(write);
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        let child = Child::spawn(Path::new(program), &args, &[], write.as_raw_handle()).unwrap();
        drop(write);
        let mut out = String::new();
        let mut bytes = Vec::new();
        read.read_to_end(&mut bytes).unwrap();
        out.push_str(&String::from_utf8_lossy(&bytes));
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let code = runtime.block_on(child.wait()).unwrap();
        (out, code)
    }

    /// The engine's own check, restricted (`ENGINE_CHECK=<engine.exe>`).
    #[test]
    fn engine_check() {
        let Some(engine) = std::env::var_os("ENGINE_CHECK") else { return };
        let home = std::env::var("USERPROFILE").unwrap();
        let (out, code) = run(&engine.to_string_lossy(), &["--check", "example.com", &home]);
        println!("exit {code:#x}\n{out}");
    }

    fn system32(program: &str) -> String {
        format!(r"{}\System32\{program}", std::env::var("SystemRoot").unwrap())
    }

    /// The exit code comes back; the output goes where it was sent.
    #[test]
    fn runs_and_reports() {
        let (out, code) = run(&system32("hostname.exe"), &[]);
        assert_eq!(code, 0);
        assert!(!out.trim().is_empty());
        let (_, code) = run(&system32("hostname.exe"), &["--no-such-option"]);
        assert_ne!(code, 0);
    }
}
