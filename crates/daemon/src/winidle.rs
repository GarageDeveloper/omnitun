//! The user's idle time on Windows. The service runs in session 0, which
//! sees no keyboard or mouse: in each signed-in session (active, console
//! or remote), `omnitund --idle-secs` runs as its user, reads the session's
//! last input and answers in its exit code. The least idle session counts,
//! as on macOS, where the idle time is the computer's.

use std::ptr::{null, null_mut};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSActive, WTSEnumerateSessionsW, WTSFreeMemory, WTSQueryUserToken,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, GetExitCodeProcess, PROCESS_INFORMATION,
    STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};

/// The helper's answer when it cannot read the last input.
const UNKNOWN: u32 = u32::MAX;
/// How long a helper may take.
const HELPER_TIMEOUT: Duration = Duration::from_secs(5);
/// Sessions with an idle limit ask every tick: one reading serves them.
const FRESH: Duration = Duration::from_secs(5);

/// `omnitund --idle-secs`: this session's seconds since its last input,
/// as the exit code.
pub fn helper() -> u32 {
    use windows_sys::Win32::System::SystemInformation::GetTickCount;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
    let mut info = LASTINPUTINFO { cbSize: size_of::<LASTINPUTINFO>() as u32, dwTime: 0 };
    // SAFETY: `info` is a LASTINPUTINFO with its size set.
    if unsafe { GetLastInputInfo(&mut info) } == 0 {
        return UNKNOWN;
    }
    // SAFETY: no arguments. Both are milliseconds since boot, wrapping.
    let now = unsafe { GetTickCount() };
    now.wrapping_sub(info.dwTime) / 1000
}

static LAST: Mutex<Option<(Instant, Option<u64>)>> = Mutex::new(None);

/// Seconds since the last input in the least idle signed-in session;
/// `None` with nobody signed in, or where it cannot be read.
pub async fn user_idle_secs() -> Option<u64> {
    if let Some((at, idle)) = *LAST.lock().unwrap()
        && at.elapsed() < FRESH
    {
        return idle;
    }
    let idle = tokio::task::spawn_blocking(read).await.ok().flatten();
    *LAST.lock().unwrap() = Some((Instant::now(), idle));
    idle
}

fn read() -> Option<u64> {
    let exe = std::env::current_exe().ok()?;
    active_sessions().into_iter().filter_map(|session| ask(session, &exe)).min()
}

fn active_sessions() -> Vec<u32> {
    let mut list: *mut WTS_SESSION_INFOW = null_mut();
    let mut count = 0u32;
    // SAFETY: out pointers to locals; the list is freed below.
    if unsafe { WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut list, &mut count) } == 0 {
        return Vec::new();
    }
    // SAFETY: WTSEnumerateSessionsW gave `count` entries at `list`.
    let sessions = unsafe { std::slice::from_raw_parts(list, count as usize) };
    let active = sessions.iter().filter(|s| s.State == WTSActive && s.SessionId != 0).map(|s| s.SessionId).collect();
    // SAFETY: allocated by WTSEnumerateSessionsW.
    unsafe { WTSFreeMemory(list.cast()) };
    active
}

/// Runs the helper in `session` as its user; its answer.
fn ask(session: u32, exe: &std::path::Path) -> Option<u64> {
    let mut token: HANDLE = null_mut();
    // SAFETY: out pointer to a local; the service runs as LocalSystem,
    // which may read a session's token. Closed below.
    if unsafe { WTSQueryUserToken(session, &mut token) } == 0 {
        return None;
    }
    let answer = run(token, exe);
    // SAFETY: the token is ours.
    unsafe { CloseHandle(token) };
    answer
}

fn run(token: HANDLE, exe: &std::path::Path) -> Option<u64> {
    let wide = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let mut command = wide(&format!("\"{}\" --idle-secs", exe.display()));
    let mut desktop = wide("winsta0\\default");
    let mut environment = null_mut();
    // SAFETY: out pointer to a local; destroyed below.
    let have_environment = unsafe { CreateEnvironmentBlock(&mut environment, token, 0) } != 0;
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = size_of::<STARTUPINFOW>() as u32;
    startup.lpDesktop = desktop.as_mut_ptr();
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: NUL-terminated buffers that outlive the call, a primary token
    // from WTSQueryUserToken; no handle is inherited.
    let started = unsafe {
        CreateProcessAsUserW(
            token,
            null(),
            command.as_mut_ptr(),
            null(),
            null(),
            0,
            CREATE_NO_WINDOW | if have_environment { CREATE_UNICODE_ENVIRONMENT } else { 0 },
            if have_environment { environment } else { null() },
            null(),
            &startup,
            &mut process,
        )
    } != 0;
    if have_environment {
        // SAFETY: from CreateEnvironmentBlock.
        unsafe { DestroyEnvironmentBlock(environment) };
    }
    if !started {
        return None;
    }
    let mut code = UNKNOWN;
    // SAFETY: the process's handles are ours, closed below.
    unsafe {
        if WaitForSingleObject(process.hProcess, HELPER_TIMEOUT.as_millis() as u32) == WAIT_OBJECT_0 {
            GetExitCodeProcess(process.hProcess, &mut code);
        } else {
            TerminateProcess(process.hProcess, UNKNOWN);
        }
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    (code != UNKNOWN).then_some(u64::from(code))
}
