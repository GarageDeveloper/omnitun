//! What the installer sets up besides files and the service's entry
//! (`omnitund --setup <user>`, `--teardown`): the local group whose members
//! may use the service, the Windows counterpart of the `omnitun` group the
//! Unix packages create; and the service's restart when it fails (the MSI
//! table for it is documented as unreliable).
//!
//! The service does it again at each start (`at_start`): an installer's
//! custom action may fail to start a program at all (STATUS_DLL_INIT_FAILED
//! on some machines), so the installer also leaves the member's name in
//! the registry for the service to add.

use anyhow::bail;
use windows_sys::Win32::Foundation::{ERROR_ALIAS_EXISTS, ERROR_MEMBER_IN_ALIAS, ERROR_NO_SUCH_ALIAS};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    LOCALGROUP_INFO_1, LOCALGROUP_MEMBERS_INFO_3, NERR_GroupExists as NERR_GROUP_EXISTS,
    NERR_GroupNotFound as NERR_GROUP_NOT_FOUND, NetLocalGroupAdd, NetLocalGroupAddMembers, NetLocalGroupDel,
};

/// Creates `group` if needed, and adds `user` (`DOMAIN\name`, or empty).
pub fn setup(group: &str, user: &str) -> anyhow::Result<()> {
    let mut name = wide(group);
    let mut comment = wide(&format!("Users of {}", vpn_core::brand::PRODUCT));
    let info = LOCALGROUP_INFO_1 { lgrpi1_name: name.as_mut_ptr(), lgrpi1_comment: comment.as_mut_ptr() };
    // SAFETY: a structure of strings alive for the call.
    match unsafe { NetLocalGroupAdd(std::ptr::null(), 1, (&raw const info).cast(), std::ptr::null_mut()) } {
        0 => println!("created group {group}"),
        NERR_GROUP_EXISTS | ERROR_ALIAS_EXISTS => {}
        error => bail!("cannot create group {group}: {}", std::io::Error::from_raw_os_error(error as i32)),
    }
    if user.trim().is_empty() || user.trim() == "\\" {
        return Ok(());
    }
    let mut member = wide(user.trim());
    let entry = LOCALGROUP_MEMBERS_INFO_3 { lgrmi3_domainandname: member.as_mut_ptr() };
    // SAFETY: one entry whose string is alive for the call.
    // Not fatal: an installation by a deployment tool, as SYSTEM, names no
    // person; members are added later with `net localgroup`.
    match unsafe { NetLocalGroupAddMembers(std::ptr::null(), name.as_ptr(), 3, (&raw const entry).cast(), 1) } {
        0 => println!("added {user} to {group}"),
        ERROR_MEMBER_IN_ALIAS => {}
        error => eprintln!("cannot add {user} to {group}: {}", std::io::Error::from_raw_os_error(error as i32)),
    }
    Ok(())
}

/// The installer's step: the group with `user` in it, and the service
/// restarted when it fails or a client stops it (after 2 s, 30 s, then a
/// minute; the count starts again after a day).
pub fn install(group: &str, user: &str) -> anyhow::Result<()> {
    setup(group, user)?;
    restart_on_failure()
}

fn restart_on_failure() -> anyhow::Result<()> {
    use windows_sys::Win32::System::Services::{
        ChangeServiceConfig2W, CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_ACTION, SC_ACTION_RESTART,
        SC_MANAGER_CONNECT, SERVICE_CHANGE_CONFIG, SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
        SERVICE_FAILURE_ACTIONS_FLAG, SERVICE_FAILURE_ACTIONSW, SERVICE_START,
    };
    // Always started again, after a minute from the third failure of a
    // day on (a client's Shutdown is one: see service.rs).
    let mut actions = [
        SC_ACTION { Type: SC_ACTION_RESTART, Delay: 2_000 },
        SC_ACTION { Type: SC_ACTION_RESTART, Delay: 30_000 },
        SC_ACTION { Type: SC_ACTION_RESTART, Delay: 60_000 },
    ];
    let config = SERVICE_FAILURE_ACTIONSW {
        dwResetPeriod: 24 * 3600,
        cActions: actions.len() as u32,
        lpsaActions: actions.as_mut_ptr(),
        ..Default::default()
    };
    // SAFETY: handles closed below; the configuration outlives the call.
    unsafe {
        let manager = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if manager.is_null() {
            return Err(std::io::Error::last_os_error().into());
        }
        // Restarting is starting: the change needs that right too.
        let service =
            OpenServiceW(manager, wide(vpn_core::brand::DAEMON).as_ptr(), SERVICE_CHANGE_CONFIG | SERVICE_START);
        let result = if service.is_null() {
            Err(std::io::Error::last_os_error())
        } else {
            // A stop with a non-zero exit code counts as a failure too.
            let flag = SERVICE_FAILURE_ACTIONS_FLAG { fFailureActionsOnNonCrashFailures: 1 };
            let changed = ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, (&raw const config).cast())
                & ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, (&raw const flag).cast());
            let result = if changed == 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) };
            CloseServiceHandle(service);
            result
        };
        CloseServiceHandle(manager);
        result.map_err(|e| anyhow::anyhow!("cannot set the service's restart on failure: {e}"))
    }
}

/// Where the installer leaves the member to add (`SetupMember`, under
/// HKLM), taken by the service's next start.
const SETUP_KEY: &str = r"SOFTWARE\Omnitun";
const SETUP_MEMBER: &str = "SetupMember";

/// At each service start: the group, the member the installer left (once),
/// the restart on failure. Problems are logged: the service runs anyway.
pub fn at_start(group: &str) {
    let member = take_member();
    if let Err(e) = setup(group, member.as_deref().unwrap_or("")) {
        tracing::warn!("{e:#}");
    }
    if let Err(e) = restart_on_failure() {
        tracing::warn!("{e:#}");
    }
}

/// Reads and deletes the installer's `SetupMember` value, if any.
fn take_member() -> Option<String> {
    use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegDeleteKeyValueW, RegGetValueW};
    let (key, value) = (wide(SETUP_KEY), wide(SETUP_MEMBER));
    let mut buffer = [0u16; 512];
    let mut size = std::mem::size_of_val(&buffer) as u32;
    // SAFETY: NUL-terminated names; the buffer and its size in bytes.
    let found = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if found != 0 {
        return None;
    }
    // SAFETY: as above; added once, not at every start.
    unsafe { RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, key.as_ptr(), value.as_ptr()) };
    let len = (size as usize / 2).saturating_sub(1).min(buffer.len());
    let member = String::from_utf16_lossy(&buffer[..len]);
    tracing::info!("adding {member} to the group, as the installer asked");
    Some(member)
}

/// Removes `group`, which may be gone already.
pub fn remove(group: &str) -> anyhow::Result<()> {
    // SAFETY: a NUL-terminated name.
    match unsafe { NetLocalGroupDel(std::ptr::null(), wide(group).as_ptr()) } {
        0 | NERR_GROUP_NOT_FOUND | ERROR_NO_SUCH_ALIAS => Ok(()),
        error => bail!("cannot remove group {group}: {}", std::io::Error::from_raw_os_error(error as i32)),
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
