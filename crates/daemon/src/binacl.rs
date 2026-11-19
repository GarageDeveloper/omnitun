//! Windows: who may change the programs the service runs as SYSTEM. The
//! program, its folder and every folder above it must belong to SYSTEM, the
//! Administrators or TrustedInstaller, and grant nobody else a right that
//! would let them replace it: writing the program, adding a file to its
//! folder (a DLL there is loaded with it), or deleting, renaming or
//! changing the access of any of them. Adding a folder to one further up
//! (as users may at the root of a drive) changes nothing below.

use std::path::Path;
use std::ptr::null_mut;

use anyhow::{Context, bail};
use windows_sys::Win32::Foundation::{GENERIC_ALL, GENERIC_WRITE, LocalFree};
use windows_sys::Win32::Security::Authorization::{ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, INHERIT_ONLY_ACE,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_WRITE_DATA, WRITE_DAC,
    WRITE_OWNER,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ACCESS_DENIED_CALLBACK_ACE_TYPE, ACCESS_DENIED_OBJECT_ACE_TYPE,
};

/// SYSTEM, the Administrators, TrustedInstaller.
const TRUSTED: [&str; 3] =
    ["S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"];

/// Rights that let one replace or take over an object.
const TAKE_OVER: u32 = DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;

/// What only the trusted may do to the program, its folder, and the
/// folders above.
fn guarded(depth: usize) -> u32 {
    match depth {
        0 => TAKE_OVER | FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE,
        1 => TAKE_OVER | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD | GENERIC_WRITE,
        _ => TAKE_OVER | FILE_DELETE_CHILD,
    }
}

pub fn check(path: &Path) -> anyhow::Result<()> {
    let path = path.canonicalize().with_context(|| format!("cannot find {}", path.display()))?;
    for (depth, p) in path.ancestors().enumerate() {
        let shown = p.display().to_string();
        let shown = shown.strip_prefix(r"\\?\").unwrap_or(&shown);
        let (owner, writers) = security(p).with_context(|| format!("cannot check {shown}"))?;
        if !TRUSTED.contains(&owner.as_str()) {
            bail!("{shown} belongs to {}, not to SYSTEM or the Administrators", account(&owner));
        }
        if let Some((sid, _)) =
            writers.iter().find(|(sid, mask)| mask & guarded(depth) != 0 && !TRUSTED.contains(&sid.as_str()))
        {
            bail!("{shown} can be changed by {}, not only by SYSTEM or the Administrators", account(sid));
        }
    }
    Ok(())
}

/// The owner, and the rights each account is granted (not those only
/// passed on to children), as SIDs.
fn security(path: &Path) -> anyhow::Result<(String, Vec<(String, u32)>)> {
    let wide: Vec<u16> = path.as_os_str().encode_wide_nul();
    let (mut owner, mut dacl, mut descriptor): (PSID, *mut ACL, PSECURITY_DESCRIPTOR) =
        (null_mut(), null_mut(), null_mut());
    // SAFETY: the owner and the DACL point into `descriptor`, freed below.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32).into());
    }
    let result = (|| {
        let owner = sid_string(owner)?;
        if dacl.is_null() {
            // No access list: everyone may do anything.
            return Ok((owner, vec![("S-1-1-0".to_owned(), u32::MAX)]));
        }
        let mut writers = Vec::new();
        // SAFETY: a valid DACL; each ACE starts with its header.
        unsafe {
            for i in 0..(*dacl).AceCount as u32 {
                let mut ace = null_mut();
                if GetAce(dacl, i, &mut ace) == 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                let header = &*ace.cast::<ACE_HEADER>();
                if header.AceFlags as u32 & INHERIT_ONLY_ACE != 0 {
                    continue;
                }
                match header.AceType as u32 {
                    ACCESS_ALLOWED_ACE_TYPE => {
                        let allowed = &*ace.cast::<ACCESS_ALLOWED_ACE>();
                        let sid = (&raw const allowed.SidStart).cast_mut().cast();
                        writers.push((sid_string(sid)?, allowed.Mask));
                    }
                    ACCESS_DENIED_ACE_TYPE | ACCESS_DENIED_OBJECT_ACE_TYPE | ACCESS_DENIED_CALLBACK_ACE_TYPE => {}
                    other => bail!("unexpected access entry of type {other}"),
                }
            }
        }
        Ok((owner, writers))
    })();
    // SAFETY: allocated by GetNamedSecurityInfoW.
    unsafe { LocalFree(descriptor) };
    result
}

/// `DOMAIN\name` of a SID, for messages; the SID itself if unknown.
fn account(sid: &str) -> String {
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows_sys::Win32::Security::{LookupAccountSidW, SID_NAME_USE};
    let wide: Vec<u16> = sid.encode_utf16().chain(std::iter::once(0)).collect();
    let mut binary: PSID = null_mut();
    // SAFETY: a NUL-terminated string; the SID is freed below.
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut binary) } == 0 {
        return sid.to_owned();
    }
    let (mut name, mut domain) = (vec![0u16; 256], vec![0u16; 256]);
    let (mut name_len, mut domain_len, mut kind) = (256u32, 256u32, SID_NAME_USE::default());
    // SAFETY: buffers of the sizes given.
    let found = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            binary,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    } != 0;
    // SAFETY: allocated by ConvertStringSidToSidW.
    unsafe { LocalFree(binary) };
    if !found {
        return sid.to_owned();
    }
    let name = String::from_utf16_lossy(&name[..name_len as usize]);
    let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
    if domain.is_empty() { name } else { format!("{domain}\\{name}") }
}

fn sid_string(sid: PSID) -> anyhow::Result<String> {
    let mut text = null_mut();
    // SAFETY: a valid SID; the string is freed below.
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: NUL-terminated, from the call above.
    let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
    let string = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
    unsafe { LocalFree(text.cast()) };
    Ok(string)
}

trait EncodeWideNul {
    fn encode_wide_nul(&self) -> Vec<u16>;
}

impl EncodeWideNul for std::ffi::OsStr {
    fn encode_wide_nul(&self) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        self.encode_wide().chain(std::iter::once(0)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_programs_pass() {
        let cmd = Path::new(&std::env::var("SystemRoot").unwrap()).join(r"System32\cmd.exe");
        check(&cmd).unwrap();
    }

    #[test]
    fn a_users_files_do_not() {
        let file = std::env::temp_dir().join(format!("omnitund-binacl-{}.exe", std::process::id()));
        std::fs::write(&file, b"").unwrap();
        let error = check(&file).unwrap_err().to_string();
        std::fs::remove_file(&file).unwrap();
        assert!(error.contains("belongs to") || error.contains("can be changed"), "{error}");
    }
}
