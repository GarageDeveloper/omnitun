//! The directory of the daemon's runtime files (`vpn_core::brand::runtime_dir`).
//! On macOS and Linux it is the system's (`/var/run`, `/run`). On Windows
//! it is `%ProgramData%\Omnitun`, where any user may create a folder
//! first: the daemon makes sure it is a folder rather than a link (which
//! it removes), that SYSTEM or the Administrators own it and that only
//! they can change what is inside (the route journal is acted upon at the
//! next start).

/// Creates the directory if needed, and on Windows checks its owner and
/// sets its access list.
#[cfg(unix)]
pub fn prepare_runtime_dir() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(windows)]
pub fn prepare_runtime_dir() -> anyhow::Result<()> {
    windows::prepare(&vpn_core::brand::runtime_dir())
}

#[cfg(windows)]
mod windows {
    use std::ptr::{null, null_mut};

    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;

    use anyhow::{Context, bail};
    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
        SetSecurityInfo,
    };
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, IsWellKnownSid, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateDirectoryW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL, WRITE_DAC,
    };

    /// SYSTEM and the Administrators only, for the folder and what it
    /// holds; nothing inherited from `%ProgramData%`.
    const SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

    pub(super) fn prepare(dir: &str) -> anyhow::Result<()> {
        let path = wide(dir);
        let descriptor = Descriptor::from_sddl(SDDL)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        let mut link_removed = false;
        loop {
            // SAFETY: a NUL-terminated path and attributes valid for the call.
            if unsafe { CreateDirectoryW(path.as_ptr(), &attributes) } != 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
                return Err(error).with_context(|| format!("cannot create {dir}"));
            }
            // There already. The folder itself is opened, not what a link
            // there points to: a junction made by a user would pass the
            // checks below on its target, then stay theirs to point
            // anywhere the service writes, renames or deletes. It is kept
            // open, without sharing its deletion, until its access is set.
            let folder = std::fs::OpenOptions::new()
                .access_mode(READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(dir)
                .with_context(|| format!("cannot open {dir}"))?;
            let attributes = folder.metadata().with_context(|| format!("cannot check {dir}"))?.file_attributes();
            if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                drop(folder);
                if link_removed {
                    bail!("{dir} is a link again; remove it");
                }
                // Removes the link, not what it points to.
                std::fs::remove_dir(dir).with_context(|| format!("{dir} is a link and cannot be removed"))?;
                link_removed = true;
                continue;
            }
            if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
                bail!("{dir} is not a folder; remove it");
            }
            return secure(&folder, dir, &descriptor);
        }
    }

    /// Checks that SYSTEM or the Administrators own the open folder, and
    /// sets its access list.
    fn secure(folder: &std::fs::File, dir: &str, descriptor: &Descriptor) -> anyhow::Result<()> {
        let handle = folder.as_raw_handle();
        // Someone else's would stay theirs to change.
        let mut owner: PSID = null_mut();
        let mut current: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: an open handle; `owner` points into `current`, freed below.
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut current,
            )
        };
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status as i32))
                .with_context(|| format!("cannot check {dir}"));
        }
        let current = Descriptor(current);
        // SAFETY: a valid SID.
        let trusted = unsafe {
            IsWellKnownSid(owner, WinLocalSystemSid) != 0 || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
        };
        drop(current);
        if !trusted {
            bail!("{dir} belongs to a user other than SYSTEM or the Administrators; remove it");
        }
        let (mut present, mut defaulted, mut dacl) = (0, 0, null_mut::<ACL>());
        // SAFETY: the DACL points into `descriptor`, alive below.
        if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) } == 0 {
            return Err(std::io::Error::last_os_error()).context("invalid access list");
        }
        // SAFETY: an open handle and a valid DACL.
        let status = unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                dacl,
                null(),
            )
        };
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status as i32))
                .with_context(|| format!("cannot set who may change {dir}"));
        }
        Ok(())
    }

    struct Descriptor(PSECURITY_DESCRIPTOR);

    impl Descriptor {
        fn from_sddl(sddl: &str) -> anyhow::Result<Self> {
            let wide = wide(sddl);
            let mut descriptor = null_mut();
            // SAFETY: a NUL-terminated string; freed on drop.
            if unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error()).context("invalid access list");
            }
            Ok(Self(descriptor))
        }
    }

    impl Drop for Descriptor {
        fn drop(&mut self) {
            // SAFETY: allocated by the system.
            unsafe { LocalFree(self.0) };
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
}
