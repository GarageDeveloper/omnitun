//! The log of the Windows service, which has no console: a file in the
//! runtime folder (SYSTEM's and the Administrators' only). Past `MAX_SIZE`
//! it becomes `.1` (the older ones shift up to `.KEEP`) and a new file
//! starts.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const MAX_SIZE: u64 = 10 * 1024 * 1024;
const KEEP: u32 = 5;

pub fn path() -> PathBuf {
    Path::new(&vpn_core::brand::runtime_dir()).join(format!("{}.log", vpn_core::brand::DAEMON))
}

/// Sends the log to the file, from now on.
pub fn init() -> anyhow::Result<()> {
    vpn_platform::prepare_runtime_dir()?;
    let file = LogFile::open(path())?;
    tracing_subscriber::fmt()
        .with_writer(file)
        .with_ansi(false)
        .with_env_filter(crate::log_filter())
        .try_init()
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

struct LogFile {
    path: PathBuf,
    file: Mutex<(File, u64)>,
}

impl LogFile {
    fn open(path: PathBuf) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let size = file.metadata()?.len();
        Ok(Self { path, file: Mutex::new((file, size)) })
    }

    fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        let mut current = self.file.lock().unwrap_or_else(|e| e.into_inner());
        if current.1 > MAX_SIZE {
            match rotate(&self.path) {
                Ok(file) => *current = (file, 0),
                Err(e) => eprintln!("cannot rotate {}: {e}", self.path.display()),
            }
        }
        current.0.write_all(buf)?;
        current.1 += buf.len() as u64;
        Ok(buf.len())
    }
}

/// Shifts the numbered files up and starts a new one.
fn rotate(path: &Path) -> std::io::Result<File> {
    let numbered = |n: u32| PathBuf::from(format!("{}.{n}", path.display()));
    for n in (1..KEEP).rev() {
        if numbered(n).exists() {
            std::fs::rename(numbered(n), numbered(n + 1))?;
        }
    }
    std::fs::rename(path, numbered(1))?;
    OpenOptions::new().create(true).append(true).open(path)
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogFile {
    type Writer = LogWriter<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        LogWriter(self)
    }
}

pub struct LogWriter<'a>(&'a LogFile);

impl Write for LogWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotates_past_the_limit() {
        let dir = std::env::temp_dir().join(format!("omnitund-winlog-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("d.log");
        let log = LogFile::open(path.clone()).unwrap();
        let line = vec![b'x'; 1024 * 1024];
        for _ in 0..12 {
            log.write(&line).unwrap();
        }
        assert!(PathBuf::from(format!("{}.1", path.display())).exists());
        assert!(std::fs::metadata(&path).unwrap().len() <= 2 * 1024 * 1024);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
