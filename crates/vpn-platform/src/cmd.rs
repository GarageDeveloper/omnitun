use anyhow::{Context, bail};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// Where system tools are, root's only.
const SYSTEM_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// Runs a system tool; fails with its stderr on non-zero exit.
pub async fn run(program: &str, args: &[&str]) -> anyhow::Result<String> {
    run_with_stdin(program, args, None).await
}

pub async fn run_with_stdin(program: &str, args: &[&str], stdin: Option<&str>) -> anyhow::Result<String> {
    tracing::debug!("exec {program} {}", args.join(" "));
    let mut child = Command::new(program)
        .args(args)
        // System tools only, wherever the daemon was started from: the
        // program is looked up in this PATH.
        .env_clear()
        .env("PATH", SYSTEM_PATH)
        .env("LC_ALL", "C")
        .stdin(if stdin.is_some() { std::process::Stdio::piped() } else { std::process::Stdio::null() })
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| format!("cannot run {program}"))?;
    if let Some(input) = stdin {
        let mut pipe = child.stdin.take().expect("stdin piped");
        pipe.write_all(input.as_bytes()).await?;
    }
    let out = child.wait_with_output().await?;
    if !out.status.success() {
        bail!("{program} {} failed: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
