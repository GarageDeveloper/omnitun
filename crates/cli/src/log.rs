//! `omnitunctl log`: the service's log, readable: local time, one session
//! or several, the important lines only (unless `--all`), repeated lines
//! counted once.

use std::io::{Read, Seek, SeekFrom};
use std::time::Duration;

use anyhow::{Context, bail};
use vpn_client::service_log::{self, Condenser, Filter};

pub struct Options {
    /// Session (profile) names; empty: every session and the service.
    pub names: Vec<String>,
    pub since: Duration,
    pub all: bool,
    pub follow: bool,
}

pub async fn show(options: Options) -> anyhow::Result<()> {
    let from = service_log::now().saturating_sub(options.since.as_secs());
    let mut condenser = Condenser::new(Filter { names: options.names, all: options.all });
    let print = |text: Option<String>| {
        if let Some(text) = text {
            println!("{text}");
        }
    };
    for line in service_log::read_since(from)? {
        print(condenser.push(line));
    }
    print(condenser.finish());
    if !options.follow {
        return Ok(());
    }
    // New lines as they come; a rotated (shorter) file is read again.
    let path = service_log::path();
    let mut file = std::fs::File::open(&path).with_context(|| format!("cannot read {path}"))?;
    let mut offset = file.metadata()?.len();
    let mut pending = String::new();
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if len < offset {
            file = std::fs::File::open(&path)?;
            offset = 0;
        }
        if len == offset {
            continue;
        }
        file.seek(SeekFrom::Start(offset))?;
        let mut chunk = String::new();
        offset += file.read_to_string(&mut chunk)? as u64;
        pending.push_str(&chunk);
        while let Some(end) = pending.find('\n') {
            let raw: String = pending.drain(..=end).collect();
            if let Some(line) = service_log::parse(raw.trim_end()) {
                print(condenser.push(line));
            }
        }
        print(condenser.finish());
    }
}

/// `30m`, `2h`, `3d`, `90s`.
pub fn duration(text: &str) -> anyhow::Result<Duration> {
    let (number, unit) = text.split_at(text.find(|c: char| !c.is_ascii_digit()).unwrap_or(text.len()));
    let n: u64 = number.parse().with_context(|| format!("{text:?}: a number then s, m, h or d"))?;
    let seconds = match unit {
        "s" => 1,
        "m" | "" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => bail!("{text:?}: the unit is s, m, h or d"),
    };
    Ok(Duration::from_secs(n.saturating_mul(seconds)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(duration("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(duration("2h").unwrap(), Duration::from_secs(7200));
        assert!(duration("2w").is_err());
    }
}
