//! The service's log (`/var/log/omnitund.log` and the files its rotation
//! keeps), taken apart: local time, session, importance; runs of similar
//! lines condensed. Read by `omnitunctl log` and the diagnostic report.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use vpn_core::brand;

/// Rotated files kept by the service (`.1` the most recent).
const ROTATED: u32 = 5;

/// One line of the log, taken apart.
#[derive(Debug, PartialEq)]
pub struct Line {
    /// Unix time, seconds.
    pub at: u64,
    pub level: String,
    /// The session it is about, if any.
    pub session: Option<String>,
    pub target: String,
    pub message: String,
}

pub fn path() -> String {
    format!("/var/log/{}.log", brand::DAEMON)
}

/// The text of the current log file, with an error that says who may
/// read it.
pub fn read_current() -> anyhow::Result<String> {
    read_file(&path())
}

fn read_file(path: &str) -> anyhow::Result<String> {
    let bytes = std::fs::read(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::PermissionDenied => {
            anyhow::anyhow!("{path} is readable by administrators only (it names servers, accounts and addresses)")
        }
        _ => anyhow::Error::new(e).context(format!("cannot read {path}")),
    })?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// The lines since `from` (Unix time), oldest first, rotated files
/// included.
pub fn read_since(from: u64) -> anyhow::Result<Vec<Line>> {
    let mut lines = Vec::new();
    for n in (1..=ROTATED).rev() {
        let rotated = format!("{}.{n}", path());
        // An old file entirely before `from` is skipped unread.
        let recent = std::fs::metadata(&rotated)
            .and_then(|m| m.modified())
            .is_ok_and(|t| t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()) >= from);
        if recent {
            lines.extend(read_file(&rotated)?.lines().filter_map(parse).filter(|l| l.at >= from));
        }
    }
    let current = read_current().context("the service's log")?;
    lines.extend(current.lines().filter_map(parse).filter(|l| l.at >= from));
    Ok(lines)
}

/// Which lines matter.
pub struct Filter {
    /// Session (profile) names; empty: every session and the service.
    pub names: Vec<String>,
    /// Every line, debug included, repetitions too.
    pub all: bool,
}

impl Filter {
    pub fn wanted(&self, line: &Line) -> bool {
        let named = |s: &Option<String>| s.as_ref().is_some_and(|s| self.names.contains(s));
        if !self.names.is_empty() && !named(&line.session) {
            return false;
        }
        if self.all {
            return true;
        }
        if !["INFO", "WARN", "ERROR"].contains(&line.level.as_str()) {
            return false;
        }
        // Lines of other components without a session (a library's
        // warning) only with `all`.
        line.session.is_some() || line.target == brand::DAEMON
    }
}

/// Turns the wanted lines into text, a run of similar ones once with its
/// count: `push` returns a line once its run is over, `finish` the last.
pub struct Condenser {
    filter: Filter,
    last: Option<(Line, String, usize)>,
}

impl Condenser {
    pub fn new(filter: Filter) -> Self {
        Self { filter, last: None }
    }

    pub fn push(&mut self, line: Line) -> Option<String> {
        if !self.filter.wanted(&line) {
            return None;
        }
        let shape = shape(&line);
        if let Some((_, last_shape, count)) = &mut self.last
            && *last_shape == shape
            && !self.filter.all
        {
            *count += 1;
            return None;
        }
        let done = self.finish();
        self.last = Some((line, shape, 1));
        done
    }

    pub fn finish(&mut self) -> Option<String> {
        let (line, _, count) = self.last.take()?;
        let who = line.session.as_deref().map_or(String::new(), |s| format!("[{s}] "));
        let level = match line.level.as_str() {
            "INFO" => String::new(),
            other => format!("{other}: "),
        };
        let more = if count > 1 { format!(" (and {} similar)", count - 1) } else { String::new() };
        Some(format!("{} {who}{level}{}{more}", local_time(line.at), line.message))
    }
}

/// A line with each number, address or SPI blanked: lines of the same
/// shape are repetitions.
fn shape(line: &Line) -> String {
    let mut text = String::new();
    let mut run = String::new();
    let end_run = |run: &mut String, text: &mut String| {
        if run.chars().any(|c| c.is_ascii_digit()) {
            text.push('#');
        } else {
            text.push_str(run);
        }
        run.clear();
    };
    for c in line.message.chars() {
        if c.is_ascii_hexdigit() || ".:/".contains(c) {
            run.push(c);
        } else {
            end_run(&mut run, &mut text);
            text.push(c);
        }
    }
    end_run(&mut run, &mut text);
    format!("{:?}|{}|{text}", line.session, line.level)
}

/// `2026-10-26T16:40:51.045740Z  INFO omnitund::engine: [acme-eu]  INFO
/// engine{session="acme-eu"}: starting …` and the like.
pub fn parse(raw: &str) -> Option<Line> {
    let raw = strip_ansi(raw);
    let mut words = raw.splitn(3, ' ').filter(|w| !w.is_empty());
    let at = unix_time(words.next()?)?;
    let rest = raw.split_once('Z')?.1.trim_start();
    let (level, rest) = rest.split_once(' ')?;
    let (target, mut message) = rest.trim_start().split_once(": ")?;
    let mut session = None;
    let mut level = level.to_owned();
    // An engine's line: "[name]  LEVEL spans: message".
    if let Some(inner) = message.strip_prefix('[')
        && let Some((name, after)) = inner.split_once("] ")
    {
        session = Some(name.to_owned());
        let after = after.trim_start();
        if let Some((inner_level, text)) = after.split_once(' ')
            && ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"].contains(&inner_level)
        {
            level = inner_level.to_owned();
            message = text.trim_start();
        } else {
            message = after;
        }
        // Spans: "engine{session=\"x\"}: ".
        while let Some((span, text)) = message.split_once("}: ")
            && span.contains('{')
            && !span.contains(' ')
        {
            message = text;
        }
    }
    let mut message = message.to_owned();
    // The service's own lines end with session="name".
    if let Some(start) = message.rfind(" session=\"") {
        let name = message[start + 10..].trim_end_matches('"').to_owned();
        if !name.contains('"') {
            session.get_or_insert(name);
            message.truncate(start);
        }
    }
    let target = target.split("::").next().unwrap_or(target).to_owned();
    Some(Line { at, level, session, target, message })
}

fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// `2026-10-26T16:40:51.045740Z` (UTC).
fn unix_time(stamp: &str) -> Option<u64> {
    let stamp = stamp.strip_suffix('Z')?;
    let (date, time) = stamp.split_once('T')?;
    let mut d = date.split('-').map(|n| n.parse::<i64>().ok());
    let (y, m, day) = (d.next()??, d.next()??, d.next()??);
    let mut t = time.split(':');
    let (h, min) = (t.next()?.parse::<i64>().ok()?, t.next()?.parse::<i64>().ok()?);
    let s = t.next()?.split('.').next()?.parse::<i64>().ok()?;
    // Days since 1970-01-01 (H. Hinnant's days_from_civil).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + h * 3600 + min * 60 + s).ok()
}

pub fn local_time(at: u64) -> String {
    let t = at as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: both pointers are valid for the call; localtime_r is the
    // thread-safe variant.
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return at.to_string();
    }
    format!(
        "{}-{:02}-{:02} {:02}:{:02}:{:02}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    )
}

pub fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_lines() {
        let line = parse(
            "2026-10-26T16:40:51.045740Z  INFO omnitund::engine: [acme-eu]  INFO engine{session=\"acme-eu\"}: \
             starting IKEv1 main mode gateway=192.0.2.1:500",
        )
        .unwrap();
        assert_eq!(line.at, 1_793_032_851);
        assert_eq!(line.session.as_deref(), Some("acme-eu"));
        assert_eq!(line.level, "INFO");
        assert_eq!(line.message, "starting IKEv1 main mode gateway=192.0.2.1:500");
        let line =
            parse("2026-10-26T14:20:03.203758Z  INFO omnitund::engine: [acme-eu]  INFO IKEv1 SAs deleted").unwrap();
        assert_eq!(line.message, "IKEv1 SAs deleted");
    }

    #[test]
    fn service_lines() {
        let line = parse(
            "\x1b[2m2026-10-26T13:16:14.257167Z\x1b[0m \x1b[32m INFO\x1b[0m omnitund::manager: \
             Connected: 192.0.2.9 on utun6 session=\"acme-eu\"",
        )
        .unwrap();
        assert_eq!((line.session.as_deref(), line.target.as_str()), (Some("acme-eu"), "omnitund"));
        assert_eq!(line.message, "Connected: 192.0.2.9 on utun6");
        let line = parse("2026-10-26T15:49:41.562523Z  INFO omnitund: listening on /var/run/omnitund.sock").unwrap();
        assert_eq!(line.session, None);
        assert!(parse("not a log line").is_none());
    }

    #[test]
    fn repeated_lines_have_one_shape() {
        let a = parse("2026-10-26T08:24:17.665330Z  WARN omnitund::manager: route 10.0.0.0/30 takes x session=\"F\"");
        let b =
            parse("2026-10-26T08:24:17.665344Z  WARN omnitund::manager: route 192.168.100.4/31 takes x session=\"F\"");
        assert_eq!(shape(&a.unwrap()), shape(&b.unwrap()));
    }
}
