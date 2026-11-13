//! Sessions that end by themselves, as their profile's `auto_disconnect`
//! says: the deadlines, the time of day and the user's idle time.

use std::time::Duration;

use vpn_core::auto_disconnect::{AutoDisconnect, Clock, Criterion, HourMinute, POSTPONE_AT_SECS, Planned};

/// How often deadlines are checked, against the wall clock: a monotonic
/// timer would stop while the computer sleeps, and fire late after.
pub const TICK: Duration = Duration::from_secs(15);

/// A session's deadlines, which `Postpone` moves.
#[derive(Debug, Default)]
pub struct Schedule {
    /// `after` counts from here: the first connection, or the last
    /// postponement. `None` until the tunnel has been up.
    after_from: Option<u64>,
    /// The time of day to disconnect at, as Unix time.
    at: Option<u64>,
}

impl Schedule {
    /// The deadlines of a session first up at `connected`; later calls
    /// keep them (a reconnection does not start them again).
    pub fn start(&mut self, rule: &AutoDisconnect, connected: u64) {
        if self.after_from.is_none() {
            self.after_from = Some(connected);
            self.at = rule.at.map(|time| next_time_of_day(connected, time));
        }
    }

    pub fn clock(&self, now: u64, idle_secs: Option<u64>) -> Option<Clock> {
        Some(Clock { now, after_from: self.after_from?, at: self.at, idle_secs })
    }

    /// Puts off the deadline `planned` was for: the time connected starts
    /// again, a time of day moves an hour later. Idleness ends with the
    /// user's next input, not with a request: false.
    pub fn postpone(&mut self, planned: &Planned, now: u64) -> bool {
        match planned.criterion {
            Criterion::After if self.after_from.is_some() => {
                self.after_from = Some(now);
                true
            }
            Criterion::At => match &mut self.at {
                Some(at) => {
                    *at = (*at).max(now) + POSTPONE_AT_SECS;
                    true
                }
                None => false,
            },
            _ => false,
        }
    }
}

/// Why the session ended, for its last state.
pub fn reason(planned: &Planned) -> String {
    match planned.criterion {
        Criterion::After => format!("disconnected automatically after {} connected", planned.limit),
        Criterion::Idle => format!("disconnected automatically after {} without activity", planned.limit),
        Criterion::At => format!("disconnected automatically at {}", planned.limit),
    }
}

/// The first `time` of day, local time, strictly after `from` (Unix time).
pub fn next_time_of_day(from: u64, time: HourMinute) -> u64 {
    let local = |day_offset: i32| -> Option<u64> {
        let t = libc::time_t::try_from(from).ok()?;
        // SAFETY: localtime_r and mktime only read and write `tm`, which
        // lives on this stack frame; both are thread-safe.
        unsafe {
            let mut tm: libc::tm = std::mem::zeroed();
            if libc::localtime_r(&t, &mut tm).is_null() {
                return None;
            }
            tm.tm_mday += day_offset;
            tm.tm_hour = time.hours() as libc::c_int;
            tm.tm_min = time.minutes() as libc::c_int;
            tm.tm_sec = 0;
            // Whether summer time applies on that day: for mktime to say.
            tm.tm_isdst = -1;
            u64::try_from(libc::mktime(&mut tm)).ok()
        }
    };
    match local(0) {
        Some(today) if today > from => today,
        _ => local(1).filter(|&tomorrow| tomorrow > from).unwrap_or_else(|| {
            // No local time to read: UTC.
            let day = from - from % 86_400;
            let at = day + time.secs();
            if at > from { at } else { at + 86_400 }
        }),
    }
}

/// Seconds since the last keyboard or mouse input on this computer,
/// whoever is logged in; `None` where it cannot be read.
#[cfg(target_os = "macos")]
pub async fn user_idle_secs() -> Option<u64> {
    let output = tokio::process::Command::new("/usr/sbin/ioreg")
        .args(["-r", "-c", "IOHIDSystem", "-d", "1", "-k", "HIDIdleTime"])
        .env_clear()
        .env("LC_ALL", "C")
        .kill_on_drop(true)
        .output();
    let output = tokio::time::timeout(Duration::from_secs(5), output).await.ok()?.ok()?;
    if !output.status.success() {
        return None;
    }
    parse_idle(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(not(target_os = "macos"))]
pub async fn user_idle_secs() -> Option<u64> {
    None
}

/// `"HIDIdleTime" = <nanoseconds>` in ioreg's output.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_idle(text: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let value = line.trim().strip_prefix("\"HIDIdleTime\"")?.trim().strip_prefix('=')?;
        value.trim().parse::<u64>().ok().map(|ns| ns / 1_000_000_000)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpn_core::auto_disconnect::Criterion;

    fn hm(s: &str) -> HourMinute {
        s.parse().unwrap()
    }

    fn local_hour_minute(t: u64) -> (i32, i32) {
        let t = t as libc::time_t;
        // SAFETY: as in `next_time_of_day`.
        unsafe {
            let mut tm: libc::tm = std::mem::zeroed();
            libc::localtime_r(&t, &mut tm);
            (tm.tm_hour, tm.tm_min)
        }
    }

    #[test]
    fn the_next_time_of_day() {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        for time in ["0:00", "7:30", "12:00", "19:15", "23:59"] {
            let at = next_time_of_day(now, hm(time));
            assert!(at > now && at - now <= 25 * 3600, "{time}: {at} from {now}");
            assert_eq!(local_hour_minute(at), (hm(time).hours() as i32, hm(time).minutes() as i32), "{time}");
        }
        // Exactly that time: the next day's.
        let at = next_time_of_day(now, hm("12:00"));
        let next = next_time_of_day(at, hm("12:00"));
        assert!(next > at + 22 * 3600 && next <= at + 26 * 3600);
    }

    #[test]
    fn deadlines_start_once_and_move_when_postponed() {
        let rule = AutoDisconnect {
            after: Some(hm("8:00")),
            idle: Some(hm("0:30")),
            at: Some(hm("19:00")),
            ..Default::default()
        };
        let mut schedule = Schedule::default();
        assert!(schedule.clock(100, None).is_none(), "not up yet");
        schedule.start(&rule, 1_000);
        let at = schedule.at.unwrap();
        // A reconnection keeps the first connection's deadlines.
        schedule.start(&rule, 5_000);
        assert_eq!(schedule.clock(6_000, None).unwrap().after_from, 1_000);

        let after = Planned { at: 1_000 + 8 * 3600, criterion: Criterion::After, limit: hm("8:00") };
        assert!(schedule.postpone(&after, 20_000));
        assert_eq!(schedule.clock(20_000, None).unwrap().after_from, 20_000);
        assert_eq!(schedule.at, Some(at), "only the deadline that was due moves");

        let time = Planned { at, criterion: Criterion::At, limit: hm("19:00") };
        assert!(schedule.postpone(&time, 0));
        assert_eq!(schedule.at, Some(at + POSTPONE_AT_SECS));
        // Late (the computer slept): an hour from now.
        assert!(schedule.postpone(&time, at + 7200));
        assert_eq!(schedule.at, Some(at + 7200 + POSTPONE_AT_SECS));

        let idle = Planned { at: 0, criterion: Criterion::Idle, limit: hm("0:30") };
        assert!(!schedule.postpone(&idle, 0));
    }

    #[test]
    fn idle_time_from_ioreg() {
        let text = "+-o IOHIDSystem  <class IOHIDSystem>\n    {\n      \"HIDIdleTime\" = 7608266583\n    }\n";
        assert_eq!(parse_idle(text), Some(7));
        assert_eq!(parse_idle("nothing"), None);
    }
}
