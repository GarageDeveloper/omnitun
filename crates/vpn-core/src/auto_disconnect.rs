//! Automatic disconnection of a profile: after a time connected, after a
//! time without keyboard or mouse input, or at a time of day. Every limit
//! is written `H:MM`; the first one reached disconnects.

use serde::{Deserialize, Serialize};

/// A duration or a time of day, written `H:MM` (`8:00`, `18:30`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HourMinute {
    minutes: u32,
}

/// Durations above this are surely mistakes (about six weeks).
pub const MAX_HOURS: u32 = 999;

impl HourMinute {
    pub const fn new(hours: u32, minutes: u32) -> Self {
        Self { minutes: hours * 60 + minutes }
    }

    pub fn hours(self) -> u32 {
        self.minutes / 60
    }

    pub fn minutes(self) -> u32 {
        self.minutes % 60
    }

    pub fn secs(self) -> u64 {
        u64::from(self.minutes) * 60
    }
}

impl std::fmt::Display for HourMinute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{:02}", self.hours(), self.minutes())
    }
}

impl std::str::FromStr for HourMinute {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        let bad = || anyhow::anyhow!("{s:?} is not a time written H:MM");
        let (hours, minutes) = s.trim().split_once(':').ok_or_else(bad)?;
        let digits = |t: &str, lengths: std::ops::RangeInclusive<usize>| {
            (lengths.contains(&t.len()) && t.bytes().all(|b| b.is_ascii_digit())).then(|| t.parse::<u32>().ok())?
        };
        // Minutes always on two digits: `8:5` is ambiguous.
        match (digits(hours, 1..=3), digits(minutes, 2..=2)) {
            (Some(hours), Some(minutes)) if minutes < 60 => Ok(Self::new(hours, minutes)),
            _ => Err(bad()),
        }
    }
}

impl Serialize for HourMinute {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for HourMinute {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// When a profile's session ends by itself; nothing set, or off: never.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoDisconnect {
    /// Off keeps the limits for later, without applying them.
    #[serde(default = "yes", skip_serializing_if = "is_yes")]
    pub enabled: bool,
    /// This long after the connection; reconnections after a drop do not
    /// start it again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<HourMinute>,
    /// This long without keyboard or mouse input on the computer (not
    /// network traffic, which never stops). macOS only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle: Option<HourMinute>,
    /// At this time of day, local time: the first one after the connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<HourMinute>,
}

fn yes() -> bool {
    true
}

fn is_yes(b: &bool) -> bool {
    *b
}

impl Default for AutoDisconnect {
    fn default() -> Self {
        Self { enabled: true, after: None, idle: None, at: None }
    }
}

impl AutoDisconnect {
    /// No limit set: nothing to keep in the profile.
    pub fn is_empty(&self) -> bool {
        self.after.is_none() && self.idle.is_none() && self.at.is_none()
    }

    /// Limits set and switched on: the session ends by itself.
    pub fn is_active(&self) -> bool {
        self.enabled && !self.is_empty()
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        for (name, limit) in [("after", self.after), ("idle", self.idle)] {
            match limit {
                Some(l) if l.minutes == 0 => anyhow::bail!("auto_disconnect.{name} must be longer than 0:00"),
                Some(l) if l.hours() > MAX_HOURS => {
                    anyhow::bail!("auto_disconnect.{name} must be at most {MAX_HOURS}:59")
                }
                _ => {}
            }
        }
        if let Some(at) = self.at
            && at.hours() >= 24
        {
            anyhow::bail!("auto_disconnect.at must be a time of day, 0:00 to 23:59");
        }
        Ok(())
    }
}

/// Which limit is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Criterion {
    After,
    Idle,
    At,
}

/// The disconnection to come: Unix time, the limit that causes it, and
/// that limit's value as set in the profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Planned {
    pub at: u64,
    pub criterion: Criterion,
    pub limit: HourMinute,
}

/// How long before a disconnection the user is told, at most: never more
/// than half the limit, so that a short idle limit does not warn at once.
pub const WARNING_LEAD_SECS: u64 = 300;

impl Planned {
    /// When to warn the user.
    pub fn warning_at(&self) -> u64 {
        self.at.saturating_sub(WARNING_LEAD_SECS.min(self.limit.secs() / 2))
    }
}

/// What a session's deadlines count from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clock {
    /// Unix time.
    pub now: u64,
    /// `after` counts from here: the connection, or the last postponement.
    pub after_from: u64,
    /// The time of day `at` falls next, as Unix time, postponements added.
    pub at: Option<u64>,
    /// Seconds without input; `None` where it cannot be read.
    pub idle_secs: Option<u64>,
}

/// One hour more, for a postponed time of day.
pub const POSTPONE_AT_SECS: u64 = 3600;

impl AutoDisconnect {
    /// The earliest of the deadlines that apply.
    pub fn next(&self, clock: &Clock) -> Option<Planned> {
        if !self.enabled {
            return None;
        }
        let after = self.after.map(|limit| Planned {
            at: clock.after_from.saturating_add(limit.secs()),
            criterion: Criterion::After,
            limit,
        });
        let idle = self.idle.zip(clock.idle_secs).map(|(limit, idle)| Planned {
            at: clock.now.saturating_add(limit.secs().saturating_sub(idle)),
            criterion: Criterion::Idle,
            limit,
        });
        let at = self.at.zip(clock.at).map(|(limit, at)| Planned { at, criterion: Criterion::At, limit });
        [after, idle, at].into_iter().flatten().min_by_key(|p| p.at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hm(s: &str) -> HourMinute {
        s.parse().unwrap()
    }

    #[test]
    fn written_hours_and_minutes() {
        assert_eq!(hm("8:00"), HourMinute::new(8, 0));
        assert_eq!(hm(" 18:30 "), HourMinute::new(18, 30));
        assert_eq!(hm("0:05").secs(), 300);
        assert_eq!(hm("120:00").hours(), 120);
        assert_eq!(HourMinute::new(8, 5).to_string(), "8:05");
        for bad in ["8", "8:5", "8:60", ":30", "8:", "-1:00", "8:30:00", "1000:00", "a:00", "8h30", ""] {
            assert!(bad.parse::<HourMinute>().is_err(), "{bad}");
        }
    }

    #[test]
    fn stored_as_text() {
        #[derive(Serialize, Deserialize)]
        struct T {
            auto_disconnect: AutoDisconnect,
        }
        let t: T = toml::from_str("auto_disconnect = { after = \"8:00\", at = \"19:15\" }").unwrap();
        assert_eq!(t.auto_disconnect.after, Some(HourMinute::new(8, 0)));
        assert_eq!(t.auto_disconnect.idle, None);
        let text = toml::to_string(&t).unwrap();
        assert!(text.contains("after = \"8:00\"") && text.contains("at = \"19:15\""), "{text}");
        assert!(t.auto_disconnect.enabled && !text.contains("enabled"), "{text}");
        assert!(toml::from_str::<T>("auto_disconnect = { after = \"8h\" }").is_err());
        // Switched off: the limits stay, with the switch.
        let off: T = toml::from_str("auto_disconnect = { enabled = false, idle = \"1:00\" }").unwrap();
        assert!(!off.auto_disconnect.enabled && !off.auto_disconnect.is_active());
        assert!(toml::to_string(&off).unwrap().contains("enabled = false"));
    }

    #[test]
    fn limits_are_checked() {
        let a = |after: &str, idle: &str, at: &str| AutoDisconnect {
            enabled: true,
            after: (!after.is_empty()).then(|| hm(after)),
            idle: (!idle.is_empty()).then(|| hm(idle)),
            at: (!at.is_empty()).then(|| hm(at)),
        };
        assert!(a("8:00", "0:30", "23:59").validate().is_ok());
        assert!(a("0:00", "", "").validate().is_err());
        assert!(a("", "0:00", "").validate().is_err());
        assert!(a("", "", "24:00").validate().is_err());
        assert!(AutoDisconnect::default().is_empty());
    }

    #[test]
    fn the_first_deadline_wins() {
        let rule = AutoDisconnect {
            after: Some(hm("8:00")),
            idle: Some(hm("1:00")),
            at: Some(hm("19:00")),
            ..Default::default()
        };
        let clock = Clock { now: 10_000, after_from: 1_000, at: Some(50_000), idle_secs: Some(0) };
        // Active user: the idle deadline is an hour away, before the others.
        assert_eq!(rule.next(&clock), Some(Planned { at: 13_600, criterion: Criterion::Idle, limit: hm("1:00") }));
        // Idle for 50 minutes: ten minutes left.
        let idle = Clock { idle_secs: Some(3000), ..clock };
        assert_eq!(rule.next(&idle).unwrap().at, 10_600);
        // No idle time to read: the time of day comes before 8 hours.
        let unknown = Clock { idle_secs: None, ..clock };
        assert_eq!(rule.next(&unknown).unwrap().criterion, Criterion::After);
        assert_eq!(rule.next(&unknown).unwrap().at, 1_000 + 8 * 3600);
        let early = Clock { at: Some(20_000), ..unknown };
        assert_eq!(rule.next(&early).unwrap().criterion, Criterion::At);
        assert_eq!(AutoDisconnect::default().next(&clock), None);
        let off = AutoDisconnect { enabled: false, ..rule };
        assert_eq!(off.next(&clock), None);
        assert!(!off.is_active() && !off.is_empty());
    }

    #[test]
    fn warned_five_minutes_before_or_half_the_limit() {
        let planned = Planned { at: 10_000, criterion: Criterion::After, limit: hm("8:00") };
        assert_eq!(planned.warning_at(), 9_700);
        let short = Planned { at: 10_000, criterion: Criterion::Idle, limit: hm("0:04") };
        assert_eq!(short.warning_at(), 9_880);
    }
}
