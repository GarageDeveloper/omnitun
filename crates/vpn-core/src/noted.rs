//! A list entry with an optional note, to remember what it is for. In
//! `profiles.toml` an entry without a note stays a plain string, so older
//! lists read as before: `"10.0.0.0/8"`, or `{ net = "10.0.0.0/8", note =
//! "Intranet" }` (`domain = …` for a domain).

use std::fmt;

use ipnet::Ipv4Net;
use serde::de::{self, IntoDeserializer, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Longest note kept with an entry, in characters.
pub const MAX_NOTE: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Noted<T> {
    pub value: T,
    pub note: Option<String>,
}

/// The key naming the value in the table form.
pub trait NoteKey: Sized {
    /// The keys the table form accepts.
    const KEYS: &'static [&'static str];

    /// The key this value is written under.
    fn key(&self) -> &'static str;

    /// The value read under `key`, one of `KEYS`.
    fn keyed(key: &str, text: &str) -> Result<Self, String>;
}

impl NoteKey for Ipv4Net {
    const KEYS: &'static [&'static str] = &["net"];

    fn key(&self) -> &'static str {
        "net"
    }

    fn keyed(_key: &str, text: &str) -> Result<Self, String> {
        text.parse().map_err(|_| format!("{text:?} is not a network (10.1.0.0/16)"))
    }
}

impl NoteKey for String {
    const KEYS: &'static [&'static str] = &["domain"];

    fn key(&self) -> &'static str {
        "domain"
    }

    fn keyed(_key: &str, text: &str) -> Result<Self, String> {
        Ok(text.to_owned())
    }
}

impl<T> Noted<T> {
    pub fn new(value: T, note: Option<String>) -> Self {
        Self { value, note }
    }

    /// A note within `MAX_NOTE` characters, without control characters.
    pub fn check_note(&self) -> anyhow::Result<()> {
        if let Some(note) = &self.note {
            anyhow::ensure!(note.chars().count() <= MAX_NOTE, "a note is limited to {MAX_NOTE} characters");
            anyhow::ensure!(!note.chars().any(char::is_control), "a note is one line of text");
        }
        Ok(())
    }
}

impl<T> From<T> for Noted<T> {
    fn from(value: T) -> Self {
        Self { value, note: None }
    }
}

/// The value alone, without a note.
impl<T: std::str::FromStr> std::str::FromStr for Noted<T> {
    type Err = T::Err;

    fn from_str(text: &str) -> Result<Self, T::Err> {
        text.parse::<T>().map(Noted::from)
    }
}

impl<T> std::ops::Deref for Noted<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

impl<T: PartialEq> PartialEq<T> for Noted<T> {
    fn eq(&self, other: &T) -> bool {
        self.value == *other
    }
}

impl PartialEq<&str> for Noted<String> {
    fn eq(&self, other: &&str) -> bool {
        self.value == *other
    }
}

impl<T: fmt::Display> fmt::Display for Noted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.value.fmt(f)
    }
}

impl<T: Serialize + NoteKey> Serialize for Noted<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.note {
            None => self.value.serialize(serializer),
            Some(note) => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry(self.value.key(), &self.value)?;
                map.serialize_entry("note", note)?;
                map.end()
            }
        }
    }
}

impl<'de, T: Deserialize<'de> + NoteKey> Deserialize<'de> for Noted<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Entry<T>(std::marker::PhantomData<T>);

        impl<'de, T: Deserialize<'de> + NoteKey> Visitor<'de> for Entry<T> {
            type Value = Noted<T>;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "a string, or a table with `{}` and `note`", T::KEYS.join("` or `"))
            }

            fn visit_str<E: de::Error>(self, text: &str) -> Result<Self::Value, E> {
                T::deserialize(text.into_deserializer()).map(Noted::from)
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let (mut value, mut note) = (None, None);
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        k if T::KEYS.contains(&k) && value.is_none() => {
                            let text = map.next_value::<String>()?;
                            value = Some(T::keyed(k, &text).map_err(de::Error::custom)?);
                        }
                        "note" if note.is_none() => note = Some(map.next_value::<String>()?),
                        other => return Err(de::Error::unknown_field(other, T::KEYS)),
                    }
                }
                let value = value.ok_or_else(|| de::Error::missing_field(T::KEYS[0]))?;
                // An empty note is no note.
                Ok(Noted { value, note: note.map(|n| n.trim().to_owned()).filter(|n| !n.is_empty()) })
            }
        }

        deserializer.deserialize_any(Entry(std::marker::PhantomData))
    }
}

/// The values of a list, without their notes.
pub fn values<T: Clone>(list: &[Noted<T>]) -> Vec<T> {
    list.iter().map(|entry| entry.value.clone()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Lists {
        nets: Vec<Noted<Ipv4Net>>,
        domains: Vec<Noted<String>>,
    }

    #[test]
    fn plain_and_noted_entries() {
        let text = r#"
nets = ["10.0.0.0/8", { net = "10.20.0.5/32", note = "Jira" }]
domains = ["corp.example", { domain = "*.saas.example", note = "  CRM  " }, { domain = "x.example", note = " " }]
"#;
        let lists: Lists = toml::from_str(text).unwrap();
        assert_eq!(lists.nets[0], "10.0.0.0/8".parse::<Ipv4Net>().unwrap());
        assert_eq!(lists.nets[1].note.as_deref(), Some("Jira"));
        assert_eq!(
            (lists.domains[1].value.as_str(), lists.domains[1].note.as_deref()),
            ("*.saas.example", Some("CRM"))
        );
        assert_eq!(lists.domains[2].note, None, "a blank note is none");
        // Written back in line: entries without a note stay strings.
        let written = toml::to_string(&lists).unwrap();
        assert!(written.contains(r#"nets = ["10.0.0.0/8", { net = "10.20.0.5/32", note = "Jira" }]"#), "{written}");
        assert_eq!(toml::from_str::<Lists>(&written).unwrap(), lists);
        // Every entry with a note: toml writes `[[nets]]` tables (the
        // profiles file puts them back in line), which read the same.
        let all = Lists { nets: vec![lists.nets[1].clone()], domains: vec![] };
        assert_eq!(toml::from_str::<Lists>(&toml::to_string(&all).unwrap()).unwrap(), all);
        // And through JSON, as profiles go to the daemon.
        let json = serde_json::to_string(&lists).unwrap();
        assert_eq!(serde_json::from_str::<Lists>(&json).unwrap(), lists);
    }

    #[test]
    fn malformed_entries_are_refused() {
        for bad in [
            r#"nets = [{ net = "10.0.0.0/8", nope = 1 }]"#,
            r#"nets = [{ note = "no network" }]"#,
            r#"nets = ["10.0.0.0/33"]"#,
            r#"nets = [{ domain = "corp.example" }]"#,
        ] {
            let text = format!("{bad}\ndomains = []");
            assert!(toml::from_str::<Lists>(&text).is_err(), "{bad}");
        }
        let long = Noted::new("x".to_owned(), Some("n".repeat(MAX_NOTE + 1)));
        assert!(long.check_note().is_err());
        assert!(Noted::new("x".to_owned(), Some("a\nb".into())).check_note().is_err());
    }
}
