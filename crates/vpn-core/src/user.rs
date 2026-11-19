//! Who is asking the service: a user id and whether the connection has
//! administrator rights. Sessions belong to the user who started them; an
//! administrator may act on everyone's.

use std::fmt;

/// A system account: a uid on macOS and Linux, a SID on Windows.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UserId {
    Uid(u32),
    /// String form, `S-1-5-21-…`.
    Sid(String),
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uid(uid) => write!(f, "uid {uid}"),
            Self::Sid(sid) => write!(f, "{sid}"),
        }
    }
}

/// The user on the other end of a connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct User {
    pub id: UserId,
    /// root; on Windows, SYSTEM or an elevated administrator. A property
    /// of the connection: the same Windows user may connect elevated or
    /// not.
    pub admin: bool,
}

impl User {
    /// A Unix user; root is the administrator.
    pub fn uid(uid: u32) -> Self {
        Self { id: UserId::Uid(uid), admin: uid == 0 }
    }

    /// May act on what `owner` started: its own, or anything for an
    /// administrator.
    pub fn may_act_for(&self, owner: &UserId) -> bool {
        self.admin || self.id == *owner
    }
}

impl fmt::Display for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.id, if self.admin { " (admin)" } else { "" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn administrators_act_for_everyone() {
        let alice = User::uid(501);
        let bob = User::uid(502);
        assert!(alice.may_act_for(&alice.id));
        assert!(!alice.may_act_for(&bob.id));
        assert!(User::uid(0).may_act_for(&bob.id));
        let elevated = User { id: UserId::Sid("S-1-5-21-1-2-3-1001".into()), admin: true };
        assert!(elevated.may_act_for(&bob.id));
        assert_eq!(elevated.to_string(), "S-1-5-21-1-2-3-1001 (admin)");
    }
}
