//! Allowlist / denylist check for io_uring_setup flags.

use crate::flags;
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct Guard {
    pub allow_mask: u32,
    pub deny_mask: u32,
}

impl Default for Guard {
    fn default() -> Self {
        Self {
            allow_mask: flags::default_allow_mask(),
            deny_mask: flags::default_deny_mask(),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny { matched: u32 },
}

impl Guard {
    pub fn check(&self, setup_flags: u32) -> Decision {
        let hit = setup_flags & self.deny_mask;
        if hit != 0 {
            return Decision::Deny { matched: hit };
        }
        // Any bit outside allow_mask (and not zero) is also denied when
        // unknown — conservative: deny bits that are neither allowed nor
        // explicitly catalogued as deny? Keep simple: deny_mask is authoritative;
        // bits outside allow∪deny are allowed only if allow_mask is not exclusive.
        // Policy: deny_mask wins; otherwise allow.
        let _ = self.allow_mask;
        Decision::Allow
    }

    pub fn check_strict(&self, setup_flags: u32) -> Decision {
        let hit = setup_flags & self.deny_mask;
        if hit != 0 {
            return Decision::Deny { matched: hit };
        }
        let unknown = setup_flags & !(self.allow_mask | self.deny_mask);
        if unknown != 0 {
            return Decision::Deny { matched: unknown };
        }
        Decision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqpoll_denied() {
        let g = Guard::default();
        match g.check(flags::SQPOLL) {
            Decision::Deny { matched } => assert_eq!(matched, flags::SQPOLL),
            Decision::Allow => panic!("SQPOLL must deny"),
        }
    }

    #[test]
    fn clean_allowed() {
        let g = Guard::default();
        assert_eq!(g.check(0), Decision::Allow);
        assert_eq!(g.check(flags::CLAMP | flags::CQSIZE), Decision::Allow);
    }

    #[test]
    fn fifty_deny_runs() {
        let g = Guard::default();
        for _ in 0..50 {
            assert!(matches!(
                g.check(flags::SQPOLL | flags::NO_MMAP),
                Decision::Deny { .. }
            ));
        }
    }
}
