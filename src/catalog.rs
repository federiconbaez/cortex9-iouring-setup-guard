//! Residual surface catalog (≥10). Entries cite iouring-lab RATIONALE.md
//! (leído 2026-10-29) and public NVD pages named there.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub id: String,
    pub kind: String,
    pub surface: String,
    pub note: String,
    pub evidence: String,
}

pub fn embedded_catalog() -> Vec<CatalogEntry> {
    vec![
        e("CVE-2022-3910", "opcode", "IORING_OP_MSG_RING", "RATIONALE: exploited MSG_RING / kCTF", "https://nvd.nist.gov/vuln/detail/CVE-2022-3910"),
        e("CVE-2022-29582", "opcode", "IORING_OP_LINK_TIMEOUT", "RATIONALE: LINK_TIMEOUT exploited", "https://nvd.nist.gov/vuln/detail/CVE-2022-29582"),
        e("CVE-2021-41073", "register", "IORING_REGISTER_BUFFERS", "RATIONALE: provided-buffer cluster (Pwn2Own)", "https://nvd.nist.gov/vuln/detail/CVE-2021-41073"),
        e("CVE-2022-2602", "register", "IORING_REGISTER_FILES", "RATIONALE: fixed file table cluster", "https://nvd.nist.gov/vuln/detail/CVE-2022-2602"),
        e("CVE-2023-1872", "register", "IORING_REGISTER_FILES", "RATIONALE: fixed file table", "https://nvd.nist.gov/vuln/detail/CVE-2023-1872"),
        e("CVE-2023-2236", "register", "IORING_REGISTER_FILES", "RATIONALE: fixed file table", "https://nvd.nist.gov/vuln/detail/CVE-2023-2236"),
        e("CVE-2023-2598", "opcode", "IORING_OP_READ_FIXED", "RATIONALE: fixed buffers exploited", "https://nvd.nist.gov/vuln/detail/CVE-2023-2598"),
        e("CVE-2023-2430", "opcode", "IORING_OP_MSG_RING", "RATIONALE: MSG_RING history", "https://nvd.nist.gov/vuln/detail/CVE-2023-2430"),
        e("CVE-2023-3389", "opcode", "IORING_OP_LINK_TIMEOUT", "RATIONALE: LINK_TIMEOUT", "https://nvd.nist.gov/vuln/detail/CVE-2023-3389"),
        e("setup-flags-share", "setup_flag", "IORING_SETUP_*", "RATIONALE: ~12% of 43 CNA CVEs 2024-02..2026-09 reachable via setup flags (5/43)", "https://github.com/gvozdetsky/iouring-lab/blob/main/profile/RATIONALE.md"),
        e("kctf-setup-flags", "setup_flag", "IORING_SETUP_*", "RATIONALE: 2/23 kCTF-exploited io_uring CVEs via setup flags", "https://github.com/gvozdetsky/iouring-lab/blob/main/profile/RATIONALE.md"),
        e("SQPOLL-surface", "setup_flag", "IORING_SETUP_SQPOLL", "Privileged SQ poll thread; not covered by opcode cBPF filters", "https://man7.org/linux/man-pages/man7/io_uring_setup_flags.7.html"),
    ]
}

fn e(id: &str, kind: &str, surface: &str, note: &str, evidence: &str) -> CatalogEntry {
    CatalogEntry {
        id: id.into(),
        kind: kind.into(),
        surface: surface.into(),
        note: note.into(),
        evidence: evidence.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn at_least_ten() {
        assert!(embedded_catalog().len() >= 10);
    }
}
