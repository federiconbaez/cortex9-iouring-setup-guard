//! IORING_SETUP_* flag bits and names.

pub const IOPOLL: u32 = 1 << 0;
pub const SQPOLL: u32 = 1 << 1;
pub const SQ_AFF: u32 = 1 << 2;
pub const CQSIZE: u32 = 1 << 3;
pub const CLAMP: u32 = 1 << 4;
pub const ATTACH_WQ: u32 = 1 << 5;
pub const R_DISABLED: u32 = 1 << 6;
pub const SUBMIT_ALL: u32 = 1 << 7;
pub const COOP_TASKRUN: u32 = 1 << 8;
pub const TASKRUN_FLAG: u32 = 1 << 9;
pub const SQE128: u32 = 1 << 10;
pub const CQE32: u32 = 1 << 11;
pub const SINGLE_ISSUER: u32 = 1 << 12;
pub const DEFER_TASKRUN: u32 = 1 << 13;
pub const NO_MMAP: u32 = 1 << 14;
pub const REGISTERED_FD_ONLY: u32 = 1 << 15;
pub const NO_SQARRAY: u32 = 1 << 16;

pub fn parse(name: &str) -> Option<u32> {
    Some(match name {
        "IORING_SETUP_IOPOLL" => IOPOLL,
        "IORING_SETUP_SQPOLL" => SQPOLL,
        "IORING_SETUP_SQ_AFF" => SQ_AFF,
        "IORING_SETUP_CQSIZE" => CQSIZE,
        "IORING_SETUP_CLAMP" => CLAMP,
        "IORING_SETUP_ATTACH_WQ" => ATTACH_WQ,
        "IORING_SETUP_R_DISABLED" => R_DISABLED,
        "IORING_SETUP_SUBMIT_ALL" => SUBMIT_ALL,
        "IORING_SETUP_COOP_TASKRUN" => COOP_TASKRUN,
        "IORING_SETUP_TASKRUN_FLAG" => TASKRUN_FLAG,
        "IORING_SETUP_SQE128" => SQE128,
        "IORING_SETUP_CQE32" => CQE32,
        "IORING_SETUP_SINGLE_ISSUER" => SINGLE_ISSUER,
        "IORING_SETUP_DEFER_TASKRUN" => DEFER_TASKRUN,
        "IORING_SETUP_NO_MMAP" => NO_MMAP,
        "IORING_SETUP_REGISTERED_FD_ONLY" => REGISTERED_FD_ONLY,
        "IORING_SETUP_NO_SQARRAY" => NO_SQARRAY,
        _ => return None,
    })
}

pub fn name_of(bit: u32) -> Option<&'static str> {
    Some(match bit {
        IOPOLL => "IORING_SETUP_IOPOLL",
        SQPOLL => "IORING_SETUP_SQPOLL",
        SQ_AFF => "IORING_SETUP_SQ_AFF",
        CQSIZE => "IORING_SETUP_CQSIZE",
        CLAMP => "IORING_SETUP_CLAMP",
        ATTACH_WQ => "IORING_SETUP_ATTACH_WQ",
        R_DISABLED => "IORING_SETUP_R_DISABLED",
        SUBMIT_ALL => "IORING_SETUP_SUBMIT_ALL",
        COOP_TASKRUN => "IORING_SETUP_COOP_TASKRUN",
        TASKRUN_FLAG => "IORING_SETUP_TASKRUN_FLAG",
        SQE128 => "IORING_SETUP_SQE128",
        CQE32 => "IORING_SETUP_CQE32",
        SINGLE_ISSUER => "IORING_SETUP_SINGLE_ISSUER",
        DEFER_TASKRUN => "IORING_SETUP_DEFER_TASKRUN",
        NO_MMAP => "IORING_SETUP_NO_MMAP",
        REGISTERED_FD_ONLY => "IORING_SETUP_REGISTERED_FD_ONLY",
        NO_SQARRAY => "IORING_SETUP_NO_SQARRAY",
        _ => return None,
    })
}

/// Default deny-list for a hardened allowlist (dangerous / privileged).
pub fn default_deny_mask() -> u32 {
    SQPOLL | IOPOLL | NO_MMAP | DEFER_TASKRUN | SQ_AFF
}

/// Flags generally safe for unprivileged apps.
pub fn default_allow_mask() -> u32 {
    CLAMP | CQSIZE | SUBMIT_ALL | COOP_TASKRUN | SINGLE_ISSUER | R_DISABLED | NO_SQARRAY
}
