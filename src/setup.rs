//! Thin io_uring_setup wrapper that applies the guard first.

use crate::flags;
use crate::guard::{Decision, Guard};
use serde::Serialize;
use std::io;

const SYS_IO_URING_SETUP: libc::c_long = 425;

#[derive(Debug, Clone, Serialize)]
pub struct SetupResult {
    pub flags: u32,
    pub decision: String,
    pub fd_or_errno: i32,
    pub note: String,
}

pub fn try_setup(guard: &Guard, entries: u32, flags: u32, actually_call: bool) -> io::Result<SetupResult> {
    match guard.check(flags) {
        Decision::Deny { matched } => Ok(SetupResult {
            flags,
            decision: "deny".into(),
            fd_or_errno: -libc::EPERM,
            note: format!(
                "blocked bits={matched:#x} ({})",
                flags::name_of(matched).unwrap_or("mixed")
            ),
        }),
        Decision::Allow => {
            if !actually_call {
                return Ok(SetupResult {
                    flags,
                    decision: "allow".into(),
                    fd_or_errno: 0,
                    note: "dry-run".into(),
                });
            }
            let mut params = vec![0u8; 256];
            // flags go at offset 0 of io_uring_params as __u32 flags
            params[0..4].copy_from_slice(&flags.to_le_bytes());
            let fd = unsafe { libc::syscall(SYS_IO_URING_SETUP, entries as usize, params.as_mut_ptr()) };
            if fd < 0 {
                let err = io::Error::last_os_error();
                // SQPOLL often EPERM for unprivileged — document, don't silent-skip
                Ok(SetupResult {
                    flags,
                    decision: "allow".into(),
                    fd_or_errno: -err.raw_os_error().unwrap_or(1),
                    note: format!("kernel rejected setup: {err}"),
                })
            } else {
                unsafe { libc::close(fd as i32) };
                Ok(SetupResult {
                    flags,
                    decision: "allow".into(),
                    fd_or_errno: fd as i32,
                    note: "setup ok (fd closed)".into(),
                })
            }
        }
    }
}
