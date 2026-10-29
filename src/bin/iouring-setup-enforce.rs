//! Fail hard if io_uring_setup itself cannot run (baseline).

use std::process::ExitCode;

fn main() -> ExitCode {
    let release =
        std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_else(|_| "unknown".into());
    println!("kernel={}", release.trim());
    match iouring_setup_guard::try_setup(&iouring_setup_guard::Guard::default(), 8, 0, true) {
        Ok(r) if r.fd_or_errno >= 0 => {
            println!("io_uring_setup=ok");
            ExitCode::SUCCESS
        }
        Ok(r) => {
            eprintln!("io_uring_setup=FAIL errno={}", r.fd_or_errno);
            eprintln!("refusing to skip");
            ExitCode::from(2)
        }
        Err(e) => {
            eprintln!("io_uring_setup=FAIL: {e}");
            ExitCode::from(2)
        }
    }
}
