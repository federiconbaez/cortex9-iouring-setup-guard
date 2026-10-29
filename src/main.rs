use clap::{Parser, Subcommand};
use iouring_setup_guard::flags;
use iouring_setup_guard::{embedded_catalog, try_setup, Guard};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "iouring-setup-guard",
    about = "Allowlist de flags de io_uring_setup + catálogo residual"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    Check {
        #[arg(long, default_value_t = 0)]
        flags: u32,
        #[arg(long)]
        flag_name: Option<String>,
        #[arg(long, default_value_t = false)]
        call_kernel: bool,
    },
    Catalog,
    Measure {
        #[arg(long, default_value_t = 50)]
        runs: u32,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let guard = Guard::default();
    match cli.cmd {
        Cmd::Check {
            mut flags,
            flag_name,
            call_kernel,
        } => {
            if let Some(n) = flag_name {
                flags = match iouring_setup_guard::flags::parse(&n) {
                    Some(b) => b,
                    None => {
                        eprintln!("unknown flag {n}");
                        return ExitCode::from(1);
                    }
                };
            }
            match try_setup(&guard, 8, flags, call_kernel) {
                Ok(r) => {
                    println!(
                        "decision={} flags={:#x} fd_or_errno={} note={}",
                        r.decision, r.flags, r.fd_or_errno, r.note
                    );
                    if r.decision == "deny" {
                        ExitCode::from(1)
                    } else {
                        ExitCode::SUCCESS
                    }
                }
                Err(e) => {
                    eprintln!("{e}");
                    ExitCode::from(2)
                }
            }
        }
        Cmd::Catalog => {
            let c = embedded_catalog();
            println!("entries={}", c.len());
            for e in &c {
                println!("{} | {} | {} | {}", e.id, e.kind, e.surface, e.evidence);
            }
            if c.len() >= 10 {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Cmd::Measure { runs } => {
            let mut blocked = 0u32;
            for _ in 0..runs {
                let r = try_setup(&guard, 8, flags::SQPOLL, false).unwrap();
                if r.decision == "deny" {
                    blocked += 1;
                }
            }
            let clean = try_setup(&guard, 8, 0, true).unwrap();
            println!(
                "deny_list_block={blocked}/{runs} clean_setup={} note={}",
                clean.decision, clean.note
            );
            if blocked == runs && clean.decision == "allow" && clean.fd_or_errno >= 0 {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
    }
}
