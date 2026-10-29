//! `kluis` – offline, versleutelde wachtwoordmanager voor de terminal.

mod cli;

use std::process::ExitCode;

use clap::{CommandFactory, FromArgMatches};

/// BEVEILIGING: alle vrijgegeven geheugen wordt eerst met nullen overschreven.
#[global_allocator]
static GLOBAL: kluis::secure_mem::ZeroizingAllocator = kluis::secure_mem::ZeroizingAllocator;

fn main() -> ExitCode {
    // BEVEILIGING: als allereerste core dumps uitzetten en het proces
    // niet-dumpbaar maken, vóórdat er ook maar één geheim in het geheugen staat.
    let hardening = kluis::secure_mem::harden_process();
    cli::commands::set_hardening(hardening);

    // Verborgen hulpproces dat na 20 s het klembord wist (zie clipboard.rs).
    // Bewust buiten clap gehouden, zodat het niet in hulp of completions staat.
    let mut argv = std::env::args_os();
    if argv.nth(1).as_deref() == Some(std::ffi::OsStr::new(kluis::clipboard::HELPER_ARG)) {
        let tool = argv.next().and_then(|t| kluis::clipboard::Tool::from_name(&t.to_string_lossy()));
        return match tool.map(|t| kluis::clipboard::run_clear_helper(t, kluis::clipboard::CLEAR_AFTER_SECS)) {
            Some(Ok(())) => ExitCode::SUCCESS,
            _ => ExitCode::FAILURE,
        };
    }

    let matches = cli::args::localize(cli::args::Cli::command()).get_matches();
    let args = cli::args::Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    cli::ui::init(args.no_color);
    match cli::commands::run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(kluis::Error::Cancelled) => {
            cli::ui::info("Afgebroken.");
            ExitCode::from(130)
        }
        Err(e) => {
            cli::ui::error(&e.to_string());
            ExitCode::FAILURE
        }
    }
}
