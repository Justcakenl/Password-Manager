//! `cakepass` – offline, encrypted password manager for the terminal.

mod cli;

use std::process::ExitCode;

use clap::FromArgMatches;

/// SECURITY: all released memory is overwritten with zeros first.
#[global_allocator]
static GLOBAL: cakepass::secure_mem::ZeroizingAllocator = cakepass::secure_mem::ZeroizingAllocator;

fn main() -> ExitCode {
    // SECURITY: first of all, disable core dumps and make the process
    // non-dumpable, before a single secret is in memory.
    let hardening = cakepass::secure_mem::harden_process();
    cli::commands::set_hardening(hardening);

    // Hidden helper process that clears the clipboard after 20 s (see clipboard.rs).
    // Deliberately kept outside clap, so it does not show up in help or completions.
    let mut argv = std::env::args_os();
    if argv.nth(1).as_deref() == Some(std::ffi::OsStr::new(cakepass::clipboard::HELPER_ARG)) {
        let tool = argv.next().and_then(|t| cakepass::clipboard::Tool::from_name(&t.to_string_lossy()));
        return match tool
            .map(|t| cakepass::clipboard::run_clear_helper(t, cakepass::clipboard::CLEAR_AFTER_SECS))
        {
            Some(Ok(())) => ExitCode::SUCCESS,
            _ => ExitCode::FAILURE,
        };
    }

    // `cakepass --update` is the familiar spelling; internally it is the command `update`.
    let argv: Vec<std::ffi::OsString> = std::env::args_os()
        .map(|a| if a == "--update" { std::ffi::OsString::from("update") } else { a })
        .collect();
    let matches = cli::args::command().get_matches_from(argv);
    let args = cli::args::Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());
    cli::ui::init(args.no_color);
    // The animation follows the saved setting, unless `--no-animation` is given.
    cli::logo::set_animation(cli::config::load().animation && !args.no_animation);
    match cli::commands::run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(cakepass::Error::Cancelled) => {
            cli::ui::info("Cancelled.");
            ExitCode::from(130)
        }
        Err(e) => {
            cli::ui::error(&e.to_string());
            ExitCode::FAILURE
        }
    }
}
