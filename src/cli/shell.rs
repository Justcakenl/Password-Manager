//! `kluis shell`: één keer ontgrendelen, daarna opdrachten typen.
//!
//! BEVEILIGING: als er `timeout` seconden geen invoer komt, wordt de kluis
//! automatisch vergrendeld: de sleutel en alle ontsleutelde gegevens worden
//! uit het geheugen gewist en het programma stopt. Voor `passwd` en
//! `export` vraagt de shell het hoofdwachtwoord opnieuw.

use std::io::{self, Write};

use clap::{CommandFactory, FromArgMatches};

use kluis::storage::VaultPaths;
use kluis::{Error, Result};

use super::args::{ShellLine, localize};
use super::{commands, prompt, ui};

const MAX_TIMEOUT: u64 = 24 * 60 * 60;

enum Wait {
    Ready,
    TimedOut,
}

/// Wacht maximaal `secs` seconden tot er invoer op stdin staat.
fn wait_for_input(secs: u64) -> Result<Wait> {
    let mut fds = libc::pollfd { fd: 0, events: libc::POLLIN, revents: 0 };
    let ms = i32::try_from(secs * 1000).unwrap_or(i32::MAX);
    loop {
        // SAFETY: één geldige pollfd-struct.
        let r = unsafe { libc::poll(&mut fds, 1, ms) };
        if r > 0 {
            return Ok(Wait::Ready); // invoer, of einde invoer (POLLHUP)
        }
        if r == 0 {
            return Ok(Wait::TimedOut);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err.into());
        }
    }
}

/// Waakhond: vergrendelt ook als je midden in een vraag (bijv. "Gebruikersnaam:"
/// of een verborgen wachtwoordprompt) wegloopt. Het proces stopt dan direct;
/// het besturingssysteem geeft al het geheugen vrij (en wist pagina's voordat
/// een ander proces ze krijgt). De terminalinstellingen worden eerst hersteld.
fn start_watchdog(timeout: u64, human: String) {
    // SAFETY: termios is een gewone C-struct; tcgetattr vult hem in.
    let saved = unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        (libc::isatty(0) == 1 && libc::tcgetattr(0, &mut t) == 0).then_some(t)
    };
    prompt::mark_activity();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            // Iets ruimer dan de timeout, zodat bij de gewone `kluis>`-prompt de
            // nette route (met expliciet wissen) eerst aan de beurt is.
            if prompt::idle_secs() > timeout + 2 {
                if let Some(t) = saved {
                    // SAFETY: geldige termios die we eerder zelf hebben gelezen.
                    unsafe {
                        libc::tcsetattr(0, libc::TCSANOW, &t);
                    }
                }
                eprintln!();
                ui::info(&format!("Automatisch vergrendeld na {human} zonder invoer."));
                std::process::exit(0);
            }
        }
    });
}

fn print_help() {
    let help = localize(ShellLine::command()).render_help();
    eprintln!("{help}");
    eprintln!("Verder: help, exit/quit/lock (vergrendelen en stoppen).");
    eprintln!("Namen met spaties zet je tussen aanhalingstekens: get \"Mijn Bank\"");
}

pub fn run(paths: &VaultPaths, timeout: u64) -> Result<()> {
    if timeout == 0 || timeout > MAX_TIMEOUT {
        return Err(Error::InvalidInput("de timeout moet tussen 1 en 86400 seconden liggen".into()));
    }
    let mut uv = commands::unlock(paths)?;
    let human =
        if timeout.is_multiple_of(60) { format!("{} min", timeout / 60) } else { format!("{timeout} s") };
    ui::success(&format!(
        "Kluis ontgrendeld. Typ 'help' voor de opdrachten of 'exit' om te vergrendelen. \
         Na {human} zonder invoer vergrendelt de kluis vanzelf."
    ));

    start_watchdog(timeout, human.clone());
    loop {
        eprint!("kluis> ");
        io::stderr().flush()?;
        if let Wait::TimedOut = wait_for_input(timeout)? {
            eprintln!();
            ui::info(&format!("Automatisch vergrendeld na {human} zonder invoer."));
            break;
        }
        let Some(line) = prompt::read_raw_line()? else {
            eprintln!();
            break; // Ctrl+D of einde invoer
        };
        let line = line.trim();
        match line {
            "" => continue,
            "exit" | "quit" | "lock" | "q" => break,
            "help" | "?" => {
                print_help();
                continue;
            }
            _ => {}
        }
        let Some(words) = shlex::split(line) else {
            ui::error("ongeldige aanhalingstekens");
            continue;
        };
        let argv = std::iter::once("kluis".to_string()).chain(words);
        let parsed = localize(ShellLine::command())
            .try_get_matches_from(argv)
            .and_then(|m| ShellLine::from_arg_matches(&m));
        match parsed {
            Ok(parsed) => match commands::execute(&mut uv, parsed.command, true) {
                Ok(()) => {}
                Err(Error::Cancelled) => ui::info("Afgebroken."),
                Err(Error::ConcurrentModification) => {
                    ui::error(
                        "de kluis is buiten deze shell gewijzigd. Sluit de shell (exit) en open \
                         hem opnieuw; je laatste wijziging is niet opgeslagen.",
                    );
                }
                Err(e) => ui::error(&e.to_string()),
            },
            Err(e) => {
                let _ = e.print();
            }
        }
    }
    drop(uv);
    ui::success("Kluis vergrendeld; de sleutel is uit het geheugen gewist.");
    Ok(())
}
