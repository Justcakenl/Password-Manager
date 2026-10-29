//! Bouwscript: bewaart in het programma uit welke git-versie (commit) het
//! gebouwd is. `kluis --update` vergelijkt dat met de nieuwste versie op GitHub.
//!
//! De PKGBUILD geeft de commit door via KLUIS_GIT_COMMIT; bij een gewone
//! `cargo build` vragen we het aan git zelf. Lukt dat niet, dan is het
//! "onbekend" (en biedt `kluis --update` altijd een update aan).

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=KLUIS_GIT_COMMIT");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");

    let from_env = std::env::var("KLUIS_GIT_COMMIT").ok().filter(|c| is_commit(c));
    let commit = from_env.or_else(|| {
        let out = Command::new("git").args(["rev-parse", "--short=12", "HEAD"]).output().ok()?;
        let c = String::from_utf8(out.stdout).ok()?.trim().to_string();
        (out.status.success() && is_commit(&c)).then_some(c)
    });
    println!("cargo:rustc-env=KLUIS_GIT_COMMIT={}", commit.unwrap_or_else(|| "onbekend".into()));
}

fn is_commit(s: &str) -> bool {
    (7..=40).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}
