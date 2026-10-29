//! Build script: records which git version (commit) the program was built
//! from. `cakepass --update` compares that with the newest version on GitHub.
//!
//! The PKGBUILD passes the commit via CAKEPASS_GIT_COMMIT; with a plain
//! `cargo build` we ask git ourselves. If that fails the value is "unknown"
//! (and `cakepass --update` will then always offer an update).

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=CAKEPASS_GIT_COMMIT");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");

    let from_env = std::env::var("CAKEPASS_GIT_COMMIT").ok().filter(|c| is_commit(c));
    let commit = from_env.or_else(|| {
        let out = Command::new("git").args(["rev-parse", "--short=12", "HEAD"]).output().ok()?;
        let c = String::from_utf8(out.stdout).ok()?.trim().to_string();
        (out.status.success() && is_commit(&c)).then_some(c)
    });
    println!("cargo:rustc-env=CAKEPASS_GIT_COMMIT={}", commit.unwrap_or_else(|| "unknown".into()));
}

fn is_commit(s: &str) -> bool {
    (7..=40).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_hexdigit())
}
