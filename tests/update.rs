//! Integratietests voor `kluis --update`.
//!
//! "GitHub" is hier een lokale bare git-repo; `makepkg` is een nepscript dat
//! alleen opschrijft dat het is aangeroepen. Zo wordt de echte logica
//! (git fetch, fast-forward, back-up, terugzetten bij een fout) getest, zonder
//! netwerk, root of pacman. De tests werken alleen in debug-builds, waar de
//! geïnstalleerde commit via KLUIS_TEST_INSTALLED_COMMIT te simuleren is.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command as Proc;
use std::time::Duration;

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;

const PW: &str = "tq8#vLp2!mZr9wXe";
const FAST_KDF: [&str; 6] = ["--kdf-memory", "8", "--kdf-iterations", "1", "--kdf-parallelism", "1"];

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Proc::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Test")
        .env("GIT_AUTHOR_EMAIL", "test@example.org")
        .env("GIT_COMMITTER_NAME", "Test")
        .env("GIT_COMMITTER_EMAIL", "test@example.org")
        .output()
        .expect("git draait");
    assert!(out.status.success(), "git {args:?} faalde: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

struct World {
    t: tempfile::TempDir,
}

impl World {
    /// Nep-GitHub + bronmap (`src`) + ontwikkelaarskopie (`dev`) + nep-makepkg.
    fn new() -> World {
        let w = World { t: tempfile::tempdir().unwrap() };
        let origin = w.path("origin.git");
        fs::create_dir(&origin).unwrap();
        git(&origin, &["init", "--bare", "--quiet", "-b", "main"]);
        git(w.t.path(), &["clone", "--quiet", origin.to_str().unwrap(), "src"]);
        let src = w.src();
        git(&src, &["checkout", "--quiet", "-b", "main"]);
        fs::create_dir_all(src.join("packaging/arch")).unwrap();
        fs::write(src.join("packaging/arch/PKGBUILD"), "# nep\n").unwrap();
        fs::write(src.join("README.md"), "versie 1\n").unwrap();
        git(&src, &["add", "-A"]);
        git(&src, &["commit", "--quiet", "-m", "Eerste versie"]);
        git(&src, &["push", "--quiet", "-u", "origin", "main"]);
        git(w.t.path(), &["clone", "--quiet", "-b", "main", origin.to_str().unwrap(), "dev"]);

        fs::create_dir(w.path("bin")).unwrap();
        let script = format!(
            "#!/bin/sh\necho \"$@ | $(pwd)\" >> '{log}'\n[ \"$1\" = \"--version\" ] && exit 0\n[ -f '{fail}' ] && exit 1\nexit 0\n",
            log = w.path("makepkg.log").display(),
            fail = w.path("makepkg-fail").display()
        );
        let bin = w.path("bin/makepkg");
        fs::write(&bin, script).unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        w
    }

    fn path(&self, p: &str) -> PathBuf {
        self.t.path().join(p)
    }
    fn src(&self) -> PathBuf {
        self.path("src")
    }
    fn vault(&self) -> PathBuf {
        self.path("data/vault.enc")
    }

    /// De commit die "geïnstalleerd" is (nu de kop van de bronmap).
    fn installed(&self) -> String {
        git(&self.src(), &["rev-parse", "--short=12", "HEAD"])
    }

    /// Een nieuwe versie "op GitHub" zetten.
    fn publish(&self, subject: &str) -> String {
        let dev = self.path("dev");
        git(&dev, &["pull", "--quiet", "--ff-only"]);
        let n = fs::read_to_string(dev.join("README.md")).unwrap().lines().count() + 1;
        fs::write(dev.join("README.md"), format!("versie {n}\n")).unwrap();
        git(&dev, &["add", "-A"]);
        git(&dev, &["commit", "--quiet", "-m", subject]);
        git(&dev, &["push", "--quiet", "origin", "main"]);
        git(&dev, &["rev-parse", "HEAD"])
    }

    fn kluis(&self, installed: &str) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_kluis"));
        let path = format!("{}:{}", self.path("bin").display(), std::env::var("PATH").unwrap_or_default());
        c.env("PATH", path)
            .env("NO_COLOR", "1")
            .env("KLUIS_VAULT", self.vault())
            .env("XDG_CACHE_HOME", self.path("cache"))
            .env("KLUIS_TEST_ALLOW_ROOT", "1")
            .env("KLUIS_TEST_INSTALLED_COMMIT", installed)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("DISPLAY")
            .timeout(Duration::from_secs(60));
        c
    }

    fn update(&self, installed: &str, args: &[&str]) -> Command {
        let mut c = self.kluis(installed);
        c.args(["--update", "--source"]).arg(self.src()).args(args);
        c
    }

    fn init_vault(&self, installed: &str) {
        self.kluis(installed)
            .arg("init")
            .args(FAST_KDF)
            .write_stdin(format!("{PW}\n{PW}\n"))
            .assert()
            .success();
        self.kluis(installed)
            .args(["add", "Bank", "-u", "jan", "--url", "https://bank.nl", "-t", "geld"])
            .write_stdin(format!("{PW}\nGeheim-Bank-PW-1!\n"))
            .assert()
            .success();
    }

    fn makepkg_calls(&self) -> Vec<String> {
        fs::read_to_string(self.path("makepkg.log"))
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.starts_with("--version"))
            .map(String::from)
            .collect()
    }

    fn backups(&self) -> Vec<String> {
        fs::read_dir(self.path("data"))
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .filter(|n| n.starts_with("vault.enc.voor-update-"))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn assert_vault_works(&self, installed: &str) {
        self.kluis(installed)
            .args(["get", "bank", "--show"])
            .write_stdin(format!("{PW}\n"))
            .assert()
            .success()
            .stdout(contains("Geheim-Bank-PW-1!"));
    }
}

#[test]
fn nieuwste_versie_geeft_geen_update() {
    let w = World::new();
    let installed = w.installed();
    w.update(&installed, &["--check"]).assert().success().stderr(contains("al de nieuwste versie"));
    assert!(w.makepkg_calls().is_empty());
}

#[test]
fn controleren_vindt_een_update_en_onthoudt_dat() {
    let w = World::new();
    let installed = w.installed();
    let new = w.publish("Mooie nieuwe functie");
    w.update(&installed, &["--check"])
        .assert()
        .success()
        .stderr(contains("Update beschikbaar (1 nieuwe wijziging(en))"));
    // Er is niets geïnstalleerd of binnengehaald in de werkmap.
    assert!(w.makepkg_calls().is_empty());
    assert_eq!(git(&w.src(), &["rev-parse", "HEAD"]), git(&w.src(), &["rev-parse", "origin/main~1"]));
    // Het resultaat staat in de cache, en `kluis info` laat het zien (zonder netwerk).
    let cache = fs::read_to_string(w.path("cache/kluis/update-status")).unwrap();
    assert!(cache.contains(&format!("remote={new}")));
    w.kluis(&installed).arg("info").assert().success().stdout(contains("kluis --update"));
    // Na een nieuwe controle zonder nieuws verdwijnt de melding weer.
    w.update(&new[..12], &["--check"]).assert().success();
    w.kluis(&new[..12]).arg("info").assert().success().stdout(contains("geen bekende nieuwe versie"));
    // --notify zonder notify-send in PATH is geen fout.
    w.update(&installed, &["--check", "--notify"]).assert().success();
}

#[test]
fn volledige_update_laat_de_kluis_ongemoeid() {
    let w = World::new();
    let installed = w.installed();
    w.init_vault(&installed);
    let before = fs::read(w.vault()).unwrap();
    let new = w.publish("Nieuwe functie");

    w.update(&installed, &["--yes"])
        .assert()
        .success()
        .stderr(
            contains("Er is een nieuwe versie")
                .and(contains("Nieuwe functie"))
                .and(contains("Extra back-up")),
        )
        .stderr(contains("CakePass is bijgewerkt"));

    // Nieuwe code is binnengehaald (alleen vooruit), en makepkg draaide in packaging/arch.
    assert_eq!(git(&w.src(), &["rev-parse", "HEAD"]), new);
    let calls = w.makepkg_calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert!(
        calls[0].starts_with("-s -i -f --noconfirm | ") && calls[0].ends_with("packaging/arch"),
        "{calls:?}"
    );
    // De kluis is byte voor byte gelijk, er is een identieke extra back-up (rechten 600), en alles opent nog.
    assert_eq!(fs::read(w.vault()).unwrap(), before);
    let backups = w.backups();
    assert_eq!(backups.len(), 1);
    let backup = w.path("data").join(&backups[0]);
    assert_eq!(fs::read(&backup).unwrap(), before);
    assert_eq!(fs::metadata(&backup).unwrap().permissions().mode() & 0o777, 0o600);
    w.assert_vault_works(&new[..12]);
    // De back-up opent ook los.
    Command::new(env!("CARGO_BIN_EXE_kluis"))
        .args(["--vault", backup.to_str().unwrap(), "list"])
        .write_stdin(format!("{PW}\n"))
        .assert()
        .success()
        .stdout(contains("Bank"));
    // Daarna is er niets meer te doen.
    w.update(&new[..12], &[]).assert().success().stderr(contains("al de nieuwste versie"));
}

#[test]
fn zonder_ja_gebeurt_er_niets() {
    let w = World::new();
    let installed = w.installed();
    w.init_vault(&installed);
    w.publish("Nieuwe functie");
    let head = git(&w.src(), &["rev-parse", "HEAD"]);
    w.update(&installed, &[]).write_stdin("n\n").assert().success().stderr(contains("Niets gewijzigd"));
    assert_eq!(git(&w.src(), &["rev-parse", "HEAD"]), head);
    assert!(w.makepkg_calls().is_empty() && w.backups().is_empty());
    // Met "j" gaat het door (zonder --noconfirm: pacman vraagt zelf nog).
    w.update(&installed, &[]).write_stdin("j\n").assert().success().stderr(contains("bijgewerkt"));
    assert_eq!(w.makepkg_calls().len(), 1);
    assert!(!w.makepkg_calls()[0].contains("--noconfirm"));
}

#[test]
fn mislukte_bouw_zet_alles_terug() {
    let w = World::new();
    let installed = w.installed();
    w.init_vault(&installed);
    let before = fs::read(w.vault()).unwrap();
    let head = git(&w.src(), &["rev-parse", "HEAD"]);
    w.publish("Kapotte versie");
    fs::write(w.path("makepkg-fail"), "").unwrap();

    w.update(&installed, &["--yes"])
        .assert()
        .failure()
        .stderr(contains("het bijwerken is mislukt").and(contains("je kluis is veilig")));
    assert_eq!(git(&w.src(), &["rev-parse", "HEAD"]), head, "bronmap is teruggezet");
    assert_eq!(fs::read(w.vault()).unwrap(), before);
    assert_eq!(w.backups().len(), 1, "back-up is gemaakt vóór het proberen");
    w.assert_vault_works(&installed);
    // Als het later wel lukt, werkt een nieuwe poging.
    fs::remove_file(w.path("makepkg-fail")).unwrap();
    w.update(&installed, &["--yes"]).assert().success();
}

#[test]
fn lokale_wijzigingen_worden_nooit_overschreven() {
    let w = World::new();
    let installed = w.installed();
    w.publish("Nieuwe functie");
    fs::write(w.src().join("README.md"), "mijn eigen wijziging\n").unwrap();
    w.update(&installed, &["--yes"]).assert().failure().stderr(contains("lokale wijzigingen"));
    assert_eq!(fs::read_to_string(w.src().join("README.md")).unwrap(), "mijn eigen wijziging\n");
    assert!(w.makepkg_calls().is_empty() && w.backups().is_empty());
}

#[test]
fn afwijkende_geschiedenis_wordt_nooit_herschreven() {
    let w = World::new();
    let installed = w.installed();
    fs::write(w.src().join("eigen.txt"), "lokaal\n").unwrap();
    git(&w.src(), &["add", "-A"]);
    git(&w.src(), &["commit", "--quiet", "-m", "Mijn eigen commit"]);
    let mine = git(&w.src(), &["rev-parse", "HEAD"]);
    w.publish("Iets anders op GitHub");
    w.update(&installed, &["--yes"]).assert().failure().stderr(contains("wijkt af van GitHub"));
    assert_eq!(git(&w.src(), &["rev-parse", "HEAD"]), mine);
    assert!(w.makepkg_calls().is_empty());
}

#[test]
fn onveilige_tekens_in_commits_worden_onschadelijk() {
    let w = World::new();
    let installed = w.installed();
    w.publish("Gemene \u{1b}[2J\u{1b}[31m titel \u{7}");
    let out = w.update(&installed, &["--yes"]).assert().success();
    let o = out.get_output();
    assert!(!o.stderr.contains(&0x1b) && !o.stderr.contains(&0x07), "geen stuurtekens in de uitvoer");
    assert!(String::from_utf8_lossy(&o.stderr).contains("Gemene"));
}

#[test]
fn bereikbaarheid_en_bronmap_fouten() {
    let w = World::new();
    let installed = w.installed();
    // Ongeldige bronmap.
    w.kluis(&installed)
        .args(["--update", "--source", "/tmp"])
        .assert()
        .failure()
        .stderr(contains("geen CakePass-bronmap"));
    // GitHub onbereikbaar: nette fout, niets verandert.
    git(&w.src(), &["remote", "set-url", "origin", w.path("bestaat-niet.git").to_str().unwrap()]);
    w.update(&installed, &["--check"]).assert().failure().stderr(contains("git fetch mislukte"));
    assert!(w.makepkg_calls().is_empty());
}

#[test]
fn niet_binnen_de_kluis_shell() {
    let w = World::new();
    let installed = w.installed();
    w.init_vault(&installed);
    w.kluis(&installed)
        .arg("shell")
        .write_stdin(format!("{PW}\nupdate\nexit\n"))
        .assert()
        .success()
        .stderr(contains("sluit eerst de kluis"));
}

#[test]
fn update_opent_de_kluis_nooit() {
    // Zonder kluis en zonder wachtwoordvraag: update werkt, en vraagt nergens om een wachtwoord.
    let w = World::new();
    let installed = w.installed();
    w.publish("Nieuwe functie");
    w.update(&installed, &["--yes"])
        .assert()
        .success()
        .stderr(contains("Hoofdwachtwoord").not().and(contains("geen back-up nodig")));
}

#[test]
fn versie_bevat_de_commit() {
    Command::new(env!("CARGO_BIN_EXE_kluis"))
        .arg("--version")
        .assert()
        .success()
        .stdout(contains(env!("CARGO_PKG_VERSION")).and(contains("commit ")));
}
