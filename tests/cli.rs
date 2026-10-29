//! Integratietests: draaien het echte `kluis`-programma met invoer via stdin.
//!
//! Alle tests gebruiken een tijdelijke map en lichte Argon2-instellingen
//! (8 MiB, t=1) zodat ze snel zijn. Er wordt nooit een klembord gebruikt.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;

/// Testwachtwoorden (alleen voor tests; zijn sterk genoeg voor zxcvbn).
const PW: &str = "tq8#vLp2!mZr9wXe";
const PW2: &str = "grape-lantern-oyster-bulky-scenic-dwarf";
const ITEM_PW: &str = "Item-Geheim-7731!";
const FAST_KDF: [&str; 6] = ["--kdf-memory", "8", "--kdf-iterations", "1", "--kdf-parallelism", "1"];

struct Kluis {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl Kluis {
    fn new() -> Kluis {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.enc");
        Kluis { _dir: dir, path }
    }

    fn dir(&self) -> &Path {
        self.path.parent().unwrap()
    }

    fn cmd(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_kluis"));
        c.env("KLUIS_VAULT", &self.path)
            .env("NO_COLOR", "1")
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("DISPLAY")
            .timeout(Duration::from_secs(60));
        c
    }

    fn init(self) -> Kluis {
        self.cmd()
            .arg("init")
            .args(FAST_KDF)
            .write_stdin(format!("{PW}\n{PW}\n"))
            .assert()
            .success()
            .stderr(contains("Kluis gemaakt"));
        self
    }

    fn add(&self, name: &str, user: &str, password: &str) {
        self.cmd()
            .args(["add", name, "--username", user, "--url", "https://example.org", "--tags", "werk,test"])
            .write_stdin(format!("{PW}\n{password}\n"))
            .assert()
            .success();
    }

    fn run(&self, args: &[&str], stdin: &str) -> assert_cmd::assert::Assert {
        self.cmd().args(args).write_stdin(stdin.to_string()).assert()
    }
}

#[test]
fn init_maakt_kluis_met_juiste_rechten() {
    use std::os::unix::fs::PermissionsExt;
    let k = Kluis::new().init();
    let mode = std::fs::metadata(&k.path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    // Een tweede init overschrijft niets.
    k.run(&["init"], &format!("{PW}\n{PW}\n")).failure().stderr(contains("overschrijf het niet"));
}

#[test]
fn zwak_of_ongelijk_hoofdwachtwoord_wordt_geweigerd() {
    let k = Kluis::new();
    k.run(&["init", FAST_KDF[0], FAST_KDF[1]], "wachtwoord123\nwachtwoord123\n")
        .failure()
        .stderr(contains("te zwak"));
    k.run(&["init", FAST_KDF[0], FAST_KDF[1]], &format!("{PW}\n{PW}x\n"))
        .failure()
        .stderr(contains("komen niet overeen"));
    assert!(!k.path.exists());
}

#[test]
fn toevoegen_ophalen_en_tonen() {
    let k = Kluis::new().init();
    k.add("GitHub", "jan", ITEM_PW);

    // Zonder --show: wachtwoord nooit in de uitvoer; geen klembord → fout.
    k.run(&["get", "github"], &format!("{PW}\n"))
        .failure()
        .stdout(contains("jan").and(contains(ITEM_PW).not()))
        .stderr(contains("geen klembord").and(contains(ITEM_PW).not()));
    k.run(&["get", "github", "--no-copy"], &format!("{PW}\n")).success().stdout(contains(ITEM_PW).not());

    // Met --show: expliciet gevraagd.
    k.run(&["get", "GITHUB", "--show"], &format!("{PW}\n")).success().stdout(contains(ITEM_PW));

    // list en search tonen geen wachtwoorden.
    k.run(&["list"], &format!("{PW}\n")).success().stdout(contains("GitHub").and(contains(ITEM_PW).not()));
    k.run(&["search", "examp"], &format!("{PW}\n")).success().stdout(contains("GitHub"));
    k.run(&["search", ITEM_PW], &format!("{PW}\n")).success().stderr(contains("Niets gevonden"));
    k.run(&["list", "--tag", "WERK"], &format!("{PW}\n")).success().stdout(contains("GitHub"));
    k.run(&["list", "--tag", "prive"], &format!("{PW}\n")).success().stderr(contains("Geen items"));

    // Dubbele naam wordt geweigerd.
    k.run(&["add", "github", "-u", "x", "--url", "", "-t", ""], &format!("{PW}\nx\n"))
        .failure()
        .stderr(contains("bestaat al"));
}

#[test]
fn interactief_toevoegen_met_gegenereerd_wachtwoord() {
    let k = Kluis::new().init();
    // gebruikersnaam, url, tags, notities, wachtwoord (leeg = genereren)
    k.run(&["add", "Mail"], &format!("{PW}\nik@mail.nl\nhttps://mail.nl\npriv\ngeheime notitie\n\n"))
        .success()
        .stderr(contains("gegenereerd (24 tekens"));
    let out = k.run(&["get", "mail", "--show"], &format!("{PW}\n")).success().get_output().stdout.clone();
    let out = String::from_utf8(out).unwrap();
    assert!(out.contains("geheime notitie"));
    let pw_line = out.lines().find(|l| l.starts_with("Wachtwoord:")).unwrap();
    assert_eq!(pw_line.trim_start_matches("Wachtwoord:").trim().chars().count(), 24);
}

#[test]
fn bewerken_en_verwijderen() {
    let k = Kluis::new().init();
    k.add("GitHub", "jan", ITEM_PW);
    k.run(
        &["edit", "github", "--username", "piet", "--rename", "GitLab", "--password"],
        &format!("{PW}\nNieuw-PW-99\n"),
    )
    .success();
    k.run(&["get", "gitlab", "--show"], &format!("{PW}\n"))
        .success()
        .stdout(contains("piet").and(contains("Nieuw-PW-99")));
    k.run(&["get", "github", "--show"], &format!("{PW}\n")).failure().stderr(contains("geen item"));

    // Zonder bevestiging gebeurt er niets.
    k.run(&["rm", "gitlab"], &format!("{PW}\nn\n")).success().stderr(contains("Niets verwijderd"));
    k.run(&["rm", "gitlab"], &format!("{PW}\nj\n")).success();
    k.run(&["list"], &format!("{PW}\n")).success().stderr(contains("leeg"));
    k.run(&["rm", "bestaatniet", "-y"], &format!("{PW}\n")).failure();
}

#[test]
fn verkeerd_hoofdwachtwoord_faalt_altijd() {
    let k = Kluis::new().init();
    k.add("GitHub", "jan", ITEM_PW);
    for wrong in ["", "fout", &PW[..PW.len() - 1], &format!("{PW} "), &PW.to_uppercase()] {
        k.run(&["get", "github", "--show"], &format!("{wrong}\n"))
            .failure()
            .stdout(contains(ITEM_PW).not())
            .stderr(contains("verkeerd hoofdwachtwoord"));
    }
}

#[test]
fn gemanipuleerd_of_kapot_bestand_faalt_netjes() {
    let k = Kluis::new().init();
    k.add("GitHub", "jan", ITEM_PW);
    let good = std::fs::read(&k.path).unwrap();

    // Elke bitflip (steekproef over het hele bestand) wordt opgemerkt.
    for i in (0..good.len()).step_by(7) {
        let mut bad = good.clone();
        bad[i] ^= 0x04;
        std::fs::write(&k.path, &bad).unwrap();
        k.run(&["get", "github", "--show"], &format!("{PW}\n")).failure().stdout(contains(ITEM_PW).not());
    }
    // Afgekapt, leeg, rommel.
    for bad in [&good[..good.len() - 1], &good[..40], &b""[..], &b"hallo, dit is geen kluis"[..]] {
        std::fs::write(&k.path, bad).unwrap();
        k.run(&["list"], &format!("{PW}\n")).failure().stderr(contains("fout:"));
    }
    // Herstel en controleer dat het weer werkt.
    std::fs::write(&k.path, &good).unwrap();
    k.run(&["list"], &format!("{PW}\n")).success().stdout(contains("GitHub"));
}

#[test]
fn backup_bevat_vorige_versie() {
    let k = Kluis::new().init();
    k.add("Een", "a", "pw-een-1234");
    k.add("Twee", "b", "pw-twee-1234");
    let bak = k.dir().join("vault.enc.bak");
    let out = Command::new(env!("CARGO_BIN_EXE_kluis"))
        .args(["--vault", bak.to_str().unwrap(), "list"])
        .env("NO_COLOR", "1")
        .write_stdin(format!("{PW}\n"))
        .assert()
        .success();
    out.stdout(contains("Een").and(contains("Twee").not()));
}

#[test]
fn hoofdwachtwoord_wijzigen() {
    let k = Kluis::new().init();
    k.add("GitHub", "jan", ITEM_PW);
    k.run(&["passwd"], &format!("{PW}\n{PW2}\n{PW2}\n")).success().stderr(contains("gewijzigd"));
    k.run(&["list"], &format!("{PW}\n")).failure();
    k.run(&["get", "github", "--show"], &format!("{PW2}\n")).success().stdout(contains(ITEM_PW));
    // Ook de back-up opent niet meer met het oude wachtwoord.
    let bak = k.dir().join("vault.enc.bak");
    Command::new(env!("CARGO_BIN_EXE_kluis"))
        .args(["--vault", bak.to_str().unwrap(), "list"])
        .write_stdin(format!("{PW}\n"))
        .assert()
        .failure();
}

#[test]
fn export_en_import() {
    let a = Kluis::new().init();
    a.add("GitHub", "jan", ITEM_PW);
    let export = a.dir().join("export.kluis");
    let export_s = export.to_str().unwrap();
    a.run(&["export", export_s], &format!("{PW}\n{PW2}\n{PW2}\n")).success();
    // Bestaand bestand wordt niet overschreven.
    a.run(&["export", export_s], &format!("{PW}\n")).failure().stderr(contains("overschrijf het niet"));
    let raw = std::fs::read(&export).unwrap();
    assert!(!raw.windows(ITEM_PW.len()).any(|w| w == ITEM_PW.as_bytes()), "export is versleuteld");

    let b = Kluis::new().init();
    b.run(&["import", export_s], &format!("{PW}\n{PW}\n")).failure().stderr(contains("verkeerd"));
    b.run(&["import", export_s], &format!("{PW}\n{PW2}\n"))
        .success()
        .stderr(contains("1 item(s) toegevoegd"));
    b.run(&["import", export_s], &format!("{PW}\n{PW2}\n"))
        .success()
        .stderr(contains("0 item(s) toegevoegd"));
    b.run(&["get", "github", "--show"], &format!("{PW}\n")).success().stdout(contains(ITEM_PW));
}

#[test]
fn csv_import_met_waarschuwing_en_verwijderen() {
    let k = Kluis::new().init();
    let csv = k.dir().join("bitwarden.csv");
    std::fs::write(
        &csv,
        "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
         Werk,,login,GitHub,,,0,https://github.com,jan,csv-pw-1,\n\
         ,,login,Mail,,,0,https://mail.nl,ik,csv-pw-2,\n",
    )
    .unwrap();
    let csv_s = csv.to_str().unwrap();
    k.run(&["import-csv", csv_s], &format!("{PW}\nn\n"))
        .success()
        .stderr(contains("NIET versleuteld").and(contains("2 item(s) geïmporteerd")).and(contains("shred")));
    assert!(csv.exists());
    // Nogmaals: niets dubbel, en nu laten verwijderen.
    k.run(&["import-csv", csv_s], &format!("{PW}\nj\n"))
        .success()
        .stderr(contains("0 item(s) geïmporteerd").and(contains("verwijderd")));
    assert!(!csv.exists());
    k.run(&["get", "mail", "--show"], &format!("{PW}\n")).success().stdout(contains("csv-pw-2"));
}

#[test]
fn generator() {
    let k = Kluis::new();
    let out = k.run(&["generate", "--show", "-l", "40"], "").success().get_output().stdout.clone();
    assert_eq!(String::from_utf8(out).unwrap().trim().chars().count(), 40);
    let out = k
        .run(&["generate", "--show", "-p", "-w", "5", "--separator", "_"], "")
        .success()
        .get_output()
        .stdout
        .clone();
    assert_eq!(String::from_utf8(out).unwrap().trim().split('_').count(), 5);
    k.run(&["generate", "--show", "-l", "4"], "").failure().stderr(contains("lengte"));
    k.run(&["generate"], "").failure().stderr(contains("geen klembord"));
}

#[test]
fn info_werkt_zonder_wachtwoord() {
    let k = Kluis::new();
    k.run(&["info"], "").success().stdout(contains("bestaat nog niet"));
    let k = k.init();
    k.run(&["info"], "").success().stdout(
        contains("Argon2id, 8 MiB")
            .and(contains("Rechten:          600"))
            .and(contains("Core dumps uit:   ja"))
            .and(contains("Formaatversie:    2"))
            .and(contains("elk wachtwoord en elke notitie apart versleuteld")),
    );
}

#[test]
fn ontbrekende_kluis_geeft_hint() {
    let k = Kluis::new();
    k.run(&["list"], "").failure().stderr(contains("kluis init"));
}

#[test]
fn completions_voor_alle_shells() {
    let k = Kluis::new();
    for shell in ["bash", "zsh", "fish"] {
        k.run(&["completions", shell], "")
            .success()
            .stdout(contains("generate").and(contains("clipboard").not()));
    }
}

#[test]
fn shell_modus() {
    let k = Kluis::new().init();
    k.add("GitHub", "jan", ITEM_PW);
    k.run(&["shell"], &format!("{PW}\nlist\nget github --show\nonzin\nadd\n\"ongesloten\nexit\n"))
        .success()
        .stdout(contains("GitHub").and(contains(ITEM_PW)))
        .stderr(contains("ontgrendeld").and(contains("vergrendeld")));
    // passwd in de shell vraagt het huidige wachtwoord opnieuw.
    k.run(&["shell"], &format!("{PW}\npasswd\nfout\nexit\n"))
        .success()
        .stderr(contains("verkeerd hoofdwachtwoord"));
    k.run(&["list"], &format!("{PW}\n")).success();
}

/// Start `kluis shell --timeout 1`, stuur `input` en laat stdin open.
/// Geeft de stderr-uitvoer terug zodra de shell uit zichzelf stopt.
fn shell_until_locked(k: &Kluis, input: &str) -> String {
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_kluis"))
        .args(["shell", "--timeout", "1"])
        .env("KLUIS_VAULT", &k.path)
        .env("NO_COLOR", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input.as_bytes()).unwrap();
    // stdin blijft open: er komt gewoon geen invoer meer.
    let start = Instant::now();
    let out = loop {
        if let Some(_status) = child.try_wait().unwrap() {
            break child.wait_with_output().unwrap();
        }
        assert!(start.elapsed() < Duration::from_secs(30), "shell vergrendelde niet");
        std::thread::sleep(Duration::from_millis(50));
    };
    drop(stdin);
    assert!(out.status.success());
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn shell_vergrendelt_automatisch_bij_inactiviteit() {
    let k = Kluis::new().init();
    let err = shell_until_locked(&k, &format!("{PW}\n"));
    assert!(err.contains("Automatisch vergrendeld"));
    assert!(err.contains("sleutel is uit het geheugen gewist"));
}

#[test]
fn shell_vergrendelt_ook_midden_in_een_vraag() {
    let k = Kluis::new().init();
    // `add` vraagt om een gebruikersnaam; daar komt nooit antwoord op.
    let err = shell_until_locked(&k, &format!("{PW}\nadd Wegloper\n"));
    assert!(err.contains("Gebruikersnaam"));
    assert!(err.contains("Automatisch vergrendeld"));
    k.run(&["list"], &format!("{PW}\n")).success().stdout(contains("Wegloper").not());
}

#[test]
fn kluisbestand_bevat_geen_klare_tekst() {
    let k = Kluis::new().init();
    k.add("ZichtbareNaam", "gebruiker123", ITEM_PW);
    let raw = std::fs::read(&k.path).unwrap();
    for needle in ["ZichtbareNaam", "gebruiker123", ITEM_PW, "example.org"] {
        assert!(
            !raw.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "{needle} staat leesbaar in het bestand"
        );
    }
    assert_eq!(&raw[..8], b"KLUISVLT");
}
