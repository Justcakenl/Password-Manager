# Voortgang `kluis`

Laatst bijgewerkt: stap 3 (CLI).
Branch: `claude/kluis-v1`

## Klaar

- [x] **Stap 1 – Crypto-kern**: `secure_mem` (wissende allocator, mlock-buffer,
  core dumps uit), `crypto` (Argon2id + XChaCha20-Poly1305), `format`
  (versioneerde header als associated data). 20 unit-tests, waaronder de
  officiële Argon2id-testvector uit RFC 9106 en tests waarin elke bitflip en
  elke afgekapte lengte moet falen.
- [x] **Stap 2 – Opslag en kluismodel**: `vault` (items met naam,
  gebruikersnaam, wachtwoord, URL, notities, tags; zoeken, hernoemen,
  samenvoegen) en `storage` (XDG-pad, map 700/bestand 600, atomisch schrijven
  met fsync, automatische `.bak`, `flock` plus detectie van gelijktijdige
  wijzigingen, symlinks geweigerd, wachtwoord wijzigen, versleutelde export).
  40 tests.
- [x] **Stap 3 – CLI**: `init`, `add`, `get`, `edit`, `rm`, `list`, `search`,
  `generate` (wachtwoord/passphrase), `passwd`, `export`, `import`,
  `import-csv`, `info`, `shell` (auto-vergrendeling), `completions`.
  Klembord via wl-copy/xclip met wissen na 20 s. Nederlandse hulpteksten.
  82 tests, waarvan 18 integratietests die het echte programma aansturen
  (verkeerd wachtwoord, gemanipuleerde bestanden, shell-timeout, enz.).

## Nog te doen

- [ ] Stap 4 – Packaging (PKGBUILD), README, security-review

## Gemaakte keuzes

Zie `docs/ONTWERP.md` voor de uitleg. Kort samengevat:

- Programmanaam `kluis`, kluis in `~/.local/share/kluis/vault.enc`.
- Argon2id m=64 MiB, t=3, p=4 (instelbaar, minimaal 8 MiB), salt van 32 bytes.
- XChaCha20-Poly1305 met een nieuwe nonce bij elke keer opslaan.
- Na `kluis passwd` wordt ook de back-up met het NIEUWE wachtwoord
  versleuteld, zodat een uitgelekt oud wachtwoord niets meer opent.
- Itemnamen zijn uniek (hoofdletterongevoelig). Bij een conflict tijdens
  import krijgt een item een volgnummer, bijvoorbeeld "GitHub (2)".
- Een kluisbestand dat een symlink is, wordt geweigerd. Atomisch schrijven
  zou de link anders stilletjes vervangen.
- `rust-version` is 1.88, omdat oudere versies van de crate `time` een
  bekende kwetsbaarheid hebben (RUSTSEC-2026-0009). Arch heeft altijd de
  nieuwste Rust, dus dat is geen probleem.
- Automatisch vergrendelen: elk los commando vraagt opnieuw het hoofdwachtwoord
  (er draait geen achtergronddienst met de sleutel). `kluis shell` houdt de
  kluis open en vergrendelt na 5 minuten zonder invoer (`--timeout`).
  In de shell vragen `passwd` en `export` het hoofdwachtwoord opnieuw.
- Zonder klembord geeft `get` een foutmelding in plaats van het wachtwoord
  te tonen; tonen kan alleen met `--show`.
- Itemwachtwoorden mag je zelf kiezen (geen sterktecontrole, want sites
  stellen eigen eisen); leeg laten = sterk wachtwoord genereren.
- Het hoofd- en exportwachtwoord moeten zxcvbn-score ≥ 3 halen.
- EFF-diceware-woordenlijst opgenomen in `assets/` (gecontroleerd tegen twee
  onafhankelijke bronnen; sha256 `addd3553…996b903e`).

## Controles (laatste stap)

| Controle | Resultaat |
|---|---|
| `cargo test` | 82 geslaagd (58 bibliotheek, 6 CLI-unit, 18 integratie) |
| `cargo build --release --locked` | gelukt; ontgrendelen met standaardinstellingen ≈ 0,2 s |
| `cargo clippy --all-targets -- -D warnings` | geen meldingen |
| `cargo audit` | geen kwetsbaarheden |

## Testen op Arch

Dit kon in de cloudomgeving NIET getest worden. Doe dit zelf op je Arch-pc:

- [ ] `cargo build --release` op een schone Arch-installatie
- [ ] XDG-pad: standaard `~/.local/share/kluis/vault.enc`; met
  `XDG_DATA_HOME=/ergens` moet het `/ergens/kluis/vault.enc` worden
  (de tests draaiden als root in een container, met een tijdelijke map)
- [ ] mlock-limiet: `ulimit -l` (verwacht 8192 KiB op een standaard Arch met
  systemd) en `kluis info` → "mlock werkt: ja"
- [ ] Klembord Wayland: `kluis get <naam>` → plakken werkt, en na 20 s is het
  klembord leeg (`wl-paste` geeft niets). Vereist `wl-clipboard`.
- [ ] Klembord X11: hetzelfde met `xclip`. Kopieer binnen 20 s iets anders;
  dat mag NIET gewist worden.
- [ ] Klembord en terminal sluiten: start `kluis get`, sluit direct het
  terminalvenster; na 20 s moet het klembord toch leeg zijn.
- [ ] Verborgen prompt: tijdens het typen van het hoofdwachtwoord verschijnen
  geen tekens, en Ctrl+C zet de terminal netjes terug.
- [ ] Kleuren: groen ✔ en gele waarschuwingen in je terminal; geen kleurcodes
  bij `kluis list | cat`.
- [ ] `kluis shell`: na 5 min niets doen verschijnt "Automatisch vergrendeld".
- [ ] Completions in bash, zsh en fish (na installatie met de PKGBUILD).
