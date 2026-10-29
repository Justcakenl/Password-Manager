# Voortgang `kluis`

Laatst bijgewerkt: stap 2 (opslag en kluismodel).
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

## Nog te doen

- [ ] Stap 3 – CLI (alle opdrachten, klembord, shell-modus, completions)
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
- EFF-diceware-woordenlijst opgenomen in `assets/` (gecontroleerd tegen twee
  onafhankelijke bronnen; sha256 `addd3553…996b903e`).

## Controles (laatste stap)

| Controle | Resultaat |
|---|---|
| `cargo test` | 40 geslaagd |
| `cargo clippy --all-targets -- -D warnings` | geen meldingen |
| `cargo audit` | geen kwetsbaarheden |

## Testen op Arch

Dit kon in de cloudomgeving NIET getest worden. Doe dit zelf op je Arch-pc:

- [ ] `cargo build --release` op een schone Arch-installatie
- [ ] XDG-pad: standaard `~/.local/share/kluis/vault.enc`; met
  `XDG_DATA_HOME=/ergens` moet het `/ergens/kluis/vault.enc` worden
  (de tests draaiden als root in een container, met een tijdelijke map)
- [ ] mlock-limiet: `ulimit -l` (verwacht 8192 KiB op een standaard Arch met systemd)
