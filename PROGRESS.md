# Voortgang `kluis`

Laatst bijgewerkt: stap 6 (API-sleutels, notities, CakePass-inlogscherm in 3D).
Branch: `claude/kluis-v1` (nog niet samengevoegd met `main`).

## Wat ik vanavond op mijn computer moet doen

1. **Pakketten installeren**
   ```bash
   sudo pacman -S --needed base-devel git rust wl-clipboard xclip
   ```
2. **Code ophalen** (de juiste branch!)
   ```bash
   git clone -b claude/kluis-v1 https://github.com/Justcakenl/passcode-manager-cli-.git kluis
   cd kluis
   ```
3. **Bouwen, testen en installeren**
   ```bash
   cd packaging/arch
   makepkg -si
   ```
   Dit duurt een paar minuten (bouwen + alle tests). Faalt het? Kopieer de
   foutmelding en vraag Claude om hulp.
4. **Uitproberen** met een testkluis, zodat je echte kluis schoon blijft:
   ```bash
   export KLUIS_VAULT=/tmp/testkluis.enc
   kluis init
   kluis add Test --generate
   kluis get Test           # plak (Ctrl+V) ergens en wacht 20 s → leeg
   kluis info
   unset KLUIS_VAULT
   ```
5. **Loop de lijst "Testen op Arch" hieronder af** en vink af wat werkt.
6. **Echte kluis maken**: `kluis init`, en maak meteen een eerste back-up
   (zie de README, kopje "Back-ups").
7. Tevreden? Laat Claude de branch samenvoegen met `main` (via een pull
   request), of doe het zelf op GitHub.

## Klaar

- [x] **Stap 1 – Crypto-kern**: `secure_mem` (wissende allocator,
  mlock-buffer, core dumps uit), `crypto` (Argon2id + XChaCha20-Poly1305),
  `format` (versioneerde header als associated data). Tests met de officiële
  Argon2id-testvector uit RFC 9106 en tests waarin elke bitflip en elke
  afgekapte lengte moet falen.
- [x] **Stap 2 – Opslag en kluismodel**: `vault` (items met naam,
  gebruikersnaam, wachtwoord, URL, notities, tags) en `storage` (XDG-pad,
  map 700/bestand 600, atomisch schrijven met fsync, automatische `.bak`,
  `flock` plus detectie van gelijktijdige wijzigingen, symlinks geweigerd).
- [x] **Stap 3 – CLI**: `init`, `add`, `get`, `edit`, `rm`, `list`, `search`,
  `generate`, `passwd`, `export`, `import`, `import-csv`, `info`, `shell`,
  `completions`. Klembord via wl-copy/xclip, wissen na 20 s.
- [x] **Stap 4 – Packaging en oplevering**: `packaging/arch/PKGBUILD`
  (installeert binary, completions voor bash/zsh/fish, docs en licentie),
  Nederlandse `README.md`, `LICENSE` (MIT), security-review met drie
  gevonden en opgeloste problemen (zie README).

- [x] **Stap 5 – Tweede versleutelingslaag**: elk wachtwoord en elke notitie
  wordt nu apart versleuteld met een eigen itemsleutel (HKDF-SHA256 uit de
  hoofdsleutel). Ook in een geopende kluis staan ze alleen versleuteld in het
  geheugen; ontsleutelen gebeurt per item, alleen bij `get`. Formaatversie 2;
  oude kluizen (versie 1) worden automatisch bijgewerkt. Gecontroleerd door
  het geheugen van een draaiende `kluis shell` te doorzoeken: 0 leesbare
  kopieën van wachtwoord en notitie, ook direct na `get --show`.

- [x] **Stap 6 – Meer soorten items + CakePass-inlogscherm**:
  - Naast logins nu ook **API-sleutels** (`--type api`) en **beveiligde
    notities** van meerdere regels (`--type notitie`).
  - **Alle inhoud** van elk item is nu per veld versleuteld: ook gebruikersnaam
    en URL (schema 3). Alleen naam, soort en tags zijn leesbaar in een
    geopende kluis. Oude kluizen worden automatisch omgezet.
  - **Inlogscherm**: `kluis` (zonder opdracht) toont een 3D-gerenderd,
    draaiend CakePass-logo (roze glazuur, cakelagen, hagelslag, glans) en
    vraagt het hoofdwachtwoord (3 pogingen). Bij vergrendelen worden scherm
    en scrollback gewist. Voorbeeld: `docs/cakepass-login.gif`.
  - Geheugenscan van een geopende kluis: wachtwoord, API-sleutel, notitie,
    gebruikersnaam en URL staan er 0 keer leesbaar in, ook na `list` en
    `get --show`.

## Nog te doen

- [ ] De punten onder "Testen op Arch" op je eigen computer controleren.
- [ ] Branch `claude/kluis-v1` samenvoegen met `main`.
- [ ] Eventueel de licentie aanpassen (nu MIT, op naam van "Justcakenl").
- [ ] Ideeën voor later: zie README, kopje "Voor later".

## Gemaakte keuzes

Zie `docs/ONTWERP.md` voor de uitleg. Kort samengevat:

- Programmanaam `kluis`, kluis in `~/.local/share/kluis/vault.enc` (XDG).
- Argon2id m=64 MiB, t=3, p=4 (instelbaar, minimaal 8 MiB), salt van 32 bytes.
  Ontgrendelen kost met deze instellingen ongeveer 0,2 s.
- XChaCha20-Poly1305 met een nieuwe nonce bij elke keer opslaan.
- Automatisch vergrendelen: elk los commando vraagt opnieuw het
  hoofdwachtwoord (er draait geen achtergronddienst met de sleutel).
  `kluis shell` vergrendelt na 5 minuten zonder invoer, ook midden in een
  vraag. In de shell vragen `passwd` en `export` het hoofdwachtwoord opnieuw.
- Zonder klembord geeft `get` een foutmelding in plaats van het wachtwoord
  te tonen; tonen kan alleen met `--show`.
- Hoofd- en exportwachtwoord moeten zxcvbn-score ≥ 3 halen. Itemwachtwoorden
  mag je vrij kiezen (sites hebben eigen eisen); leeg = genereren.
- Na `kluis passwd` wordt ook de `.bak` met het NIEUWE wachtwoord versleuteld.
- Itemnamen zijn uniek (hoofdletterongevoelig). Bij een conflict tijdens
  import krijgt een item een volgnummer ("GitHub (2)"); gelijke items worden
  overgeslagen.
- Kluisbestanden die een symlink zijn, worden geweigerd.
- `rust-version` is 1.88, omdat oudere versies van de crate `time` een bekende
  kwetsbaarheid hebben (RUSTSEC-2026-0009).
- De PKGBUILD staat in `packaging/arch/`, omdat makepkg zelf een map `src/`
  aanmaakt die anders botst met de Rust-broncode.
- Merknaam **CakePass**, maar het commando blijft `kluis` (kort en Nederlands).
  Omdopen naar `cakepass` kan later nog, zolang er geen echte kluis is.
- Het logo wordt alleen getoond bij `kluis`, `kluis shell`, `kluis init` en
  `kluis logo`, niet bij losse opdrachten zoals `kluis get` (dat zou snel
  irritant worden).
- Twee lagen: bestandssleutel en itemsleutel worden met HKDF-SHA256 uit de
  Argon2-sleutel afgeleid. Naam, gebruikersnaam, URL en tags zijn niet apart
  versleuteld (wel op schijf), zodat `list` en `search` werken zonder één
  wachtwoord te ontsleutelen.
- Een getoond wachtwoord (`--show`) gaat rechtstreeks naar de terminal, niet
  via de uitvoerbuffer van Rust, zodat er geen kopie in het geheugen achterblijft.
- EFF-diceware-woordenlijst in `assets/` (gecontroleerd tegen twee
  onafhankelijke bronnen; sha256 `addd3553…996b903e`).

## Controles (laatste stap)

| Controle | Resultaat |
|---|---|
| `cargo test` | 108 geslaagd (71 bibliotheek, 12 CLI-unit, 25 integratie) |
| `cargo clippy --all-targets -- -D warnings` | geen meldingen |
| `cargo audit` | geen kwetsbaarheden (140 crates gescand) |
| `cargo build --release --locked` | gelukt (Ubuntu-container) |

### Wél getest in een schone Arch Linux-container (als gewone gebruiker)

Pacman kon in de cloudomgeving geen pakketten downloaden (de mirrors waren
geblokkeerd). Daarom heb ik de op Ubuntu gebouwde binary in een officiële
`archlinux:latest`-container (glibc 2.44, pacman 7.1) getest:

- [x] `makepkg --printsrcinfo` leest de PKGBUILD zonder fouten
- [x] Standaardpad `~/.local/share/kluis/vault.enc`; map 700, bestand 600
- [x] `XDG_DATA_HOME=/tmp/xdg` → `/tmp/xdg/kluis/vault.enc`; relatief pad genegeerd
- [x] `ulimit -l` = 8192 KiB, `kluis info` → "mlock werkt: ja"
- [x] Core-dumplimiet 0; `/proc/<pid>/mem` onleesbaar voor dezelfde gebruiker
- [x] `init`, `add --generate` en `list` met de standaard Argon2-instellingen

## Testen op Arch

Dit kon NIET getest worden in de cloud. Doe het zelf en vink af:

- [ ] `sudo pacman -S --needed base-devel git rust` en dan
      `cargo build --release --locked` op je eigen Arch-installatie
- [ ] `cd packaging/arch && makepkg -si` (bouwt, draait alle tests, installeert)
- [ ] Na installatie: `kluis --version`, en tab-aanvulling in een nieuwe
      terminal (`kluis <Tab><Tab>`) in bash, zsh of fish
- [ ] **Klembord Wayland** (`wl-clipboard`): `kluis get <naam>` → plakken
      werkt, en na 20 s geeft `wl-paste` niets meer
- [ ] **Klembord X11** (`xclip`): hetzelfde. Kopieer binnen 20 s iets anders;
      dat mag NIET gewist worden
- [ ] Klembord en terminal sluiten: start `kluis get`, sluit meteen het
      terminalvenster; na 20 s moet het klembord toch leeg zijn
- [ ] Klembordgeschiedenis (Klipper/cliphist/CopyQ): kijk of het wachtwoord
      daarin blijft staan. Zo ja: geschiedenis uitzetten of kluis uitsluiten
- [ ] Verborgen prompt: tijdens het typen van het hoofdwachtwoord verschijnen
      geen tekens, en Ctrl+C zet de terminal netjes terug
- [ ] Kleuren: groen ✔ en gele waarschuwingen in je terminal; geen kleurcodes
      bij `kluis list | cat` of met `NO_COLOR=1`
- [ ] `kluis shell`: na 5 min niets doen verschijnt "Automatisch vergrendeld"
- [ ] **Inlogscherm**: typ `kluis`. Draait het 3D-logo soepel in je terminal
      (kitty, Alacritty, Konsole, GNOME Terminal)? Zie je roze letters met
      cakelagen? Lelijk of schokkerig? Probeer `kluis logo` in een breder
      venster, of zet het uit met `--no-animation`.
- [ ] Ziet het logo er goed uit als je terminal geen truecolor meldt?
      (`echo $COLORTERM`; leeg = 256 kleuren)
- [ ] Na `exit` in de shell: is het scherm leeg en kun je niet terugscrollen
      naar getoonde wachtwoorden?
- [ ] API-sleutel plakken in de verborgen prompt (Ctrl+Shift+V) werkt
- [ ] Core dumps: open `kluis shell`, doe in een tweede terminal
      `kill -SEGV $(pgrep -x kluis)` en daarna `coredumpctl list` → geen
      dump van kluis
- [ ] mlock-limiet op je echte systeem: `ulimit -l` en `kluis info`
- [ ] Export naar een USB-stick (FAT/exFAT) en weer importeren
