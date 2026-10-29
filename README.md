# kluis

Een **offline wachtwoordmanager voor de terminal** op Arch Linux.
Al je wachtwoorden staan in één versleuteld bestand op je eigen computer.
Geen cloud, geen account, geen telemetrie en geen enkele netwerkverbinding.

```text
$ kluis get GitHub
Hoofdwachtwoord:
Naam:            GitHub
Gebruikersnaam:  jan
URL:             https://github.com
Tags:            werk
Gewijzigd:       2026-10-29 14:43 UTC
Notities:        (verborgen; gebruik --show)
Wachtwoord:      (verborgen; gebruik --show)
✔ Het wachtwoord gekopieerd naar het klembord (via wl-copy); het wordt over 20 seconden gewist.
```

---

## Inhoud

1. [Installatie](#installatie)
2. [Eerste keer: kluis maken](#eerste-keer-kluis-maken)
3. [Dagelijks gebruik](#dagelijks-gebruik)
4. [Wachtwoorden genereren](#wachtwoorden-genereren)
5. [Shell-modus en automatisch vergrendelen](#shell-modus-en-automatisch-vergrendelen)
6. [Overstappen van een andere wachtwoordmanager (CSV)](#overstappen-van-een-andere-wachtwoordmanager-csv)
7. [Back-ups](#back-ups)
8. [Hoofdwachtwoord vergeten?](#hoofdwachtwoord-vergeten)
9. [Hoe de beveiliging werkt](#hoe-de-beveiliging-werkt)
10. [Security-review en resterende risico's](#security-review-en-resterende-risicos)
11. [Problemen oplossen](#problemen-oplossen)
12. [Voor later](#voor-later)

---

## Installatie

### 1. Benodigde pakketten

```bash
sudo pacman -S --needed base-devel git rust
# Klembord: kies wat bij jouw bureaublad past (of installeer beide)
sudo pacman -S wl-clipboard   # Wayland (GNOME, KDE Plasma 6, Sway, Hyprland)
sudo pacman -S xclip          # X11 (i3, Xfce, oudere sessies)
```

Weet je niet of je Wayland gebruikt? Typ `echo $XDG_SESSION_TYPE`.

### 2. Bouwen en installeren met makepkg (aanbevolen)

```bash
git clone https://github.com/Justcakenl/passcode-manager-cli-.git kluis
cd kluis/packaging/arch
makepkg -si
```

`makepkg` bouwt het programma, draait alle tests en installeert daarna:

- `/usr/bin/kluis`
- shell-completions voor bash, zsh en fish (tab-aanvulling werkt na het
  openen van een nieuwe terminal)
- deze README in `/usr/share/doc/kluis/`

Tests overslaan (sneller): `makepkg -si --nocheck`.
Bijwerken na een `git pull`: verhoog `pkgrel` in de PKGBUILD, of gebruik
`makepkg -si --force`.

### 3. Alternatief: alleen bouwen met cargo

```bash
cargo build --release --locked
./target/release/kluis --help
```

---

## Eerste keer: kluis maken

```bash
kluis init
```

Je kiest een **hoofdwachtwoord**. Dat is de enige sleutel tot je kluis.
`kluis` controleert met zxcvbn of het sterk genoeg is (score 3 van 4 of hoger).
Een goede keuze is een zin van vijf of meer willekeurige woorden. Laat er
gerust een maken:

```bash
kluis generate --passphrase --show
```

De kluis komt in `~/.local/share/kluis/vault.enc`. Heb je `XDG_DATA_HOME`
ingesteld, dan in `$XDG_DATA_HOME/kluis/vault.enc`. Met `--vault <pad>` of
de omgevingsvariabele `KLUIS_VAULT` kies je een andere plek.

**Zwaardere instellingen** (langzamer om te openen, moeilijker te kraken):

```bash
kluis init --kdf-memory 256 --kdf-iterations 4
```

---

## Dagelijks gebruik

Elke opdracht vraagt eerst je hoofdwachtwoord (in een verborgen prompt: je
ziet niets terwijl je typt, dat is de bedoeling).

| Wat | Opdracht |
|---|---|
| Item toevoegen (kluis vraagt alles één voor één) | `kluis add GitHub` |
| Toevoegen met opties en een gegenereerd wachtwoord | `kluis add GitHub -u jan --url https://github.com -t werk,code --generate` |
| Wachtwoord naar het klembord (20 s) | `kluis get GitHub` |
| Gebruikersnaam naar het klembord | `kluis get GitHub --copy-username` |
| Wachtwoord en notities op het scherm tonen | `kluis get GitHub --show` |
| Alle items (zonder wachtwoorden) | `kluis list` |
| Alleen items met een tag | `kluis list --tag werk` |
| Zoeken in naam, gebruiker, URL en tags | `kluis search git` |
| Item wijzigen (vraagt per veld) | `kluis edit GitHub` |
| Alleen een nieuw wachtwoord genereren | `kluis edit GitHub --generate` |
| Hernoemen | `kluis edit GitHub --rename "GitHub werk"` |
| Verwijderen | `kluis rm GitHub` |
| Hoofdwachtwoord wijzigen | `kluis passwd` |
| Info over kluis en beveiliging (geen wachtwoord nodig) | `kluis info` |
| Hulp | `kluis --help` of `kluis add --help` |

Tips:

- Namen zijn niet hoofdlettergevoelig: `kluis get github` werkt ook.
- Namen met spaties zet je tussen aanhalingstekens: `kluis get "Mijn Bank"`.
- Laat je bij `add` het wachtwoord leeg, dan genereert `kluis` een sterk
  wachtwoord van 24 tekens en zet het op het klembord.
- **Wachtwoorden geef je nooit als argument mee.** Dat is bewust: argumenten
  zijn zichtbaar voor andere programma's (`ps`) en komen in je shellgeschiedenis.
- Een wachtwoord uit een ander programma doorgeven kan via een pipe:
  `mijn-generator | kluis add Site -u jan --url x -t y`. Gebruik daarvoor
  **niet** `echo geheim | ...`, want dan staat het geheim in je shellgeschiedenis.

---

## Wachtwoorden genereren

```bash
kluis generate                         # 24 tekens → klembord
kluis generate --show -l 32            # 32 tekens, op het scherm
kluis generate --no-symbols            # zonder leestekens
kluis generate --no-lookalikes         # zonder 0 O 1 l I |
kluis generate --passphrase            # 6 woorden, bijv. grape-lantern-oyster-…
kluis generate -p -w 8 --separator .   # 8 woorden met punten
```

Passphrases komen uit de diceware-woordenlijst van de EFF (7776 woorden,
12,9 bits per woord). Zes woorden geven ongeveer 77 bits; voor een
hoofdwachtwoord is dat ruim voldoende.

---

## Shell-modus en automatisch vergrendelen

Normaal vraagt **elk** commando opnieuw je hoofdwachtwoord. Na afloop staat
de sleutel nergens meer in het geheugen. Dat is de veiligste vorm van
"automatisch vergrendelen".

Moet je veel tegelijk doen, gebruik dan de shell-modus:

```bash
kluis shell                  # vergrendelt na 5 minuten zonder invoer
kluis shell --timeout 120    # na 2 minuten
```

```text
kluis> list
kluis> get "Mijn Bank"
kluis> add Netflix --generate
kluis> exit
```

- Na de ingestelde tijd zonder invoer wordt de sleutel gewist en stopt de
  shell. Dat gebeurt ook als je midden in een vraag wegloopt.
- `passwd` en `export` vragen in de shell het hoofdwachtwoord opnieuw.
- `exit`, `quit`, `lock` of Ctrl+D vergrendelt meteen.

---

## Overstappen van een andere wachtwoordmanager (CSV)

`kluis` kan CSV-exports lezen van onder andere **Bitwarden, KeePassXC,
1Password, Firefox en Chrome/Chromium**.

```bash
kluis import-csv ~/Downloads/bitwarden_export.csv
```

> ⚠️ **Een CSV-export is NIET versleuteld.** Iedereen die het bestand kan
> lezen, ziet al je wachtwoorden. Doe dit zo:
>
> 1. Exporteer, importeer en verwijder direct daarna.
> 2. `kluis` biedt na het importeren aan het bestand te overschrijven en te
>    verwijderen. Zeg ja.
> 3. Kijk ook in je prullenbak, je map Downloads en eventuele back-ups of
>    sync-mappen (Nextcloud, Syncthing, Dropbox).
> 4. Op SSD's en op btrfs/ZFS is overschrijven geen garantie dat de data echt
>    weg is. Volledige schijfversleuteling (LUKS) is de echte bescherming.

Items met een naam die al bestaat, krijgen een volgnummer, bijvoorbeeld
"GitHub (2)". Precies dezelfde items worden overgeslagen, dus nogmaals
importeren geeft geen dubbele items.

### Versleutelde export en import (tussen je eigen computers)

```bash
kluis export /run/media/jan/usb/kluis-export.kluis   # vraagt een exportwachtwoord
kluis import /pad/naar/kluis-export.kluis             # op de andere computer
```

Het exportbestand is versleuteld met een eigen wachtwoord (dezelfde sterke
versleuteling als de kluis zelf).

---

## Back-ups

**Maak back-ups!** Als je schijf kapotgaat, ben je anders alles kwijt.

Welke bestanden er zijn:

| Bestand | Wat |
|---|---|
| `~/.local/share/kluis/vault.enc` | je kluis (versleuteld) |
| `~/.local/share/kluis/vault.enc.bak` | automatische kopie van de **vorige** versie (versleuteld) |
| `~/.local/share/kluis/vault.enc.lock` | leeg slotbestand, mag weg |

Hoe:

1. **Kopieer `vault.enc` regelmatig** naar een USB-stick of externe schijf,
   en liefst ook naar een tweede plek (bijvoorbeeld bij familie). Het bestand
   is versleuteld, dus dat is veilig, zolang je hoofdwachtwoord sterk is.
   ```bash
   cp ~/.local/share/kluis/vault.enc /run/media/$USER/USB/kluis-$(date +%F).enc
   ```
2. **Test je back-up**: open hem zonder iets te wijzigen.
   ```bash
   kluis --vault /run/media/$USER/USB/kluis-2026-10-29.enc list
   ```
3. Herstellen = het back-upbestand terugzetten als `vault.enc`.
4. Ging er iets mis met de laatste wijziging? Dan staat de vorige versie
   in `vault.enc.bak`:
   ```bash
   kluis --vault ~/.local/share/kluis/vault.enc.bak list
   ```

Goed om te weten:

- Een back-up opent met het hoofdwachtwoord dat gold **op het moment dat je
  hem maakte**. Na `kluis passwd` werkt een oude kopie dus nog steeds met het
  oude wachtwoord. Is je oude wachtwoord uitgelekt? Gooi dan oude kopieën weg
  en maak nieuwe. (De automatische `.bak` wordt bij `passwd` wel meteen
  opnieuw versleuteld met het nieuwe wachtwoord.)
- Na `kluis rm` staat het verwijderde item nog in `.bak`, tot de volgende
  wijziging.

---

## Hoofdwachtwoord vergeten?

**Dan zijn je gegevens weg. Er is geen herstel mogelijk.**

Dat is geen fout, maar precies hoe het hoort te werken:

- Je kluis is versleuteld met een sleutel die alleen uit je hoofdwachtwoord
  te maken is. Dat wachtwoord wordt nergens opgeslagen, ook niet "versleuteld"
  of als hash.
- Er is geen "wachtwoord vergeten"-knop, geen achterdeur en geen server die
  kan helpen. Ook de maker van dit programma kan je kluis niet openen.
- Raden kost door Argon2id per poging veel tijd en geheugen. Bij een goed
  hoofdwachtwoord duurt dat langer dan een mensenleven.

Wat je kunt doen om dit te voorkomen:

1. Kies een passphrase die je kunt onthouden (`kluis generate --passphrase --show`)
   en gebruik hem de eerste weken vaak.
2. Schrijf het hoofdwachtwoord op papier en bewaar dat op een veilige plek
   (bijvoorbeeld bij je paspoort). Tegen online aanvallers is papier veilig.
3. Twijfel je of je het nog weet? Test het met `kluis list` voordat je het
   wijzigt.

Weet je het echt niet meer, dan blijft alleen dit over: een nieuwe kluis
maken (`kluis init` met een andere `--vault`, of verwijder eerst
`~/.local/share/kluis/`) en via "wachtwoord vergeten" bij elke website
nieuwe wachtwoorden instellen.

---

## Hoe de beveiliging werkt

In gewone taal:

1. Je hoofdwachtwoord wordt met **Argon2id** (64 MiB geheugen, 3 rondes,
   4 lanes, een willekeurige salt van 32 bytes) omgezet in een sleutel van
   256 bits. Argon2id is expres traag en gebruikt veel geheugen. Raden met
   dure videokaarten wordt daardoor erg kostbaar.
2. **Twee lagen versleuteling.** Uit die sleutel worden met HKDF-SHA256 twee
   aparte sleutels gemaakt:
   - de **bestandssleutel** versleutelt de hele kluis op schijf;
   - de **itemsleutel** versleutelt daarnaast **elk wachtwoord en elke notitie
     apart**, elk met een eigen willekeurige nonce.

   Ook als je kluis open is (bijvoorbeeld in `kluis shell`), staan wachtwoorden
   en notities dus alleen versleuteld in het geheugen. Ze worden pas
   ontsleuteld op het moment dat jij er één opvraagt (`get`, `get --show`)
   en meteen daarna weer gewist. `list` en `search` ontsleutelen nooit een
   wachtwoord. Getest: in het geheugen van een geopende kluis staat
   het wachtwoord 0 keer als leesbare tekst, ook direct na `get --show`.
3. De hele kluis wordt met **XChaCha20-Poly1305** versleuteld. Dat versleutelt
   en controleert tegelijk ("authenticated encryption"). Verandert er ook maar
   één bit in het bestand, dan weigert `kluis` het te openen. Bij elke keer
   opslaan hoort een nieuwe willekeurige nonce.
4. Het bestand begint met een header met versienummer en instellingen. Die
   header telt mee in de controle, dus ook daar valt niet mee te knoeien.
5. Opslaan gaat **atomisch**: eerst naar een tijdelijk bestand, dan `fsync`,
   dan hernoemen. Bij stroomuitval heb je altijd óf de oude, óf de nieuwe kluis.
6. Bestanden krijgen rechten 600, de map 700. Alleen jij kunt erbij.
7. In het geheugen worden geheimen na gebruik gewist (`zeroize`, `secrecy`
   en een allocator die al het vrijgegeven geheugen wist). De sleutel en de
   ontsleutelde kluis staan in met `mlock` vergrendeld geheugen, dus niet in
   swap. Core dumps staan uit en andere programma's kunnen niet in het
   geheugen meekijken (`PR_SET_DUMPABLE=0`).
8. Alle willekeur komt van het besturingssysteem (`getrandom`).
9. `kluis` maakt nooit een netwerkverbinding.

De gebruikte crates (onder andere `argon2`, `chacha20poly1305`, `hkdf`, `sha2`, `blake2`,
`zeroize` en `subtle`) komen van het RustCrypto-project. `kluis` implementeert
zelf geen cryptografie. Meer details staan in [`docs/ONTWERP.md`](docs/ONTWERP.md).

---

## Security-review en resterende risico's

Ik heb de code zelf doorgelopen en daarbij drie problemen gevonden en opgelost:

| Gevonden | Opgelost |
|---|---|
| In `kluis shell` werkte de inactiviteitstimer niet als je midden in een vraag wegliep (bijv. bij "Gebruikersnaam:") | Een waakhond vergrendelt nu ook dan, en zet de terminal netjes terug |
| Als het wis-hulpproces niet kon starten, bleef het wachtwoord onbeperkt op het klembord staan | Het klembord wordt dan meteen gewist |
| Een kwaadaardig import- of CSV-bestand kon stuurtekens (ANSI-escapes) bevatten die je terminal manipuleren | Ze worden bij import geweigerd of vervangen, en bij `--show` zichtbaar gemaakt als `\u{1b}` |

Ook gecontroleerd en in orde: er bestaat geen enkele optie die een
wachtwoord als argument accepteert (daar is een test voor). Een verkeerd
wachtwoord en een gemanipuleerd bestand geven bewust dezelfde melding.
Vergelijkingen van geheimen zijn constant-time. Kapotte bestanden geven nette
foutmeldingen (getest met elke bitflip en elke afgekapte lengte).
Symlinks worden geweigerd. Gelijktijdig schrijven vanuit twee terminals wordt
opgemerkt. `cargo audit` meldt geen bekende kwetsbaarheden.

**Resterende risico's** (hier kan geen enkele wachtwoordmanager volledig
tegen beschermen):

1. **Malware en keyloggers.** Draait er kwaadaardige software onder jouw
   gebruiker of als root, dan kan die je hoofdwachtwoord onderscheppen terwijl
   je het typt, of je geheugen en klembord lezen. Installeer alleen software
   die je vertrouwt.
2. **Swap en slaapstand (hibernate).** De sleutels en de ontsleutelde kluis
   staan in vergrendeld geheugen, en wachtwoorden en notities blijven ook in
   het geheugen versleuteld. Namen, gebruikersnamen en URL's van een geopende
   kluis, het ene wachtwoord dat je net opvraagt en het geheugen van Argon2
   zijn niet vergrendeld en kunnen in swap belanden. Bij hibernatie gaat al het geheugen naar schijf. Gebruik
   versleutelde swap (LUKS), zram, of helemaal geen swap.
3. **Het klembord.** Zolang een wachtwoord op het klembord staat (max. 20 s),
   kan elk programma in je sessie het lezen. Klembordbeheerders (KDE Klipper,
   cliphist, CopyQ, GNOME-extensies) bewaren soms een **geschiedenis** die
   `kluis` niet kan wissen. Zet die uit of sluit `kluis` uit.
4. **Meekijken en scrollback.** `--show` zet het wachtwoord op je scherm en
   in de scrollback van je terminal.
5. **Een zwak of uitgelekt hoofdwachtwoord.** Alles staat of valt met je
   hoofdwachtwoord. Gebruik het nergens anders.
6. **Fysieke toegang tot een draaiende, ontgrendelde computer.** Vergrendel
   je scherm. Cold-boot- en DMA-aanvallen vallen buiten het bereik.
7. **Back-ups met een oud wachtwoord** blijven met dat oude wachtwoord te
   openen (zie [Back-ups](#back-ups)).
8. **Bestandssysteem.** Op SSD's en copy-on-write-systemen (btrfs, ZFS) kan
   oude, onversleutelde data (zoals een CSV-export) blijven bestaan.
   Schijfversleuteling (LUKS) lost dat op.
9. **Root en het besturingssysteem.** Root kan alles, ook `ptrace` en
   geheugen lezen. `PR_SET_DUMPABLE=0` beschermt alleen tegen andere processen
   van dezelfde gebruiker.
10. **Deze code is niet extern geaudit.** De cryptografie komt uit
    geaudite crates, maar de lijm eromheen is door mij geschreven en alleen
    door mezelf gereviewd.

---

## Problemen oplossen

| Melding | Oplossing |
|---|---|
| `geen klembord gevonden` | Installeer `wl-clipboard` (Wayland) of `xclip` (X11), of gebruik `--show`. Controleer met `kluis info`. |
| `Het geheugen kon niet worden vergrendeld (mlock)` | Je limiet is te laag. Bekijk met `ulimit -l` (Arch-standaard: 8192 KiB, ruim genoeg). Verhogen kan in `/etc/security/limits.conf`. |
| `verkeerd hoofdwachtwoord, of het bestand is beschadigd` | Controleer Caps Lock en je toetsenbordindeling. Is het bestand beschadigd? Probeer `--vault …/vault.enc.bak` of een back-up. |
| `de kluis is intussen door een ander kluis-proces gewijzigd` | Je had twee terminals open. Voer de opdracht opnieuw uit. Je andere wijziging is bewaard. |
| `is een symbolische link` | Geef het echte pad op met `--vault`. |
| Na Ctrl+C zie je je getypte tekst niet meer | Typ `reset` en druk op Enter. |

---

## Voor later

Bewust nog niet in versie 1 (liever weinig functies die goed werken):

- **TUI** met [ratatui](https://ratatui.rs): de bibliotheek (`src/lib.rs`) is
  al los van de CLI, dus een TUI kan er zo bovenop.
- **TOTP** (tweestapscodes, zoals Google Authenticator).
- **Browser-integratie** (automatisch invullen).
- Meerregelige notities in een editor (`$EDITOR`).
- Nederlandse diceware-woordenlijst.
- Aanpasbare klembordtijd en een `--clip-time`-optie.
- Signaal voor klembordbeheerders dat het om een wachtwoord gaat
  (`x-kde-passwordManagerHint`).
- Manpagina (`clap_mangen`).
- Synchronisatie tussen apparaten (bijv. via Syncthing, met conflictdetectie).

---

## Projectstructuur

```text
src/
├── lib.rs          kernbibliotheek (herbruikbaar voor TUI/GUI)
├── error.rs        foutmeldingen (zonder geheimen)
├── secure_mem.rs   wissende allocator, mlock, core dumps uit   ← kritiek
├── crypto.rs       Argon2id + XChaCha20-Poly1305               ← kritiek
├── format.rs       bestandsformaat met versie-header           ← kritiek
├── storage.rs      XDG-pad, atomisch schrijven, back-up, slot  ← kritiek
├── vault.rs        items en bewerkingen
├── generator.rs    wachtwoorden en passphrases                 ← kritiek
├── import.rs       CSV-import
├── clipboard.rs    klembord met automatisch wissen             ← kritiek
├── main.rs         start: allocator + procesbeveiliging
└── cli/            argumenten, prompts, opdrachten, shell-modus
tests/cli.rs        integratietests met het echte programma
packaging/arch/     PKGBUILD
assets/             EFF-woordenlijst (CC BY 3.0 US)
docs/ONTWERP.md     ontwerp en dreigingsanalyse
PROGRESS.md         voortgang en wat nog op Arch getest moet worden
```

Ontwikkelen:

```bash
cargo test                                   # alle tests
cargo clippy --all-targets -- -D warnings    # lint
cargo audit                                  # bekende kwetsbaarheden (cargo install cargo-audit)
```

## Licentie

MIT, zie [`LICENSE`](LICENSE). De EFF-woordenlijst valt onder CC BY 3.0 US,
zie [`assets/README.md`](assets/README.md).
