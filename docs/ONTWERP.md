# Ontwerp en dreigingsanalyse van `kluis`

## Doel

`kluis` is een offline wachtwoordmanager voor de terminal op Arch Linux. Er is
geen cloud, geen telemetrie en geen netwerkcode. Alles staat in één versleuteld
bestand.

## Architectuur

```text
src/
├── lib.rs          kernbibliotheek (herbruikbaar voor een latere TUI/GUI)
├── error.rs        één fouttype, meldingen zonder geheimen
├── secure_mem.rs   wissende allocator, mlock-buffer, core dumps uit
├── crypto.rs       Argon2id + XChaCha20-Poly1305 (RustCrypto-crates)
├── format.rs       versioneerde bestandskop, sleutelafleiding (HKDF), migratie v1 → v2
├── vault.rs        items; wachtwoord en notities per item versleuteld
├── storage.rs      XDG-pad, atomisch schrijven, back-up, bestandsslot
├── generator.rs    wachtwoorden en diceware-passphrases
├── import.rs       CSV-import uit andere managers
├── clipboard.rs    wl-copy / xclip, automatisch wissen
├── main.rs         start de CLI (allocator + procesbeveiliging)
└── cli/            argumenten (clap), prompts, opdrachten, shell-modus
```

De CLI is een dunne laag. Alle beveiligingslogica zit in de bibliotheek.

## Belangrijke keuzes

| Onderwerp | Keuze | Waarom |
|---|---|---|
| Sleutelafleiding | Argon2id v1.3, standaard m=64 MiB, t=3, p=4, salt van 32 bytes | Bestand tegen raden met GPU's; parameters staan in de header en zijn instelbaar |
| Versleuteling | XChaCha20-Poly1305, nieuwe willekeurige nonce van 24 bytes per keer opslaan | Authenticated encryption; een willekeurige nonce van 24 bytes is veilig |
| Header | Volledige header is AEAD "associated data" | Elke wijziging, ook aan de parameters, valt op |
| Sleutelscheiding | HKDF-SHA256 leidt uit de Argon2-sleutel een bestandssleutel en een itemsleutel af | Elke sleutel dient één doel |
| Tweede laag | Alle inhoud van elk item (gebruikersnaam, URL, wachtwoord/API-sleutel, notities) per veld apart versleuteld (XChaCha20-Poly1305, eigen nonce, veldnaam als associated data) | Ook in een geopende kluis staat de inhoud alleen versleuteld in het geheugen; ontsleutelen gebeurt per veld, op het moment dat het nodig is |
| Soorten items | login, api, notitie (schema 3) | Eén kluis voor wachtwoorden, API-sleutels en beveiligde notities |
| Inlogscherm | 3D-gerenderd logo (eigen kleine renderer, geen extra crates), alleen in een kleurenterminal | Mooi, maar nooit in scripts of pipes; wist het scherm bij vergrendelen |
| Migratie | Formaat 1 en inhoudsschema 1/2 worden bij openen automatisch omgezet naar formaat 2 / schema 3 | Bestaande kluizen blijven werken |
| Willekeur | Alleen `getrandom` (OS-CSPRNG) | Geen eigen of zwakke RNG |
| Geheugen | Wissende globale allocator + `SecureBuf` (mlock, MADV_DONTDUMP) + `secrecy`/`zeroize` | Zo weinig mogelijk kopieën van geheimen in RAM en swap |
| Proces | `RLIMIT_CORE=0` en `PR_SET_DUMPABLE=0` | Geen core dumps, geen ptrace door andere processen van dezelfde gebruiker |
| Opslag | `$XDG_DATA_HOME/kluis/vault.enc` (standaard `~/.local/share/kluis/`), map 700, bestand 600 | XDG-conventie, alleen jij kunt erbij |
| Schrijven | Tijdelijk bestand → fsync → rename → fsync van de map; vorige versie wordt `vault.enc.bak` | Nooit een half geschreven kluis |
| Gelijktijdigheid | `flock` + controle of het bestand intussen veranderd is | Twee terminals overschrijven elkaars werk niet |
| Inhoud | JSON (binnen de versleuteling) | Eenvoudig, goed te migreren |
| Vergrendelen | Elk los commando vraagt het hoofdwachtwoord; `kluis shell` vergrendelt na inactiviteit (standaard 5 min) | Geen achtergronddienst met de sleutel in het geheugen |
| Klembord | `wl-copy` (Wayland) of `xclip` (X11); een los hulpproces wist na 20 s, maar alleen als het klembord nog ons wachtwoord bevat (vergelijking via BLAKE2b-hash, constant-time) | Je wachtwoord blijft niet hangen, en we wissen niets wat je zelf later kopieerde |
| Wachtwoordinvoer | Verborgen prompt via `/dev/tty` (rpassword) of stdin bij een pipe; nooit via argumenten of omgevingsvariabelen | Niet zichtbaar in `ps`, shellgeschiedenis of `/proc/<pid>/environ` |

## Dreigingsanalyse

### Waartegen `kluis` beschermt

1. **Diefstal van het kluisbestand of de back-up** (laptop kwijt, back-upschijf
   gestolen, per ongeluk gesynchroniseerd). Zonder hoofdwachtwoord is de inhoud
   onleesbaar. Hoe sterk dit is, hangt af van je hoofdwachtwoord. Daarom
   eist `init` een sterk wachtwoord (zxcvbn-score 3 of hoger).
2. **Manipulatie van het bestand.** Elke gewijzigde bit, ook in de header, geeft
   een foutmelding in plaats van verkeerde gegevens.
3. **Meekijken via `ps`, shellgeschiedenis of omgevingsvariabelen.** Geheimen
   gaan nooit via argumenten.
4. **Andere gebruikers op dezelfde computer.** Bestandsrechten 600/700.
5. **Core dumps en ptrace door andere processen van dezelfde gebruiker**
   (zonder root).
6. **Wachtwoorden die in het klembord blijven hangen.** Het klembord wordt na
   20 seconden gewist.

### Waartegen `kluis` gedeeltelijk beschermt

- **Swap en hibernatie.** mlock houdt de sleutel en de ontsleutelde kluis uit de
  swap zolang de limiet dat toelaat. Losse kopieën in normaal heapgeheugen
  (bijvoorbeeld tijdens JSON-verwerking) kunnen nog in swap belanden. Gebruik
  versleutelde swap of geen swap.
- **Klembordbeheerders** (KDE Klipper, cliphist, enz.) kunnen een geschiedenis
  bijhouden. `kluis` wist het klembord, maar niet hun geschiedenis.
- **Terminal-scrollback** als je zelf `--show` gebruikt.

### Waartegen `kluis` NIET beschermt

- Malware of keyloggers die onder jouw gebruiker of als root draaien.
- Iemand die je hoofdwachtwoord kent of afkijkt.
- Een zwak hoofdwachtwoord in combinatie met een gestolen kluisbestand.
- Fysieke aanvallen op een computer die aan staat (cold boot, DMA).
- Een vergeten hoofdwachtwoord: herstel is onmogelijk, dat is precies de bedoeling.
