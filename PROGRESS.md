# Voortgang `kluis`

Laatst bijgewerkt: stap 1 (crypto-kern).
Branch: `claude/kluis-v1`

## Klaar

- [x] **Stap 1 – Crypto-kern**: `secure_mem` (wissende allocator, mlock-buffer,
  core dumps uit), `crypto` (Argon2id + XChaCha20-Poly1305), `format`
  (versioneerde header als associated data). 20 unit-tests, waaronder de
  officiële Argon2id-testvector uit RFC 9106 en tests waarin elke bitflip en
  elke afgekapte lengte moet falen.

## Nog te doen

- [ ] Stap 2 – Opslag en kluismodel (XDG, atomisch schrijven, back-up, slot)
- [ ] Stap 3 – CLI (alle opdrachten, klembord, shell-modus, completions)
- [ ] Stap 4 – Packaging (PKGBUILD), README, security-review

## Gemaakte keuzes

Zie `docs/ONTWERP.md` voor de uitleg. Kort samengevat:

- Programmanaam `kluis`, kluis in `~/.local/share/kluis/vault.enc`.
- Argon2id m=64 MiB, t=3, p=4 (instelbaar, minimaal 8 MiB), salt van 32 bytes.
- XChaCha20-Poly1305 met een nieuwe nonce bij elke keer opslaan.
- `rust-version` is 1.88, omdat oudere versies van de crate `time` een
  bekende kwetsbaarheid hebben (RUSTSEC-2026-0009). Arch heeft altijd de
  nieuwste Rust, dus dat is geen probleem.
- EFF-diceware-woordenlijst opgenomen in `assets/` (gecontroleerd tegen twee
  onafhankelijke bronnen; sha256 `addd3553…996b903e`).

## Controles (laatste stap)

| Controle | Resultaat |
|---|---|
| `cargo test` | 20 geslaagd |
| `cargo clippy --all-targets -- -D warnings` | geen meldingen |
| `cargo audit` | geen kwetsbaarheden |

## Testen op Arch

Dit kon in de cloudomgeving NIET getest worden. Doe dit zelf op je Arch-pc:

- [ ] `cargo build --release` op een schone Arch-installatie
- [ ] mlock-limiet: `ulimit -l` (verwacht 8192 KiB op een standaard Arch met systemd)
