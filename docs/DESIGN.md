# Design and threat analysis of `cakepass` (CakePass)

## Goal

`cakepass` is an offline password manager for the terminal on Arch Linux. There is
no cloud, no telemetry and no network code. Everything lives in one encrypted
file. The only thing that ever talks to the network is `git`, started by
`cakepass --update` while the vault is closed.

## Architecture

```text
install.sh          one-line installer (curl | bash)
build.rs            records the git commit the program was built from
src/
├── lib.rs          core library (reusable for a later TUI/GUI)
├── error.rs        a single error type, messages without secrets
├── secure_mem.rs   wiping allocator, mlock buffer, core dumps off
├── crypto.rs       Argon2id + HKDF + XChaCha20-Poly1305 (RustCrypto crates),
│                   security levels, memory guard, key-file pepper
├── keyfile.rs      key files: reading (strict rules) and creating
├── format.rs       versioned file header (v3: key-file flag), key derivation (HKDF),
│                   migration v1 → v3, v2 → v3
├── vault.rs        items (login/api/card/identity/ssh-key/note); all content encrypted
│                   per field; the favorite flag is plain metadata like the tags
├── totp.rs         two-factor codes: TOTP (RFC 6238) over HOTP (RFC 4226), base32
├── storage.rs      XDG path, atomic writes, backup, file lock
├── generator.rs    passwords and diceware passphrases
├── audit.rs        password health check: weak, reused, stale, empty (names only)
├── import.rs       CSV import from other managers
├── clipboard.rs    wl-copy / xclip, automatic clearing
├── main.rs         starts the CLI (allocator + process hardening)
└── cli/            arguments (clap), prompts, commands, line mode (shell.rs)
    ├── setup.rs    first-time setup wizard and `cakepass config`
    ├── config.rs   settings file (animation, lock timeout)
    ├── logo.rs     the 3D login screen
    ├── update.rs   `cakepass --update` (git + makepkg)
    └── tui/        the screen mode (`cakepass`): arrow keys, no extra crates
        ├── term.rs     raw mode, alternate screen, signals, read/write (libc)
        ├── keys.rs     bytes → keys (escape sequences, UTF-8, bracketed paste)
        ├── grid.rs     frame buffer + diff (only changed cells, one write)
        ├── input.rs    text fields (UTF-8 safe, masked, multi-line)
        ├── theme.rs    colors (NO_COLOR) and box characters (ASCII fallback)
        ├── app.rs      state machine: keys + time in, frame out (unit-tested)
        └── screens/    list + details, form, generator, settings, dialogs
```

The CLI is a thin layer. All security logic lives in the library.

## Key decisions

| Topic | Choice | Why |
|---|---|---|
| Key derivation | Argon2id v1.3, 32-byte salt; named levels Standard (m=64 MiB), High (256 MiB, default for new vaults) and Maximum (1 GiB), all t=3, p=4; custom values with `--kdf-*` | Resistant to GPU guessing; memory is what makes each guess expensive. The parameters are in the header, so every vault keeps its own |
| Memory guard | Before Argon2 runs (opening, creating, re-keying, measuring), refuse when it would need more than 75 % of `MemAvailable` | A vault made at Maximum on a big desktop must give a clear message on a small laptop, not get OOM-killed halfway; 4 GiB stays the hard cap against tampered headers |
| Key file (optional) | pepper = BLAKE2b-256(le64(19) ‖ "cakepass keyfile v1" ‖ le64(n) ‖ file), passed to Argon2id as its secret input K; header flag bit 0 says it is required | A second secret "at rest": a stolen vault file is useless without it. Argon2's own K input mixes it in natively (no own construction). Only the path is stored; the file is re-read when needed and the pepper wiped after each Argon2 run. Wrong key file = the same `Decrypt` error as a wrong password (no fingerprint that would tell which is wrong) |
| Format 3 | A flags byte after the version, inside the authenticated header; unknown bits refused | The key-file requirement cannot be stripped or added unnoticed; v2 HKDF labels kept, so v2 → v3 needs no item re-encryption |
| Re-keying | `UnlockedVault::rekey` (new password, key file and/or level; fresh salt; all items re-sealed; `.bak` re-encrypted) used by `passwd`, `security` and the screen mode | One code path for every change of secrets; nothing is left that opens with the old secrets |
| Unlock time | Measured on this computer (one Argon2 run with a throw-away salt) only when a level is shown or chosen, never at program start | Honest numbers for the user's own machine, without slowing every start |
| Passphrase offer | The setup wizard offers 7 EFF diceware words (≈ 90.5 bits), shown once, typed back before the vault is created | Most people do not choose 90-bit passwords themselves; typing it back proves it was written down |
| Encryption | XChaCha20-Poly1305, a new random 24-byte nonce on every save | Authenticated encryption; a random 24-byte nonce is safe |
| Header | The complete header is the AEAD "associated data" | Any change, also to the parameters, is noticed |
| Key separation | HKDF-SHA256 derives a file key and an item key from the Argon2 key | Every key serves one purpose |
| Second layer | All content of every item (username, e-mail address, URL, password/API key/card number/private key, notes, expiry date, CVV, public key, key passphrase, TOTP secret) is encrypted per field (XChaCha20-Poly1305, own nonce, field name as associated data) | Even in an open vault the content is only encrypted in memory; decryption happens per field, at the moment it is needed |
| Item types | login, api, card, identity, ssh-key, note (content schema 5). A card and an SSH key reuse the generic fields where they fit (cardholder = username, card number / private key = the password field, host = URL) and add only what has no place yet: expiry date + CVV, public key + key passphrase. An identity (passport, ID card, licence, IBAN, membership) needs nothing new: full name = username, number = the password field, issuer = URL, plus the card's expiry field, so it came without a schema change. Every item has every field (unused ones hold an encrypted empty string) | One vault for passwords, API keys, bank cards, identity documents, SSH keys and secure notes; one shape for every item keeps validate/re-seal/merge free of per-type special cases, and the main secret of every type goes through the same copy/show path |
| Favorites | A plain `favorite` flag on an item, next to the tags (`#[serde(default)]`, not written while false); not encrypted per field. Pinning does not change the modification date | Organisation, not content, like the tags (the file as a whole is still encrypted). Old vaults read as "no favorites" without any migration, and a vault without favorites is byte-for-byte what it was. The date stays meaningful for the audit |
| Password health check | `cakepass audit`: weak (the same zxcvbn estimate and `MIN_SCORE` 3 as for master passwords), reused (constant-time comparison of the decrypted secrets, as in `merge`), stale (not changed in more than 365 days, `--older-than`) and empty, for logins and API keys only. Offline; prints item names and counts only; exit code 0 | Actionable advice without a network lookup (which this program never does). The decrypted secrets live in `Zeroizing` strings only during the check. Cards, keys and document numbers are not passwords you choose or rotate |
| TOTP | An optional encrypted field on any item (not a type), holding the secret as the user gave it (base32 or an `otpauth://totp` link). Codes per RFC 6238 over RFC 4226 with the RustCrypto `hmac` + `sha1`/`sha2` crates; base32 decoding is our own (an encoding, not a primitive). The secret is parsed when it is stored, codes are computed fresh on every request and never stored; `hotp` and Steam are refused | Like Bitwarden, 1Password and KeePassXC: a 2FA code belongs to one account. Tested against the RFC 6238 Appendix B vectors (SHA-1/256/512) and RFC 4648 base32 vectors. Honest trade-off, documented in the README: secret and password in one vault means one vault holds both factors |
| Login screen | 3D-rendered logo (own small renderer, no extra crates), only in a color terminal | Pretty, but never in scripts or pipes; clears the screen when locking |
| Screen mode (TUI) | `cakepass` opens a full-screen view driven by arrow keys, Enter, Esc and visible letter shortcuts (list + details, form, generator, settings, dialogs, a key-hint line and `?` help). The line mode stays as `cakepass shell` / `--no-tui`, and is used automatically for pipes, `TERM=dumb` and windows under 60×16 | Usable without knowing any command; scripts and power users keep the old interface |
| No TUI library | Written on `libc` (termios raw mode, `poll`, `ioctl(TIOCGWINSZ)`, `read`/`write`, `sigaction`) and plain ANSI/VT escape codes; no ratatui, crossterm or ncurses | No new dependency to audit or to keep secrets in buffers we do not control; small binary (+4 % on the release build); every byte that reaches the terminal goes through our own wiped buffer |
| Screen-mode secrets | Decrypt per frame only what is drawn (visible list rows' usernames, the selected item's fields); password/key/notes only while revealed (10 s, hidden on selection change, dialogs, other screens, lock). The cell grid is wiped on every redraw and on drop, the output buffer after each `write(2)`; input buffers are wiped as bytes are consumed | Nothing decrypted lingers; a memory scan after reveal/hide/edit finds 0 readable copies of the secrets |
| Screen-mode safety nets | Alternate screen (secrets never reach the scrollback), screen + scrollback cleared on exit, bracketed paste (pasted text is never a shortcut), terminal restored on exit, error, panic hook and SIGINT/SIGTERM/SIGHUP/SIGQUIT (handlers only set a flag), idle lock by monotonic and wall-clock time plus a watchdog | A crash or a signal never leaves a broken terminal or an open vault; a sleeping laptop still locks |
| Settings | `~/.config/cakepass/config`, plain `key=value`, forgiving parser | Preferences only (animation, lock timeout, clipboard time, hidden screen tabs); a damaged file can never stop the program. Hidden tabs are navigation only: no item is ever hidden by a setting |
| Man page | `cakepass man` prints roff made by `clap_mangen` from the same clap definition as `--help` and the completions; the PKGBUILD installs it as `cakepass.1` | Never out of date with the real options. A documentation generator in the same family as `clap_complete`: it only reads the command definition and never sees the vault or a secret |
| Setup wizard | `cakepass setup` asks animation, lock timeout, security level, master password (passphrase offered), optional key file; works from stdin too | An easy start for new users, scriptable and testable |
| Migration | Format 1 and content schema 1/2 are converted automatically on opening (schema 3 only gains an empty encrypted e-mail field; schema 4 gains five empty encrypted fields: expiry date, CVV, TOTP secret, public key and key passphrase); format 2 is read as is and written as format 3 on the next save | Existing vaults keep working; merely reading a vault never makes it unreadable for an older binary |
| Names on disk | The vault file keeps the stable magic `KLUISVLT` and the HKDF labels of the first release (Dutch text) | They are part of the cryptographic format; changing them would lock existing vaults. The folder names did change (`kluis` → `cakepass`) and old folders are moved automatically |
| Generated passwords | A menu in terminals (view / edit / regenerate / copy / save); none in scripts | You can fix a password that a website rejects before it is saved, scripts keep working |
| Randomness | Only `getrandom` (OS CSPRNG) | No own or weak RNG |
| Memory | Wiping global allocator + `SecureBuf` (mlock, MADV_DONTDUMP) + `secrecy`/`zeroize`; key-file contents and pepper only in `SecureBuf`; the `blake2` `zeroize` feature and a 64 KiB stack scrub after Argon2 | As few copies of secrets in RAM and swap as possible. A scan of the release build (idle, unlocked, key-file vault) finds the master password, key file bytes and pepper 0 times |
| Process | `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0` | No core dumps, no ptrace by other processes of the same user |
| Storage | `$XDG_DATA_HOME/cakepass/vault.enc` (default `~/.local/share/cakepass/`), directory 700, file 600 | XDG convention, only you can access it |
| Writing | Temporary file → fsync → rename → fsync of the directory; the previous version becomes `vault.enc.bak` | Never a half-written vault |
| Concurrency | `flock` + a check whether the file changed in the meantime | Two terminals do not overwrite each other's work |
| Contents | JSON (inside the encryption) | Simple, easy to migrate |
| Locking | Every single command asks for the master password; `cakepass shell` locks after inactivity (default 5 min, configurable) | No background service with the key in memory |
| Clipboard | `wl-copy` (Wayland) or `xclip` (X11); a detached helper clears after 20 s (`config set clip-time`: 5–300 s, passed to the helper as an argument and clamped again there), but only if the clipboard still holds our password (BLAKE2b hash, constant-time comparison). With `wl-copy` 2.3 or newer the content is marked sensitive (`--sensitive`: it also offers the `x-kde-passwordManagerHint` type; an older `wl-copy`, found from its `--help`, copies without it) | Your password does not linger, and we never wipe something you copied yourself later. A bad setting or argument can never mean "never" or "after a day". Clipboard histories that respect the hint (KDE Klipper, Omarchy's clipboard history) do not store the password at all; `xclip` cannot offer the hint next to the text (it advertises one target only), so X11 lacks this |
| Password input | Hidden prompt via `/dev/tty` (rpassword) or stdin in a pipe; never via arguments or environment variables | Not visible in `ps`, shell history or `/proc/<pid>/environ` |
| Installer | `install.sh` wrapped in `main()` and run on its last line; uses the user's own GitHub access; never touches the vault | A truncated download cannot run half a script; no tokens are stored |
| Updates | `cakepass --update` = `git fetch` + `git merge --ff-only` + `makepkg` (with tests), extra vault backup first, restore on failure | Safe, reviewable updates without network code in the program |

## Threat analysis

### What `cakepass` protects against

1. **Theft of the vault file or the backup** (lost laptop, stolen backup disk,
   accidentally synced). Without the master password the contents are
   unreadable. How strong that is depends on your master password (the attacker
   can guess offline; Argon2id at the vault's level sets the price per guess).
   That is why `setup`/`init` require a strong password (zxcvbn score 3 or
   higher) and the wizard offers a 7-word passphrase. With a **key file** kept
   elsewhere, a stolen vault file alone cannot be attacked at all (256 more
   bits to guess).
2. **Tampering with the file.** Every changed bit, also in the header, gives an
   error instead of wrong data.
3. **Peeking via `ps`, shell history or environment variables.** Secrets never
   go through arguments.
4. **Other users on the same computer.** File permissions 600/700.
5. **Core dumps and ptrace by other processes of the same user** (without root).
6. **Passwords lingering on the clipboard.** The clipboard is cleared after 20 seconds
   (configurable from 5 to 300 seconds; "never" is not possible).
7. **A broken or hostile import file.** All items are validated; control
   characters are rejected or neutralized.

### What `cakepass` partially protects against

- **Swap and hibernation.** mlock keeps the key and the decrypted vault out of
  swap as long as the limit allows it. Item content stays encrypted in memory.
  Item names and tags, the one field just requested and Argon2's working memory
  (up to 1 GiB, far above the mlock limit; wiped when Argon2 is done) are not
  locked and may end up in swap while in use. Use encrypted swap or no swap.
- **Theft of the vault file together with the key file** (both on the same
  disk or backup): then only the master password protects it.
- **Clipboard managers** may keep a history. `cakepass` clears the clipboard,
  but not their history. Under Wayland it marks what it copies as sensitive
  (`wl-copy --sensitive`, the `x-kde-passwordManagerHint` convention), and
  histories that respect that (KDE Klipper, Omarchy's) skip it; histories
  that ignore it, and every history under X11 (`xclip` cannot set the
  hint) may still keep it.
- **Two-factor authentication, when its TOTP secret is stored here.** The
  secret is as well protected as the password next to it, but someone who
  opens the vault then has both factors of that account. That is the user's
  choice per account; the README says so.
- **Terminal scrollback** when you use `--show` yourself. Locking the
  line mode clears the screen and scrollback. The screen mode draws on the
  alternate screen (not in the scrollback) and clears the screen on exit, but a
  revealed secret is visible while it is shown, and terminal recorders or the
  terminal emulator's own memory are outside our control.
- **A compromised GitHub account.** `cakepass --update` shows what changes and asks
  for confirmation, and the daily check never installs anything, but you
  install code from your own repository. Use two-factor authentication.

### What `cakepass` does NOT protect against

- Malware or keyloggers running under your user or as root.
- Someone who knows or shoulder-surfs your master password.
- A weak master password combined with a stolen vault file, when no key file
  is used (or the key file was stolen too).
- An "evil maid" who changes the computer or the CakePass program while you
  are away, and coercion ("rubber-hose").
- A lost key file without a copy: the vault is then lost, by design.
- Physical attacks on a running computer (cold boot, DMA).
- A forgotten master password: recovery is impossible, which is exactly the point.

## Strength, honestly

The full explanation for users, with a table of rough attack costs and its
assumptions, is in the README section "How strong is this, really?". In short:

- XChaCha20-Poly1305 with 256-bit keys is in the same strength class as the
  AES-256 that banks use for data at rest; banks additionally keep keys in
  HSMs and only expose online interfaces. "Better than banks" is not a claim
  a cipher swap can honestly support. The weak point of any offline vault is
  offline guessing of the master password, so the work went into making that
  expensive (levels) or impossible without a second secret (key file).
- Rough attacker model used in the docs: a top consumer GPU at its memory
  bandwidth limit (~1 TB/s) manages about 1,300 / 330 / 80 Argon2id guesses
  per second at Standard / High / Maximum (memory traffic ≈ 4 × m × t per
  guess). Real tools are slower; the estimate favours the attacker.
- Quantum: everything is symmetric or hash-based; 256-bit keys keep about
  128 bits against Grover. No RSA/ECC is used anywhere.
- Deliberately not done: cascaded ciphers, own constructions, extra hash
  iterations, a key-commitment tag (XChaCha20-Poly1305 is not key-committing;
  that matters for multi-key/multi-recipient settings, not for one local file
  under one key whose header is already associated data), hardware tokens
  (a possible later addition).
- Measured unlock times (release build, 4-core 2.1 GHz Xeon cloud VM):
  Standard ≈ 0.2 s, High ≈ 0.8 s, Maximum ≈ 3.7 s. The argon2 crate is used
  without its `parallel` (rayon) feature, so the 4 lanes are computed one after
  another; an attacker's cost does not depend on that. Wiping Argon2's freed
  memory adds about 5–10 %.
