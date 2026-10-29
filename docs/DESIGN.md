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
├── crypto.rs       Argon2id + HKDF + XChaCha20-Poly1305 (RustCrypto crates)
├── format.rs       versioned file header, key derivation (HKDF), migration v1 → v2
├── vault.rs        items (login/api/note); all content encrypted per field
├── storage.rs      XDG path, atomic writes, backup, file lock
├── generator.rs    passwords and diceware passphrases
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
| Key derivation | Argon2id v1.3, default m=64 MiB, t=3, p=4, 32-byte salt | Resistant to GPU guessing; the parameters are in the header and configurable |
| Encryption | XChaCha20-Poly1305, a new random 24-byte nonce on every save | Authenticated encryption; a random 24-byte nonce is safe |
| Header | The complete header is the AEAD "associated data" | Any change, also to the parameters, is noticed |
| Key separation | HKDF-SHA256 derives a file key and an item key from the Argon2 key | Every key serves one purpose |
| Second layer | All content of every item (username, e-mail address, URL, password/API key, notes) is encrypted per field (XChaCha20-Poly1305, own nonce, field name as associated data) | Even in an open vault the content is only encrypted in memory; decryption happens per field, at the moment it is needed |
| Item types | login, api, note (content schema 4, with the encrypted e-mail field) | One vault for passwords, API keys and secure notes |
| Login screen | 3D-rendered logo (own small renderer, no extra crates), only in a color terminal | Pretty, but never in scripts or pipes; clears the screen when locking |
| Screen mode (TUI) | `cakepass` opens a full-screen view driven by arrow keys, Enter, Esc and visible letter shortcuts (list + details, form, generator, settings, dialogs, a key-hint line and `?` help). The line mode stays as `cakepass shell` / `--no-tui`, and is used automatically for pipes, `TERM=dumb` and windows under 60×16 | Usable without knowing any command; scripts and power users keep the old interface |
| No TUI library | Written on `libc` (termios raw mode, `poll`, `ioctl(TIOCGWINSZ)`, `read`/`write`, `sigaction`) and plain ANSI/VT escape codes; no ratatui, crossterm or ncurses | No new dependency to audit or to keep secrets in buffers we do not control; small binary (+4 % on the release build); every byte that reaches the terminal goes through our own wiped buffer |
| Screen-mode secrets | Decrypt per frame only what is drawn (visible list rows' usernames, the selected item's fields); password/key/notes only while revealed (10 s, hidden on selection change, dialogs, other screens, lock). The cell grid is wiped on every redraw and on drop, the output buffer after each `write(2)`; input buffers are wiped as bytes are consumed | Nothing decrypted lingers; a memory scan after reveal/hide/edit finds 0 readable copies of the secrets |
| Screen-mode safety nets | Alternate screen (secrets never reach the scrollback), screen + scrollback cleared on exit, bracketed paste (pasted text is never a shortcut), terminal restored on exit, error, panic hook and SIGINT/SIGTERM/SIGHUP/SIGQUIT (handlers only set a flag), idle lock by monotonic and wall-clock time plus a watchdog | A crash or a signal never leaves a broken terminal or an open vault; a sleeping laptop still locks |
| Settings | `~/.config/cakepass/config`, plain `key=value`, forgiving parser | Preferences only (animation, lock timeout); a damaged file can never stop the program |
| Setup wizard | `cakepass setup` asks animation, lock timeout, master password; works from stdin too | An easy start for new users, scriptable and testable |
| Migration | Format 1 and content schema 1/2 are converted automatically on opening to format 2 / schema 4 (schema 3 only gains an empty encrypted e-mail field) | Existing vaults keep working |
| Names on disk | The vault file keeps the stable magic `KLUISVLT` and the HKDF labels of the first release (Dutch text) | They are part of the cryptographic format; changing them would lock existing vaults. The folder names did change (`kluis` → `cakepass`) and old folders are moved automatically |
| Generated passwords | A menu in terminals (view / edit / regenerate / copy / save); none in scripts | You can fix a password that a website rejects before it is saved, scripts keep working |
| Randomness | Only `getrandom` (OS CSPRNG) | No own or weak RNG |
| Memory | Wiping global allocator + `SecureBuf` (mlock, MADV_DONTDUMP) + `secrecy`/`zeroize` | As few copies of secrets in RAM and swap as possible |
| Process | `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0` | No core dumps, no ptrace by other processes of the same user |
| Storage | `$XDG_DATA_HOME/cakepass/vault.enc` (default `~/.local/share/cakepass/`), directory 700, file 600 | XDG convention, only you can access it |
| Writing | Temporary file → fsync → rename → fsync of the directory; the previous version becomes `vault.enc.bak` | Never a half-written vault |
| Concurrency | `flock` + a check whether the file changed in the meantime | Two terminals do not overwrite each other's work |
| Contents | JSON (inside the encryption) | Simple, easy to migrate |
| Locking | Every single command asks for the master password; `cakepass shell` locks after inactivity (default 5 min, configurable) | No background service with the key in memory |
| Clipboard | `wl-copy` (Wayland) or `xclip` (X11); a detached helper clears after 20 s, but only if the clipboard still holds our password (BLAKE2b hash, constant-time comparison) | Your password does not linger, and we never wipe something you copied yourself later |
| Password input | Hidden prompt via `/dev/tty` (rpassword) or stdin in a pipe; never via arguments or environment variables | Not visible in `ps`, shell history or `/proc/<pid>/environ` |
| Installer | `install.sh` wrapped in `main()` and run on its last line; uses the user's own GitHub access; never touches the vault | A truncated download cannot run half a script; no tokens are stored |
| Updates | `cakepass --update` = `git fetch` + `git merge --ff-only` + `makepkg` (with tests), extra vault backup first, restore on failure | Safe, reviewable updates without network code in the program |

## Threat analysis

### What `cakepass` protects against

1. **Theft of the vault file or the backup** (lost laptop, stolen backup disk,
   accidentally synced). Without the master password the contents are
   unreadable. How strong that is depends on your master password. That is why
   `setup`/`init` require a strong password (zxcvbn score 3 or higher).
2. **Tampering with the file.** Every changed bit, also in the header, gives an
   error instead of wrong data.
3. **Peeking via `ps`, shell history or environment variables.** Secrets never
   go through arguments.
4. **Other users on the same computer.** File permissions 600/700.
5. **Core dumps and ptrace by other processes of the same user** (without root).
6. **Passwords lingering on the clipboard.** The clipboard is cleared after 20 seconds.
7. **A broken or hostile import file.** All items are validated; control
   characters are rejected or neutralized.

### What `cakepass` partially protects against

- **Swap and hibernation.** mlock keeps the key and the decrypted vault out of
  swap as long as the limit allows it. Item content stays encrypted in memory.
  Item names and tags, the one field just requested and Argon2's working memory
  are not locked and may end up in swap. Use encrypted swap or no swap.
- **Clipboard managers** (KDE Klipper, cliphist, etc.) may keep a history.
  `cakepass` clears the clipboard, but not their history.
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
- A weak master password combined with a stolen vault file.
- Physical attacks on a running computer (cold boot, DMA).
- A forgotten master password: recovery is impossible, which is exactly the point.
