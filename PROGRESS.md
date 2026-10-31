# Progress: `cakepass` (CakePass)

Last updated: step 11 (security levels, key files, passphrase offer, version 0.4.0).
Repository: `Justcakenl/Password-Manager`, branch `main` (private until it is made public).

## Maintainer checklist: manual testing on a real Arch machine

**Already installed CakePass?** Update and try the new security features:

```bash
cakepass --update        # or run the one-line installer below again
cakepass security        # level, key file, unlock time measured on your laptop
```

Then go through the new "Security levels and key files" checks (step 11) in
the "Testing on Arch" list below. Note: after 0.4.0 has saved your vault once,
CakePass 0.3 can no longer open it (format 3); the `.pre-update-…` copy can.

**First time?** Follow these steps:

1. **Log in to GitHub** (only needed while the repository is private):
   ```bash
   sudo pacman -S --needed github-cli
   gh auth login
   ```
2. **Run the one-line installer**:
   ```bash
   gh api repos/Justcakenl/Password-Manager/contents/install.sh \
     -H "Accept: application/vnd.github.raw" | bash
   ```
   It installs the build tools, downloads the code into `~/cakepass`, builds,
   tests and installs CakePass, and then starts the setup wizard. If something
   fails, copy the error message and open an issue on GitHub. **Keep `~/cakepass`**:
   `cakepass --update` uses it.
3. **In the wizard** choose: animation on or off, the auto-lock minutes, and a
   strong master password (write it on paper too).
4. **Try it** with a throw-away vault first, so the real one stays clean:
   ```bash
   export CAKEPASS_VAULT=/tmp/testvault.enc
   cakepass setup              # answer "Open CakePass now?" with Enter
   #  a → fill in a login → Ctrl+S;  c copies the password (paste it, wait 20 s → empty)
   #  g → generator;  s → settings;  q → quit
   cakepass add Test --generate
   cakepass get Test           # the commands still work as before
   cakepass info
   unset CAKEPASS_VAULT
   ```
5. **Go through the "Testing on Arch" list below** and tick what works.
6. Make a first backup of the real vault (README, "Backups").
7. When happy there is nothing left to do: `cakepass --update` keeps the
   installation current.

## Done

- [x] **Step 1 – Crypto core**: `secure_mem` (wiping allocator, mlock buffer,
  core dumps off), `crypto` (Argon2id + XChaCha20-Poly1305), `format` (versioned
  header as associated data). Tests with the official Argon2id test vector from
  RFC 9106 and tests where every bit flip and every truncated length must fail.
- [x] **Step 2 – Storage and vault model**: `vault` and `storage` (XDG path,
  directory 700/file 600, atomic writes with fsync, automatic `.bak`, `flock`
  plus detection of concurrent changes, symlinks refused).
- [x] **Step 3 – CLI**: `add`, `get`, `edit`, `rm`, `list`, `search`, `generate`,
  `passwd`, `export`, `import`, `import-csv`, `info`, `shell`, `completions`.
  Clipboard via wl-copy/xclip, cleared after 20 s.
- [x] **Step 4 – Packaging and delivery**: PKGBUILD, README, MIT license, a
  security review with three problems found and fixed.
- [x] **Step 5 – Second encryption layer**: HKDF-derived item key; content of
  every item encrypted per field. Memory scan of an open vault: 0 readable copies.
- [x] **Step 6 – More item types + login screen**: API keys and secure notes;
  username and URL encrypted as well (schema 3); 3D login screen; cleared
  screen and scrollback on locking.
- [x] **Step 7 – Update system**: `cakepass --update` (git + makepkg, extra
  backup, restore on failure, never opens the vault), daily check with a
  systemd timer, `cakepass --version` shows the commit. Repository is private
  (checked).
- [x] **Step 8 – Installer, setup wizard, English**:
  - `install.sh`: the one-line installer (works with the script on stdin, as
    `curl | bash` does). It checks the system, installs tools with pacman,
    clones the private repository with *your* GitHub access (gh, SSH or login
    prompt), runs `makepkg -si`, and starts `cakepass setup`. Options `--yes`,
    `--no-setup`, `--dir`, `--branch`, `--uninstall`. Wrapped in `main()` so a
    truncated download never runs half a script.
  - `cakepass setup`: first-time wizard – animation on/off, auto-lock minutes,
    master password (with strength check). Works from stdin too. If a vault
    exists it only asks the first two questions.
  - `cakepass config` / `cakepass config set animation on|off` /
    `cakepass config set lock-timeout <minutes>`; settings in
    `~/.config/cakepass/config`. Animation off = a still logo. `cakepass` with no
    vault starts the wizard in a terminal.
  - **Everything is in English now**: all code, comments, messages, tests,
    README, design doc and packaging files. Fixed cryptographic labels
    (HKDF info strings, file magic `KLUISVLT`) are deliberately unchanged so
    existing vaults keep opening. The backup copies made by `--update` are now
    called `vault.enc.pre-update-<time>`.

- [x] **Step 9 – English commands, e-mail addresses, generate + edit + save**:
  - The command is now **`cakepass`** (it was `kluis`, Dutch for "vault"): binary,
    package, settings folder, environment variables (`CAKEPASS_VAULT`, …) and the
    systemd timer. An existing `~/.local/share/kluis`, `~/.config/kluis` or
    `~/.cache/kluis` folder is **moved automatically** to `cakepass` the first
    time the new program runs, and the installer removes the old `kluis` package
    first. All sub-commands and options were already English.
  - **E-mail addresses**: logins and API keys have an encrypted e-mail field
    (`add -e`, `edit -e`, `get --copy-email`; searchable; CSV import reads an
    `email` column). Content schema 4; vaults of schema 1–3 upgrade
    automatically when opened.
  - **Generate → edit → save**: in a terminal `generate`, `add --generate`,
    an empty password in `add`, and `edit --generate` show a menu (view, edit =
    type your own, regenerate, copy, save/quit). New: `cakepass generate --save
    NAME`. Without a terminal nothing changes (scripts keep working).
  - **Encryption check**: a new test adds every kind of data (login, API key,
    note, e-mail, tags, notes), edits, exports and changes settings, then reads
    **every file the program wrote** and finds no readable data; all files are
    private (no group/other access). Memory scan of an open vault: username,
    e-mail, URL, password, API key and notes found 0 times (the item *name* is
    found, as expected).

- [x] **Step 10 – The screen with arrow keys (TUI), version 0.3.0**:
  - `cakepass` now opens, after the login screen, a full-screen view you use with
    the arrow keys, Enter, Esc and a few letters shown at the bottom (`?` = help):
    tabs All/Logins/API keys/Notes, a list, a details pane (passwords, keys and
    notes as dots until you press Enter; they hide again after 10 s), live search,
    copy (`c`/`u`/`m`, cleared after 20 s), add/edit form (Ctrl+S saves, Ctrl+R
    shows the password, Ctrl+G opens the generator), delete with confirmation
    (default "no"), the generator (`g`; Enter saves a new login, like
    `generate --save`), settings (`s`: animation, auto-lock, change master
    password with re-confirmation and strength check, vault/version info), lock (`l`)
    and quit (`q`, Ctrl+C).
  - **No new dependency**: written on `libc` and ANSI escape codes (raw mode,
    alternate screen, bracketed paste, a cell grid that sends only what changed).
    Release binary +4 %. ASCII fallback without UTF-8, monochrome with `NO_COLOR`.
  - The line mode is now `cakepass shell` (or `cakepass --no-tui`); pipes,
    `TERM=dumb` and windows under 60×16 use it automatically. After the setup
    wizard CakePass offers to open the screen right away.
  - Security: only what is on screen is decrypted (per frame), revealed secrets
    are never kept, the frame and output buffers are wiped, the terminal is
    always restored (exit, error, panic, signals), idle lock also after a laptop
    slept, and when another window changed the vault you can reload it without
    losing what you typed. Memory scan (release build) after reveal, hide and
    edit: password, API key, notes, username, e-mail and URL found 0 times as
    readable text.
  - Tests: key parser, text fields, frame diff, layouts at several sizes, every
    screen, and the whole state machine against a real temporary vault; plus
    `tests/tui.rs`, which runs the real program in a pseudo-terminal (add an item
    with the arrow keys and verify it with `cakepass get`, paste, auto-lock,
    Ctrl+C/SIGTERM restore the terminal, resize, the line-mode fallbacks).

- [x] **Step 11 – Security levels, key files, passphrase offer (version 0.4.0)**.
  Release notes:
  - **Added – security levels.** `standard` (Argon2id 64 MiB), `high` (256 MiB,
    the new default for new vaults) and `maximum` (1 GiB), all t=3, p=4.
    `init`/`setup --level …`; the `--kdf-*` flags still override. The setup
    wizard asks for the level and measures the unlock time on this computer
    once one is chosen. Existing vaults keep their settings.
  - **Added – `cakepass security`.** Shows the level (or "custom"), Argon2
    settings, key file and the unlock time measured now; `--level`,
    `--new-keyfile PATH` and `--no-keyfile` re-key the vault with the same
    master password (fresh salt, all items re-sealed, `.bak` re-encrypted),
    also inside `cakepass shell`.
  - **Added – key files.** `cakepass keyfile create PATH` (64 random bytes,
    never overwrites, mode 600). A vault can require a key file: its pepper
    (BLAKE2b-256 with the label "cakepass keyfile v1") is Argon2id's secret
    input. Given with `--keyfile PATH`, `CAKEPASS_KEYFILE` or the `keyfile`
    setting (`cakepass config set keyfile PATH|none`; only the path is stored).
    Read before the password prompt; clear messages when it is missing,
    unreadable (USB stick not plugged in), a symlink, not a regular file, empty
    or over 1 MiB; a warning when others can read it or it sits next to the
    vault. A wrong key file gives the same error as a wrong password.
  - **Added – memory guard.** Argon2 never runs when it would need more than
    75 % of the free memory (`MemAvailable`): a clear message instead of the
    OOM killer, when opening, creating, re-keying and measuring.
  - **Added – passphrase offer.** The setup wizard offers to make a 7-word
    EFF passphrase (≈ 90 bits), shows it once ("write it down now") and asks to
    type it back before the vault is created; it clears the screen afterwards.
  - **Added – screen mode.** A "Security level" row in settings (← → choose,
    measured the first time a level is shown, Enter applies after the master
    password); key file status; re-checks, password change and reload re-read
    the key file.
  - **Changed – file format 3.** A flags byte (bit 0: key file required) in the
    authenticated header. Formats 1 and 2 stay readable; a format 2 vault is
    written as format 3 on its next save (reading alone does not rewrite it).
    **CakePass 0.3 cannot open format 3.**
  - **Changed.** Export files use the vault's Argon2 settings (never lighter
    than Standard); `info` shows the level and key file; `UnlockedVault::
    change_password` became `rekey`; `KdfParams::DEFAULT` became `STANDARD`
    (plus `HIGH`, `MAXIMUM`) and `weaker_than_default` became
    `weaker_than_standard` (same behaviour: a warning below Standard).
  - **Security.** The `blake2` `zeroize` feature (no new crate) wipes the
    BLAKE2b state Argon2 uses for its first hash, and the stack is scrubbed
    after each Argon2 run. Memory scan of the release build with a key-file
    vault, idle and unlocked (line mode and screen mode, also after re-keying):
    master password, key file bytes (or any 16-byte piece) and pepper found 0
    times. New "How strong is this, really?" section in the README.
  - Tests: known-answer vectors from the reference Argon2 C code (with a
    secret) and Python's BLAKE2b; format 3 bit flips, truncations, flag
    tampering, v1/v2 → v3; key-file file rules; re-keying; the memory guard;
    the wizard via pipes (passphrase typed back, key file); pseudo-terminal
    tests for the settings row and logging in with a key file.

## Still to do

- [ ] Check the "Testing on Arch" list below on your own computer.
- [ ] GitHub repository description still says "Beta-test"; change it in the
  repository settings.
- [ ] Ideas for later: see the README, "For later".

## Decisions made

See `docs/DESIGN.md` for the explanation. In short:

- Program name `cakepass`, brand CakePass; vault in `~/.local/share/cakepass/vault.enc` (XDG).
- Argon2id m=64 MiB, t=3, p=4 (configurable, minimum 8 MiB), 32-byte salt;
  unlocking takes about 0.2 s with these settings.
- XChaCha20-Poly1305 with a new nonce on every save; a second layer per field.
- Auto-lock: every single command asks for the master password again (no
  background service holds the key). `cakepass shell` locks after the configured
  idle time (default 5 minutes), also in the middle of a question.
- Without a clipboard tool `get` gives an error instead of printing the
  password; showing it is only possible with `--show`.
- Master and export passwords must reach zxcvbn score ≥ 3. Item passwords may be
  chosen freely (sites have their own rules); empty = generate.
- Item names are unique (case-insensitive). On import, a clash gets a
  sequence number ("GitHub (2)"); identical items are skipped.
- Vault files that are symlinks are refused.
- `rust-version` is 1.88 because older versions of the `time` crate have a known
  vulnerability (RUSTSEC-2026-0009).
- The PKGBUILD lives in `packaging/arch/` because makepkg makes its own `src/`
  folder, which would clash with the Rust source.
- The one-line installer for a **private** repository needs a GitHub login
  (`gh api …` or `curl` with `gh auth token`); a plain raw.githubusercontent.com
  link only works if the repository or the script is public.
- Updates are never installed unattended: the daily check only notifies (see
  the README for why).
- EFF diceware word list in `assets/` (checked against two independent sources;
  sha256 `addd3553…996b903e`).
- The screen mode uses no TUI library (no ratatui/crossterm/ncurses): `libc` +
  ANSI escape codes, so there is no new dependency and every byte with a secret
  goes through our own wiped buffers. The line mode stays as `cakepass shell`.
- Lock in the screen mode = wipe the key and close (like `exit` in the line
  mode), not "back to the login screen".
- Tests shorten the idle lock with `CAKEPASS_TEST_LOCK_SECS`; only debug builds
  read it (the release build ignores it), and it can only make the time shorter.
- Security levels instead of numbers: Standard 64 MiB, High 256 MiB (default),
  Maximum 1 GiB; t=3, p=4. Argon2 may use at most 75 % of the free memory.
  Tests pretend to have little memory with `CAKEPASS_TEST_MEM_AVAILABLE_KIB`
  (debug builds only).
- Key file = Argon2id's secret input (pepper from BLAKE2b-256 with a label);
  format 3 records "key file required" in the authenticated header. No key-file
  fingerprint: a wrong key file and a wrong password are indistinguishable.
- `cakepass security --new-keyfile PATH` (not `--keyfile`): `--keyfile` is the
  global option for the *current* key file, and clap cannot have both.
- Only the key file's path is stored (settings); the key file and its pepper
  are read again whenever needed and wiped after each Argon2 run.
- A format 2 vault is not rewritten just because it was read; it becomes
  format 3 on its next save.
- The free memory needed is shown honestly with the 75 % rule (High needs
  ~342 MiB free, Maximum ~1.4 GB), not as the bare Argon2 size.

## Checks (latest step)

| Check | Result |
|---|---|
| `cargo test` | 256 passed (97 library, 76 CLI/screen unit, 50 CLI integration, 8 screen in a pseudo-terminal, 12 update, 13 installer) |
| Known-answer tests (step 11) | Argon2id with a secret: vectors from the reference C implementation (libargon2 via argon2-cffi; the harness reproduces RFC 9106 first); key-file pepper: vectors from Python's `hashlib.blake2b(digest_size=32)` |
| Unlock times (release, 4-core 2.1 GHz Xeon VM, step 11) | Standard ≈ 0.18–0.21 s, High ≈ 0.8–0.9 s, Maximum ≈ 3.6–3.8 s (first run once 5.9 s); wiping Argon2's freed memory is ~5–10 % of that |
| Memory scan with a key-file vault (release, step 11) | idle and unlocked, line mode and screen mode, also after re-keying and measuring levels: master password (UTF-8/UTF-32), key file (64 bytes or any 16-byte window) and pepper (32 bytes or any 16-byte window) 0 times; a control (an item name) is found. Memory back to ~8.9 MB after a 256 MiB Argon2 run; no large mapping left. The same scan with the stack scrub and the `blake2` `zeroize` feature both switched off also found 0, so these two are defense in depth |
| First-run wizard in a real pseudo-terminal (step 11) | level typo corrected, passphrase retyped wrong then right, screen + scrollback cleared, key file created, screen mode opened, key file found for a re-check |
| Screen mode in a real pseudo-terminal | every screen at 80×24, 100×30, 70×30 and 60×16, in UTF-8, ASCII and `NO_COLOR`; add/edit/delete/search/paste/reveal/generator/settings, resize, too small, Ctrl+C, SIGTERM, auto-lock, `--no-tui`, `TERM=dumb` |
| Memory scan of the screen mode (release build) | after revealing, hiding, editing and leaving: username, e-mail, URL, password, API key, notes 0 times as readable text; password/key/notes also 0 times in the screen buffer; only the cells of the item on screen hold its username/e-mail/URL |
| Generator menu in a real pseudo-terminal (step 9) | regenerate, edit (own password), view, save, quit; `generate --save`, `add --generate`, `edit --generate` all driven and checked |
| `cargo clippy --all-targets -- -D warnings` | no warnings |
| `cargo audit` | no vulnerabilities |
| `cargo build --release --locked` | succeeded |
| Setup wizard in a real pseudo-terminal | answers visible, passwords hidden, settings and vault created |
| Installer | tested end to end with a fake GitHub and fake `pacman`/`sudo`/`makepkg`/`cakepass` (piped like `curl \| bash`, truncated download, re-run, local changes, failed build, uninstall) |

### Tested in a clean Arch Linux container (earlier step, as a normal user)

- [x] `makepkg --printsrcinfo` reads the PKGBUILD without errors
- [x] Default path `~/.local/share/cakepass/vault.enc`; directory 700, file 600
- [x] `XDG_DATA_HOME=/tmp/xdg` → `/tmp/xdg/cakepass/vault.enc`; relative path ignored
- [x] `ulimit -l` = 8192 KiB, `cakepass info` → "mlock works: yes"
- [x] Core dump limit 0; `/proc/<pid>/mem` unreadable for the same user

## Testing on Arch

Could NOT be tested in the cloud environment. Do this yourself and tick:

### Security levels and key files – new in step 11

- [ ] `cakepass security` on your real vault: it shows `standard` (vaults made
      before 0.4) and the unlock time measured on your laptop. Note the times of
      the three levels: `cakepass security --level high`, then `cakepass security`
      again; the same for `maximum`, then go back to the level you want
- [ ] Unlocking at each level feels like the measured time (`time cakepass list`)
- [ ] A big level on a busy laptop: open many browser tabs, then run
      `cakepass security --level maximum` → either it works, or a clear
      "needs about … MiB of free memory" message (never a crash or a frozen system)
- [ ] **Key file on a USB stick**: plug in a stick, `cakepass keyfile create
      /run/media/$USER/<stick>/cakepass.key`, then
      `cakepass security --new-keyfile /run/media/$USER/<stick>/cakepass.key`;
      `cakepass config` shows the path; `cakepass list` works with the stick in
- [ ] **Unplug the stick** and run `cakepass list`: a plain message that the key
      file cannot be read (with the path), asked *before* the password
- [ ] Plug it in again; on FAT/exFAT you get a warning that others can read it
      (expected; the stick itself must be kept safe)
- [ ] **Wrong key file**: `cakepass keyfile create /tmp/other.key`, then
      `CAKEPASS_KEYFILE=/tmp/other.key cakepass list` → the same message as a
      wrong password, plus which key file was used
- [ ] Copy the key file to a second stick, and open a copy of the vault with
      that copy: `cakepass --keyfile <copy> --vault <vault copy> list`
- [ ] `cakepass` (the screen): log in with the stick in; `s` → Security level
      row: ← → shows "Measuring…" then the time per level; Enter + master
      password switches; the `.bak` still opens (`cakepass --vault
      ~/.local/share/cakepass/vault.enc.bak list`)
- [ ] In the screen, change the master password with the stick in; unplug the
      stick and try again → "Key file needed" message, nothing changed
- [ ] `cakepass security --no-keyfile` → the password alone opens the vault;
      `cakepass config` no longer shows the path
- [ ] A fresh setup in a throw-away place (`CAKEPASS_VAULT=/tmp/t.enc
      XDG_CONFIG_HOME=/tmp/tcfg cakepass setup`): choose a level, accept "Make a
      strong passphrase for me?", write it down, type it back (the screen is
      cleared afterwards), create a key file on the stick; then log in with it
- [ ] `cakepass --update` with a key-file vault: the update never asks for the
      key file; afterwards `cakepass list` works as before

- [ ] **The one-line installer on a clean Arch install**, both commands from the
      README (`gh api … | bash` and the `curl … $(gh auth token)` variant).
      These were not run against the real private repository here (no GitHub
      login in the sandbox). Check: tools installed, `~/cakepass` cloned,
      `makepkg` builds and runs the tests, `cakepass --version` works, the wizard starts.
- [ ] The wizard in your own terminal: answer the animation question both ways;
      `cakepass config` shows what you chose
- [ ] `cakepass` shows the spinning 3D logo (kitty, Alacritty, Konsole, GNOME
      Terminal); with `cakepass config set animation off` you get a still logo
- [ ] After `exit` in the line mode (`cakepass shell`) the screen is empty and you cannot
      scroll back to displayed passwords
- [ ] `cd packaging/arch && makepkg -si` by hand works too
- [ ] After installing: `cakepass --version`, and tab completion in a new terminal
      (`cakepass <Tab><Tab>`) in bash, zsh or fish
- [ ] **Clipboard on Wayland** (`wl-clipboard`): `cakepass get <name>` → pasting
      works, and after 20 s `wl-paste` returns nothing
- [ ] **Clipboard on X11** (`xclip`): the same. Copy something else within 20 s;
      that must NOT be cleared
- [ ] Clipboard and closing the terminal: start `cakepass get`, close the window
      at once; after 20 s the clipboard must still be empty
- [ ] Clipboard history (Klipper/cliphist/CopyQ): check whether the password
      stays in there. If so: turn the history off or exclude cakepass
- [ ] Hidden prompt: no characters appear while typing the master password,
      and Ctrl+C restores the terminal
- [ ] Colors: green ✔ and yellow warnings; no color codes with `cakepass list | cat`
      or with `NO_COLOR=1`
- [ ] Interactive mode: after the idle time "Locked automatically" appears
- [ ] **The real update**: in `~/cakepass` make a small change (e.g. a text in
      `README.md`), commit and push it from a second copy, then type
      `cakepass --update`. Check: the message shows the change, `makepkg` builds and
      installs, `cakepass --version` shows the new commit, and `cakepass list` still
      works with your vault
- [ ] `cakepass --update --check` says "already have the newest version" when up to date
- [ ] `cakepass --update --auto on`, then `systemctl --user list-timers` shows
      `cakepass-update.timer`. Test it directly:
      `systemctl --user start cakepass-update.service` and
      `journalctl --user -u cakepass-update.service`
- [ ] Desktop notification (install `libnotify`) appears for a new version
- [ ] Does `git -C ~/cakepass fetch` work without a password prompt? If not, the
      daily check cannot run (manual updating still works)
- [ ] Core dumps: open CakePass (`cakepass`), run
      `kill -SEGV $(pgrep -x cakepass)` in a second terminal and then
      `coredumpctl list` → no dump of cakepass
- [ ] mlock limit on your real system: `ulimit -l` and `cakepass info`
- [ ] Export to a USB stick (FAT/exFAT) and import it again

### Screen mode (arrow keys) – new in step 10

- [ ] `cakepass` → log in → the screen appears; `?` shows the help; the bottom
      line shows the keys
- [ ] **Clipboard**: select an item, `c`, paste it somewhere (Ctrl+V): it is the
      password; the status line counts down; after 20 s `wl-paste` (or
      `xclip -o -selection clipboard`) is empty. Same for `u` (username) and `m` (e-mail)
- [ ] Add a login with `a`: type in every field, Ctrl+R shows the password,
      Ctrl+G opens the generator, Ctrl+S saves; `cakepass get <name> --show` in
      another terminal shows exactly what you typed
- [ ] **Paste an API key** (Ctrl+Shift+V) into the API key field: it arrives
      complete and no letter in it triggers a shortcut
- [ ] Edit (`e`): "(unchanged)" keeps the password; typing replaces it
- [ ] Delete (`d`): Enter alone does NOT delete; ← then Enter (or `y`) does
- [ ] Enter on an item shows the password; it hides after 10 s and when you
      press ↓
- [ ] **Resize** the window (drag the corner, tile it, zoom with Ctrl+=/−): the
      screen redraws cleanly; make it tiny → "Terminal too small"; bigger → back
- [ ] **Narrow** window (60–79 columns): details next to the list or below it
      (when it is tall), nothing garbled
- [ ] **Terminals**: kitty, Alacritty, GNOME Terminal/Console, Konsole: lines,
      colors, the pink selection bar, the cursor only in text fields
- [ ] **The Linux console** (Ctrl+Alt+F3, log in, run `cakepass`): readable
      lines and colors (with `LANG=C cakepass` you get `+-|` instead)
- [ ] **SSH** from another computer (`ssh laptop`, then `cakepass`)
- [ ] **tmux** (and screen): open it inside tmux; detach/attach; after quitting
      no password is in tmux's scrollback (`Ctrl+B [` and scroll up)
- [ ] **Idle lock**: set the auto-lock to 1 minute in settings (`s`), wait: it
      locks, the screen is cleared and the terminal works normally
- [ ] Close the laptop lid for longer than the lock time, open it: CakePass has
      locked itself (or locks at once)
- [ ] **Ctrl+C** in the screen, and closing the terminal window while it is open,
      and `kill <pid>` from another terminal: the terminal is normal afterwards
      (cursor visible, typing echoes; otherwise type `reset`)
- [ ] `NO_COLOR=1 cakepass` and `cakepass --no-color`: no colors, selection in
      reverse video
- [ ] `cakepass --no-tui` and `cakepass shell`: the old line mode
- [ ] Settings (`s`): animation off → next start shows a still logo; change the
      master password there (asks the current one first) and log in with the new one
