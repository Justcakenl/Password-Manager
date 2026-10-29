# Progress: `kluis` (CakePass)

Last updated: step 8 (one-line installer, setup wizard, everything in English).
Repository: private, `Justcakenl/passcode-manager-cli-`, branch `main`.

## What I need to do tonight on my computer

1. **Log in to GitHub** (the repository is private):
   ```bash
   sudo pacman -S --needed github-cli
   gh auth login
   ```
2. **Run the one-line installer**:
   ```bash
   gh api repos/Justcakenl/passcode-manager-cli-/contents/install.sh \
     -H "Accept: application/vnd.github.raw" | bash
   ```
   It installs the build tools, downloads the code into `~/cakepass`, builds,
   tests and installs CakePass, and then starts the setup wizard. If something
   fails, copy the error message and ask Claude. **Keep `~/cakepass`**:
   `kluis --update` uses it.
3. **In the wizard** choose: animation on or off, the auto-lock minutes, and a
   strong master password (write it on paper too).
4. **Try it** with a throw-away vault first, so the real one stays clean:
   ```bash
   export KLUIS_VAULT=/tmp/testvault.enc
   kluis setup
   kluis add Test --generate
   kluis get Test           # paste (Ctrl+V) somewhere and wait 20 s → empty
   kluis info
   unset KLUIS_VAULT
   ```
5. **Go through the "Testing on Arch" list below** and tick what works.
6. Make a first backup of the real vault (README, "Backups").
7. When happy there is nothing left to do: `kluis --update` keeps the
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
- [x] **Step 7 – Update system**: `kluis --update` (git + makepkg, extra
  backup, restore on failure, never opens the vault), daily check with a
  systemd timer, `kluis --version` shows the commit. Repository is private
  (checked).
- [x] **Step 8 – Installer, setup wizard, English**:
  - `install.sh`: the one-line installer (works with the script on stdin, as
    `curl | bash` does). It checks the system, installs tools with pacman,
    clones the private repository with *your* GitHub access (gh, SSH or login
    prompt), runs `makepkg -si`, and starts `kluis setup`. Options `--yes`,
    `--no-setup`, `--dir`, `--branch`, `--uninstall`. Wrapped in `main()` so a
    truncated download never runs half a script.
  - `kluis setup`: first-time wizard – animation on/off, auto-lock minutes,
    master password (with strength check). Works from stdin too. If a vault
    exists it only asks the first two questions.
  - `kluis config` / `kluis config set animation on|off` /
    `kluis config set lock-timeout <minutes>`; settings in
    `~/.config/kluis/config`. Animation off = a still logo. `kluis` with no
    vault starts the wizard in a terminal.
  - **Everything is in English now**: all code, comments, messages, tests,
    README, design doc and packaging files. Fixed cryptographic labels
    (HKDF info strings, file magic `KLUISVLT`) are deliberately unchanged so
    existing vaults keep opening. The backup copies made by `--update` are now
    called `vault.enc.pre-update-<time>`.

## Still to do

- [ ] Check the "Testing on Arch" list below on your own computer.
- [ ] Decide whether the command should be renamed from `kluis` to `cakepass`
  (easiest now, before a real vault exists; the vault file magic would stay).
- [ ] GitHub repository description still says "Beta-test"; change it in the
  repository settings.
- [ ] Ideas for later: see the README, "For later".

## Decisions made

See `docs/DESIGN.md` for the explanation. In short:

- Program name `kluis`, brand CakePass; vault in `~/.local/share/kluis/vault.enc` (XDG).
- Argon2id m=64 MiB, t=3, p=4 (configurable, minimum 8 MiB), 32-byte salt;
  unlocking takes about 0.2 s with these settings.
- XChaCha20-Poly1305 with a new nonce on every save; a second layer per field.
- Auto-lock: every single command asks for the master password again (no
  background service holds the key). `kluis shell` locks after the configured
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

## Checks (latest step)

| Check | Result |
|---|---|
| `cargo test` | 150 passed (72 library, 21 CLI unit, 33 integration, 12 update, 12 installer) |
| `cargo clippy --all-targets -- -D warnings` | no warnings |
| `cargo audit` | no vulnerabilities |
| `cargo build --release --locked` | succeeded |
| Setup wizard in a real pseudo-terminal | answers visible, passwords hidden, settings and vault created |
| Installer | tested end to end with a fake GitHub and fake `pacman`/`sudo`/`makepkg`/`kluis` (piped like `curl \| bash`, truncated download, re-run, local changes, failed build, uninstall) |

### Tested in a clean Arch Linux container (earlier step, as a normal user)

- [x] `makepkg --printsrcinfo` reads the PKGBUILD without errors
- [x] Default path `~/.local/share/kluis/vault.enc`; directory 700, file 600
- [x] `XDG_DATA_HOME=/tmp/xdg` → `/tmp/xdg/kluis/vault.enc`; relative path ignored
- [x] `ulimit -l` = 8192 KiB, `kluis info` → "mlock works: yes"
- [x] Core dump limit 0; `/proc/<pid>/mem` unreadable for the same user

## Testing on Arch

Could NOT be tested in the cloud environment. Do this yourself and tick:

- [ ] **The one-line installer on a clean Arch install**, both commands from the
      README (`gh api … | bash` and the `curl … $(gh auth token)` variant).
      These were not run against the real private repository here (no GitHub
      login in the sandbox). Check: tools installed, `~/cakepass` cloned,
      `makepkg` builds and runs the tests, `kluis --version` works, the wizard starts.
- [ ] The wizard in your own terminal: answer the animation question both ways;
      `kluis config` shows what you chose
- [ ] `kluis` shows the spinning 3D logo (kitty, Alacritty, Konsole, GNOME
      Terminal); with `kluis config set animation off` you get a still logo
- [ ] After `exit` in the interactive mode the screen is empty and you cannot
      scroll back to displayed passwords
- [ ] `cd packaging/arch && makepkg -si` by hand works too
- [ ] After installing: `kluis --version`, and tab completion in a new terminal
      (`kluis <Tab><Tab>`) in bash, zsh or fish
- [ ] **Clipboard on Wayland** (`wl-clipboard`): `kluis get <name>` → pasting
      works, and after 20 s `wl-paste` returns nothing
- [ ] **Clipboard on X11** (`xclip`): the same. Copy something else within 20 s;
      that must NOT be cleared
- [ ] Clipboard and closing the terminal: start `kluis get`, close the window
      at once; after 20 s the clipboard must still be empty
- [ ] Clipboard history (Klipper/cliphist/CopyQ): check whether the password
      stays in there. If so: turn the history off or exclude kluis
- [ ] Hidden prompt: no characters appear while typing the master password,
      and Ctrl+C restores the terminal
- [ ] Colors: green ✔ and yellow warnings; no color codes with `kluis list | cat`
      or with `NO_COLOR=1`
- [ ] Interactive mode: after the idle time "Locked automatically" appears
- [ ] **The real update**: in `~/cakepass` make a small change (e.g. a text in
      `README.md`), commit and push it from a second copy, then type
      `kluis --update`. Check: the message shows the change, `makepkg` builds and
      installs, `kluis --version` shows the new commit, and `kluis list` still
      works with your vault
- [ ] `kluis --update --check` says "already have the newest version" when up to date
- [ ] `kluis --update --auto on`, then `systemctl --user list-timers` shows
      `kluis-update.timer`. Test it directly:
      `systemctl --user start kluis-update.service` and
      `journalctl --user -u kluis-update.service`
- [ ] Desktop notification (install `libnotify`) appears for a new version
- [ ] Does `git -C ~/cakepass fetch` work without a password prompt? If not, the
      daily check cannot run (manual updating still works)
- [ ] Core dumps: open the interactive mode, run
      `kill -SEGV $(pgrep -x kluis)` in a second terminal and then
      `coredumpctl list` → no dump of kluis
- [ ] mlock limit on your real system: `ulimit -l` and `kluis info`
- [ ] Export to a USB stick (FAT/exFAT) and import it again
