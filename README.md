# CakePass 🍰

**CakePass is a small, offline password manager for the Linux terminal. It keeps your passwords, API keys and secure notes in one strongly encrypted file on your own computer, and you use it with the arrow keys.**

![License: MIT](https://img.shields.io/badge/license-MIT-pink)
![Platform: Linux](https://img.shields.io/badge/platform-Linux-informational)
![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-orange)
![Status: beta](https://img.shields.io/badge/status-beta-yellow)

![CakePass login screen](docs/cakepass-login.gif)

CakePass keeps everything in **one encrypted file** on your own machine. No
cloud, no account, no telemetry: the program itself never makes a network
connection. You use it with the **arrow keys** (no commands to remember), or with
single commands in scripts.

Free and open source under the [MIT license](LICENSE).

## What you get

- 🔐 **Strong encryption.** Argon2id + XChaCha20-Poly1305, plus a second layer
  that encrypts every field (username, e-mail, URL, password, notes) on its own.
  An optional **key file** (for example on a USB stick) makes a stolen vault
  useless on its own. [How strong is this, really?](#how-strong-is-this-really)
- ⌨️ **Arrow-key screen.** Tabs, live search, add/edit forms, a password
  generator and settings: no typing of commands. [See it](#using-the-screen-arrow-keys).
- 🗝️ **Logins, API keys and notes** in one place, with e-mail addresses and tags.
- 📋 **Clipboard that cleans up.** Copied secrets are wiped after 20 seconds.
- 🧹 **Careful with memory.** Secrets are wiped after use; core dumps are off;
  the screen and scrollback are cleared when you lock.
- ⏲️ **Auto-lock** after the idle time you choose.
- 🪶 **Small and light.** One static-ish binary (about 5 MB), no runtime, no
  background service.

> ⚠️ **Status: beta.** The cryptography comes from well-known, audited
> RustCrypto crates, but CakePass itself has **not been audited by an outside
> expert**. Keep a [backup](#backups) of your vault, and read
> [Security review and remaining risks](#security-review-and-remaining-risks)
> before you trust it with everything. Found a security problem? See
> [SECURITY.md](SECURITY.md).

## Install

CakePass runs on **Linux** (tested on Arch Linux and Ubuntu 24.04, x86_64).
Pick the line that fits you:

| You use… | Go to |
|---|---|
| Arch Linux, Manjaro, EndeavourOS, CachyOS | [**Arch family: one line**](#arch-family-one-line) |
| Ubuntu, Debian, Linux Mint, Pop!_OS, Zorin, Raspberry Pi OS | [**Any other Linux, step by step**](#any-other-linux-step-by-step) → Debian family |
| Fedora, RHEL, AlmaLinux, Rocky Linux | [step by step](#any-other-linux-step-by-step) → Fedora family |
| openSUSE | [step by step](#any-other-linux-step-by-step) → openSUSE |
| Alpine, Void, Gentoo, NixOS, anything else | [step by step](#any-other-linux-step-by-step) → Other |
| Windows (WSL), ChromeOS (Linux), Android (Termux), macOS | see [Other devices](#other-devices-wsl-chromebook-raspberry-pi-mac) |

### Arch family: one line

You need a user that may use `sudo`. Open a terminal and run:

```bash
curl -fsSL https://raw.githubusercontent.com/Justcakenl/Passcode-Manager/main/install.sh | bash
```

The installer is a short, readable script ([`install.sh`](install.sh)); read it
first, as you should with any script you pipe into `bash`. It:

1. Checks that you are on Arch Linux and not root.
2. Installs what it needs with `pacman` (`base-devel`, `git`, `rust`, and a
   clipboard tool for your session). Asks for your sudo password.
3. Downloads the source code with `git` into `~/cakepass`.
4. Builds, **tests** and installs the package with `makepkg`.
5. Starts the **first-time setup**: intro animation yes/no, auto-lock minutes,
   **security level**, your **master password** (it offers to make a strong
   passphrase for you) and optionally a **key file**.

Your vault is never touched by the installer. Run it again any time to update.
Options go after `bash -s --`, e.g. `... | bash -s -- --yes --no-setup`:
`--yes` (no confirmations), `--no-setup`, `--dir DIR`, `--branch B`,
`--uninstall` (removes the program, keeps your vault), `--help`.

<details>
<summary>The repository (or your fork) is private? Use your GitHub login</summary>

A plain `curl` link gives "404 Not Found" for a private repository, because the
download has no login. Log in once with the GitHub CLI
(`sudo pacman -S github-cli && gh auth login`), then run:

```bash
gh api repos/Justcakenl/Passcode-Manager/contents/install.sh \
  -H "Accept: application/vnd.github.raw" | bash
```

</details>

When it is done, type `cakepass`. That is all. Skip to
[Check that it works](#check-that-it-works).

> **Used an early version?** The command used to be called `kluis`. Run the
> installer again: the old package is replaced and your old `kluis` folders are
> moved to `cakepass` automatically, so your vault is kept.

### Any other Linux, step by step

Seven small steps. You need about **1 GB of free RAM** and a few minutes for the
first build. Everything is installed in your own home folder, so only step 1
needs `sudo`.

#### Step 1: install a compiler, git and curl

Choose your family and paste the line:

<details open>
<summary><b>Debian family</b>: Ubuntu, Debian, Linux Mint, Pop!_OS, Zorin, Raspberry Pi OS</summary>

```bash
sudo apt update
sudo apt install -y build-essential git curl
```

</details>

<details>
<summary><b>Fedora family</b>: Fedora, RHEL, AlmaLinux, Rocky Linux</summary>

```bash
sudo dnf install -y gcc git curl
```

</details>

<details>
<summary><b>openSUSE</b></summary>

```bash
sudo zypper install -y gcc git curl
```

</details>

<details>
<summary><b>Other</b>: Alpine, Void, Gentoo, NixOS, …</summary>

Install a C compiler (`gcc` or `clang`), `git` and `curl` with your package
manager. For example, Alpine: `sudo apk add build-base git curl`; Void:
`sudo xbps-install -S base-devel git curl`. (Alpine and the others are not
tested; see [Other devices](#other-devices-wsl-chromebook-raspberry-pi-mac).)

</details>

Want to copy passwords to the clipboard? Add **one** clipboard tool, depending
on your desktop (not sure? type `echo $XDG_SESSION_TYPE`):

| Session | Package | Debian family | Fedora family | openSUSE |
|---|---|---|---|---|
| Wayland (GNOME, KDE Plasma 6, Sway, Hyprland) | `wl-clipboard` | `sudo apt install -y wl-clipboard` | `sudo dnf install -y wl-clipboard` | `sudo zypper install -y wl-clipboard` |
| X11 (i3, Xfce, older sessions) | `xclip` | `sudo apt install -y xclip` | `sudo dnf install -y xclip` | `sudo zypper install -y xclip` |

No clipboard tool (a server, SSH)? CakePass still works: `--show` prints a
password on screen instead of copying it.

#### Step 2: install Rust (version 1.88 or newer)

First look whether you already have a new enough Rust:

```bash
rustc --version
```

If it prints **1.88 or higher**, skip to step 3. If the command is not found, or
the version is lower (Ubuntu and Debian ship old versions), install the official
toolchain with `rustup`. Press Enter to accept the default choice:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Then make it available in this terminal and check:

```bash
. "$HOME/.cargo/env"
rustc --version
```

#### Step 3: download CakePass

```bash
git clone https://github.com/Justcakenl/Passcode-Manager.git ~/Passcode-Manager
cd ~/Passcode-Manager
```

(Behind a private repository or fork? Log in first with `gh auth login` and use
`gh repo clone Justcakenl/Passcode-Manager ~/Passcode-Manager`.)

> **Keep this folder.** You will use it to update later.

#### Step 4: build it

```bash
cargo build --release --locked
```

The first build takes **1 to 5 minutes** (about 80 seconds on a normal laptop).
On a small board such as a Raspberry Pi, limit the parallel jobs so it does not
run out of memory: `cargo build --release --locked -j 2`.

Want to run the tests too? `cargo test --locked` (a couple of minutes more).

#### Step 5: install the program

For just you (no `sudo`):

```bash
install -Dm755 target/release/cakepass ~/.local/bin/cakepass
```

Check that `~/.local/bin` is in your `PATH`:

```bash
echo "$PATH" | tr ':' '\n' | grep -x "$HOME/.local/bin" || echo "NOT in PATH"
```

If it says `NOT in PATH`, add it and open a new terminal:

```bash
# bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
# zsh
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
# fish
fish_add_path ~/.local/bin
```

Prefer a system-wide install for all users? Use
`sudo install -Dm755 target/release/cakepass /usr/local/bin/cakepass` instead.

#### Step 6 (optional): tab completion

Press Tab to complete commands. Run the line for your shell:

```bash
# bash
mkdir -p ~/.local/share/bash-completion/completions
cakepass completions bash > ~/.local/share/bash-completion/completions/cakepass

# zsh (and add  fpath=(~/.zfunc $fpath)  before "compinit" in ~/.zshrc)
mkdir -p ~/.zfunc && cakepass completions zsh > ~/.zfunc/_cakepass

# fish
mkdir -p ~/.config/fish/completions
cakepass completions fish > ~/.config/fish/completions/cakepass.fish
```

#### Step 7: first run

```bash
cakepass
```

With no vault yet, the [first-time setup](#first-time-setup) starts by itself.

### Check that it works

```bash
cakepass --version     # prints a version, e.g. "cakepass 0.4.0 (commit …)"
cakepass info          # shows your vault and system checks; needs no password
```

If `cakepass` is "command not found", your `PATH` is missing the folder you
installed to (step 5). More help: [Troubleshooting](#troubleshooting).

### Update to a newer version

- **Arch family** (installed with the one-liner): `cakepass --update`, or run
  the installer again. See [Updating](#updating).
- **Everyone else** (installed step by step), from your `~/Passcode-Manager` folder:

  ```bash
  cd ~/Passcode-Manager
  git pull --ff-only
  cargo build --release --locked
  install -Dm755 target/release/cakepass ~/.local/bin/cakepass
  cakepass --version
  ```

  Your vault is never touched by an update, but a new version may upgrade the
  vault format the next time it **saves**. Make a [backup](#backups) first.
  (`cakepass --update` and the daily update check need Arch's `makepkg`, so on
  other systems they say they cannot run. The four lines above are the update.)

### Uninstall

```bash
rm -f ~/.local/bin/cakepass                          # the program
rm -f ~/.local/share/bash-completion/completions/cakepass ~/.zfunc/_cakepass \
      ~/.config/fish/completions/cakepass.fish       # completions, if you added them
rm -rf ~/Passcode-Manager                            # the source folder
```

On Arch family: `sudo pacman -R cakepass` (or the installer with `--uninstall`).
**Your vault is not removed**: it stays in `~/.local/share/cakepass/` and your
settings in `~/.config/cakepass/`. Delete those yourself only if you are sure you
no longer need your passwords (see [Backups](#backups)).

### Other devices (WSL, Chromebook, Raspberry Pi, Mac)

| Device | Works? | Notes |
|---|---|---|
| Normal Linux PC or laptop (x86_64) | ✅ tested | Arch and Ubuntu 24.04 |
| Raspberry Pi, other ARM64 (aarch64) boards | 🟡 should work, not tested | Use a 64-bit OS. Build with `-j 2`. On boards with 1 GB of RAM choose the *Standard* [security level](#security-levels-and-key-files); CakePass refuses a level that does not fit in free memory |
| 32-bit systems (i686, armv7) | ❔ not tested | Argon2 needs a lot of memory; use the Standard level |
| Windows with WSL 2 (Ubuntu) | 🟡 should work | Install it in the Linux side with the Debian steps. There is no Linux clipboard tool by default, so use `--show` |
| ChromeOS "Linux development environment" | 🟡 should work | It is Debian: use the Debian steps. Clipboard: `--show` |
| Android (Termux) | ❔ not tested | |
| macOS, BSD, native Windows | ❌ not supported | CakePass uses Linux features (`/proc`, `prctl`, `mlock` rules) |
| Alpine (musl), Void, Gentoo, NixOS | 🟡 should work, not tested | Follow the steps with your package manager |

Got it running somewhere that is not marked ✅? Please tell us in an issue.

## Contents

0. [Install](#install)
1. [First-time setup](#first-time-setup)
2. [Using the screen (arrow keys)](#using-the-screen-arrow-keys)
3. [Daily use (commands)](#daily-use-commands)
4. [Item types: logins, API keys and notes](#item-types-logins-api-keys-and-notes)
5. [Generating passwords](#generating-passwords)
6. [Login screen, settings and auto-lock](#login-screen-settings-and-auto-lock)
7. [Security levels and key files](#security-levels-and-key-files)
8. [Switching from another password manager (CSV)](#switching-from-another-password-manager-csv)
9. [Backups](#backups)
10. [Updating](#updating)
11. [Forgot your master password?](#forgot-your-master-password)
12. [How the security works](#how-the-security-works)
13. [How strong is this, really?](#how-strong-is-this-really)
14. [Security review and remaining risks](#security-review-and-remaining-risks)
15. [Troubleshooting](#troubleshooting)
16. [For later](#for-later)

---

## First-time setup

The installer starts it for you. You can also run it yourself at any time:

```bash
cakepass setup
```

```text
Step 1 of 5 — Startup animation
  Play the animation at startup? [Y/n]
Step 2 of 5 — Auto-lock
  Lock after how many minutes of inactivity? [5]
Step 3 of 5 — Security level
    1  Standard            works on any computer; unlocks fastest (64 MiB; needs ~86 MiB free)
    2  High (recommended)  about 1 s to unlock; needs ~342 MiB free memory (256 MiB)
    3  Maximum             about 3-5 s to unlock; needs ~1366 MiB free memory (1 GiB)
  Choose 1, 2 or 3 [2]:
✔ High (recommended): unlocking takes about 0.81 s on this computer.
Step 4 of 5 — Master password
  Make a strong passphrase for me? [Y/n]
  Your master password (7 random words, about 90 bits):
      lantern-oyster-bulky-scenic-dwarf-grape-mosaic     ← an example; yours is random
warning: Write it down on paper NOW …
  Type it again to confirm:
Step 5 of 5 — Extra protection: a key file (optional)
  Create a key file? [y/N]
✔ Vault created: ~/.local/share/cakepass/vault.enc (security level: high)
```

- **Animation**: the 3D CakePass logo that spins in when you start the program.
  Turn it off if you prefer a still logo; change it later with
  `cakepass config set animation off`.
- **Auto-lock**: after this many idle minutes CakePass (the screen and the line
  mode) locks itself and wipes your secrets from memory.
- **Security level**: how much memory Argon2id uses for every unlock (and so
  for every guess of someone who stole the file). **High** is the default;
  **Standard** suits small or old computers; **Maximum** makes guessing four
  times as expensive again and takes a few seconds to unlock. Once you choose,
  CakePass measures the unlock time on your computer. Change it any time with
  `cakepass security --level …` ([details](#security-levels-and-key-files)).
- **Master password**: the key to your vault. Press Enter at "Make a strong
  passphrase for me?" and CakePass makes **7 random words** (about 90 bits),
  shows them **once** and asks you to type them back: **write them on paper
  first**. Or answer `n` and type your own; it must reach zxcvbn score 3 of 4.
  If you forget it, your data is gone ([details](#forgot-your-master-password)).
- **Key file (optional)**: a small random file, for example on a USB stick,
  that is needed *as well as* the master password. A stolen vault file is
  useless without it. **Lose it and the vault is lost**, so keep a copy
  ([details](#key-files)).

If a vault already exists, `cakepass setup` only asks the first two questions and
leaves your vault exactly as it is. Scripts can skip the level question with
`cakepass setup --level standard|high|maximum` (or the `--kdf-*` options).

The vault goes to `~/.local/share/cakepass/vault.enc` (or
`$XDG_DATA_HOME/cakepass/vault.enc`). Use `--vault <path>` or the environment
variable `CAKEPASS_VAULT` to choose another place.

When the wizard has created your vault it asks **"Open CakePass now?"**; press
Enter and you are in the screen described below.

---

## Using the screen (arrow keys)

Type `cakepass`, enter your master password, and you get a screen that you use
with the **arrow keys, Enter, Esc and a few letters**. You never have to
remember a command: the bottom line always shows the keys that work right now,
and **`?`** shows them all.

```text
 CakePass  vault.enc                                              locks in 4:59
 All 3   Logins 1   API keys 1   Notes 1                               / search
┌─ Items ───────────────────────────────────┬─ Details ────────────────────────┐
│▌ login  GitHub               john         │ Name        GitHub               │
│  api    OpenAI               proj-1       │ Type        login                │
│  note   Recovery codes                    │ Username    john                 │
│                                           │ E-mail      john@example.org     │
│                                           │ URL         https://github.com   │
│                                           │ Tags        work, code           │
│                                           │ Modified    2026-10-29 18:10 UTC │
│                                           │ Password    ••••••••             │
│                                           │ Notes       ••••••••             │
│                                           │ Enter shows · c copies · e edits │
└───────────────────────────────────────────┴──────────────────────────────────┘
 3 items: 1 login · 1 API key · 1 note
 ↑↓ move  Enter show  c copy  a add  q quit  e edit  d delete  / search  ? help
```

**The list**

| Key | What it does |
|---|---|
| ↑ ↓, PgUp PgDn, Home End | choose an item |
| ← → (or Tab) | switch between All · Logins · API keys · Notes |
| `/` | search in name, type, tags, username, e-mail and URL (never in passwords or notes). Any key that is not a shortcut (a capital letter, a digit) starts the search too. Esc clears it |
| Enter or `v` | show / hide the password, API key and notes. They hide themselves after **10 seconds**, and when you choose another item or open another screen |
| `c` | copy the password, API key or note to the clipboard; it is **cleared after 20 seconds** |
| `u` / `m` | copy the username / the e-mail address |
| `a` or `n` | add an item |
| `e` | edit the selected item |
| `d` or Delete | delete it (asks first; the answer is "no" unless you choose "Delete") |
| `g` | password generator |
| `s` | settings |
| `l` | lock: wipe the key from memory and close |
| `q` or Ctrl+C | quit (that locks too) |
| `?` | help |

**Adding and editing** (`a`, `e`): a form with the fields Name, Type, Username
(for an API key: Account/ID), E-mail, URL, Tags, Password (or API key) and Notes.

| Key | What it does |
|---|---|
| ↑ ↓, Tab, Shift+Tab | move between the fields (Enter goes to the next field) |
| ← → Home End, Backspace Delete | edit the text; Ctrl+U clears the field |
| ← → on *Type* | login, API key or note (a note has only a name, tags and its text) |
| Ctrl+R | show / hide the password while you type |
| Ctrl+G | open the generator; Enter puts the password in the field |
| Enter in *Notes* | a new line |
| Ctrl+S (or the Save button) | save |
| Esc | cancel (asks first when you changed something) |

When you edit an item, the password field shows `•••••••• (unchanged)`. Leave it
and the password stays as it is; type and you replace it; Ctrl+R shows it.
Pasting (Ctrl+Shift+V) works in every field, also for long API keys: pasted text
is always just text, it never triggers a shortcut.

**The generator** (`g`, or Ctrl+G in the form) shows a new password as dots, its
strength in bits, and the options: ↑ ↓ choose an option, ← → change it (length,
upper/lowercase, digits, symbols, no look-alikes, or a passphrase with the number
of words and the separator). `r` makes a new one, `v` shows it, `e` lets you type
your own (twice), `c` copies it, Enter uses it, Esc cancels. Opened from the list,
Enter asks for a name and saves it as a new login (like `cakepass generate --save`).

**Settings** (`s`): the startup animation (on/off), the auto-lock time (← → one
minute, PgUp/PgDn ten), **Change master password** (asks for the current one
first, then a new strong one twice), the **Security level** (← → choose a
level; the first time a level is shown CakePass measures how long unlocking
takes on this computer; Enter switches after you type your master password),
and information about your vault (level, key file), the version and the
clipboard tool. Changes are saved at once.

Good to know:

- Passwords, API keys and notes are shown as dots until you reveal them.
- After the idle time (default 5 minutes; the countdown is in the top right
  corner) CakePass locks itself: the key is wiped and the program closes. Leaving
  (`q`, `l`, Ctrl+C or the auto-lock) also clears the screen and the scrollback.
- The screen needs a window of at least 60×16 characters; a smaller window shows
  a notice until you make it bigger. Without UTF-8 it draws with plain `+-|`;
  with `--no-color` or `NO_COLOR` it uses bold and reverse video only.
- Prefer typing commands? `cakepass shell` (or `cakepass --no-tui`) is the line
  mode. In scripts and pipes `cakepass` uses the line mode automatically.

---

## Daily use (commands)

Everything in the screen above also works as single commands, handy in scripts
or when you know exactly what you want. Each command asks for your master
password in a hidden prompt (you see nothing while typing, that is on purpose).

| What | Command |
|---|---|
| Add an item (cakepass asks for each field) | `cakepass add GitHub` |
| Add with options and a generated password | `cakepass add GitHub -u john -e john@example.org --url https://github.com -t work,code --generate` |
| Copy the password to the clipboard (20 s) | `cakepass get GitHub` |
| Copy the username / the e-mail address instead | `cakepass get GitHub --copy-username` / `--copy-email` |
| Show password and notes on screen | `cakepass get GitHub --show` |
| List all items (no secrets) | `cakepass list` |
| Only items with a tag / of a type | `cakepass list --tag work` / `cakepass list --type api` |
| Search name, type, tags, username, e-mail, URL | `cakepass search git` |
| Change an item (asks per field) | `cakepass edit GitHub` |
| Only generate a new password | `cakepass edit GitHub --generate` |
| Change only the e-mail address | `cakepass edit GitHub --email john@work.example` (`-e ""` clears it) |
| Generate a password, tweak it and save it | `cakepass generate --save GitHub` |
| Rename | `cakepass edit GitHub --rename "GitHub work"` |
| Remove | `cakepass rm GitHub` |
| Change the master password | `cakepass passwd` |
| Security level, key file and unlock time (no password needed) | `cakepass security` |
| Another security level | `cakepass security --level standard`, `high` or `maximum` |
| Make a key file / start using it / stop using it | `cakepass keyfile create PATH` / `cakepass security --new-keyfile PATH` / `cakepass security --no-keyfile` |
| Open a vault with its key file | `cakepass --keyfile PATH list` (or `CAKEPASS_KEYFILE`, or `cakepass config set keyfile PATH`) |
| Information about the vault and security (no password needed) | `cakepass info` |
| Help | `cakepass --help` or `cakepass add --help` |

Tips:

- Names are case-insensitive: `cakepass get github` works too.
- Put names with spaces in quotes: `cakepass get "My Bank"`.
- If you leave the password empty in `add`, cakepass generates a strong 24-character
  password. In a terminal you can then **view, edit, regenerate or accept** it
  before it is saved (see [Generating passwords](#generating-passwords)).
- **You never pass passwords as arguments.** That is deliberate: arguments are
  visible to other programs (`ps`) and end up in your shell history.
- To feed a password from another program, use a pipe, for example
  `my-generator | cakepass add Site -u john --url x -t y`. Do **not** use
  `echo secret | ...`, because then the secret is in your shell history.

---

## Item types: logins, API keys and notes

You can store three kinds of things. All of them are encrypted equally strongly
(see [How the security works](#how-the-security-works)).

| Type | What | Add it with |
|---|---|---|
| **login** | username, e-mail address, URL, password, notes | `cakepass add GitHub` |
| **api** | account/key ID, e-mail address, service, the API key or token, notes | `cakepass add OpenAI --type api` |
| **note** | multi-line text, e.g. recovery codes, PINs, Wi-Fi | `cakepass add "Recovery codes" --type note` |

```text
$ cakepass add OpenAI --type api
Master password:
Account or key ID (optional): project-1
E-mail address (optional): me@work.example
Service URL (optional): https://api.openai.com
Tags, separated by commas (optional): ai, work
Notes (optional, one line):
API key (hidden input; pasting is fine):
✔ API key 'OpenAI' saved (encrypted).

$ cakepass add "Recovery codes" --type note
Master password:
Tags, separated by commas (optional): google
Type or paste the text of your note (it is stored encrypted):
  Finish with a line containing only a dot (.) or press Ctrl+D.
│ Code 1: 7731-0012
│ Code 2: 9921-4410
│ .
✔ Note 'Recovery codes' saved (encrypted).
```

- `cakepass get OpenAI` copies the API key to the clipboard (20 s); `cakepass get "Recovery codes"` copies the note text. With `--show` you see it on screen.
- `cakepass list --type api` or `--type note` shows only that type.
- Replace a key: `cakepass edit OpenAI --password`. Change a note: `cakepass edit "Recovery codes" --notes`.
- An API key is typed in a hidden prompt (pasting with Ctrl+Shift+V works); it
  never ends up in your shell history.

---

## Generating passwords

```bash
cakepass generate                         # 24 characters → clipboard
cakepass generate --show -l 32            # 32 characters, on screen
cakepass generate --no-symbols            # without symbols
cakepass generate --no-lookalikes         # without 0 O 1 l I |
cakepass generate --passphrase            # 6 words, e.g. grape-lantern-oyster-…
cakepass generate -p -w 8 --separator .   # 8 words with dots
```

Passphrases come from the EFF diceware word list (7776 words, 12.9 bits per
word). Six words give about 77 bits; the setup wizard makes seven (about 90
bits) for your master password. See [How strong is this, really?](#how-strong-is-this-really).

### View, edit and save in one go

In a terminal, a generated password is not final until you say so. You get a
small menu:

```text
$ cakepass generate --save GitHub
Master password:
🔑 Password: 24 characters, about 156 bits
   [Enter] save  [v]iew  [e]dit  [r]egenerate  [c]opy  [q]uit without saving
   ❯ r                      ← not happy? make another one
   ❯ e                      ← or type your own (hidden, asked twice)
   ❯                        ← Enter: save it
Username (optional): john
E-mail address (optional): john@example.org
…
✔ Login 'GitHub' saved (encrypted).
```

- `generate` without `--save` shows the same menu with `[s]ave to vault`; Enter
  copies it to the clipboard like before.
- The same menu appears when `add` or `edit` generate a password for you
  (`--generate`, an empty password, or choosing `g` in `edit`).
- `v` prints the password on screen, `e` lets you type a password of your own
  (cakepass tells you if it is weak), `q` throws it away.
- In scripts (no terminal) there is no menu: `generate` behaves exactly as before.

---

## Login screen, settings and auto-lock

Type `cakepass` (or `cakepass shell`) and you get the **CakePass login screen**: a 3D
logo that spins into view (pink frosting, cake layers, sprinkles and a shine),
then the question for your master password. You get three attempts. Then
`cakepass` opens [the screen](#using-the-screen-arrow-keys) and `cakepass shell`
the line mode. If there is no vault yet, `cakepass` starts the
[first-time setup](#first-time-setup) instead.

- The logo is truly 3D: every letter is a block with depth, with light, shadow
  and perspective, drawn with half blocks (▀) in truecolor.
- It only shows in a color terminal. In scripts and pipes it never appears.
- **Animation on/off**: `cakepass config set animation off` shows a still logo
  instead. For a single run: `--no-animation` or `CAKEPASS_NO_ANIMATION=1`.
  Just look at it: `cakepass logo`.

**Settings** are kept in `~/.config/cakepass/config` (plain text, no secrets).
Change them on the settings screen (`s`) or with:

```bash
cakepass config                           # show the settings
cakepass config set animation off         # on / off
cakepass config set lock-timeout 10       # minutes of inactivity before auto-lock
cakepass config set keyfile /run/media/$USER/USB/cakepass.key   # where your key file is (or: none)
```

**Auto-lock.** A single command asks for your master password every time; when
it ends, no key is left in memory. That is the safest kind of "auto-lock". The
screen (`cakepass`) locks itself after the configured idle time, also when a
laptop was asleep in the meantime. For many typed commands in a row there is the
line mode, `cakepass shell` (or `cakepass --no-tui`):

```text
cakepass ❯ list
cakepass ❯ get my bank
cakepass ❯ add Netflix --generate
cakepass ❯ exit
```

- After the configured idle time (default 5 minutes) the key is wiped and the
  mode ends. That also happens if you walk away in the middle of a question.
  One-off override: `cakepass shell --timeout 120` (seconds).
- On the screen (`cakepass`) changing the master password asks for the current
  one first as well.
- `passwd` and `export` ask for the master password again.
- `exit`, `quit`, `lock` or Ctrl+D locks at once.
- On locking, the screen **and the scrollback** of your terminal are cleared, so
  passwords you displayed cannot be scrolled back to.
- In this mode, names with spaces need no quotes for `get`, `rm` and `search`.

---

## Security levels and key files

### Security levels

Your master password is turned into the key with **Argon2id**, a function
that is slow and needs a lot of memory *on purpose*: whoever steals your vault
file must pay that price for **every single password they try**. The level
sets the price:

| Level | Argon2id | Unlocks in (measured here¹) | Needs free memory² | For |
|---|---|---|---|---|
| `standard` | 64 MiB, 3 passes, 4 lanes | ~0.2 s | ~86 MiB | any computer, also small or old ones |
| `high` (default) | 256 MiB, 3 passes, 4 lanes | ~0.8 s | ~342 MiB | normal laptops and desktops |
| `maximum` | 1 GiB, 3 passes, 4 lanes | ~3.7 s | ~1.4 GB | computers with plenty of memory |

¹ On a 4-core 2.1 GHz cloud machine; `cakepass security` measures it on yours.
² CakePass never lets Argon2 take more than 75 % of the memory that is free at
that moment. If a vault's level does not fit (for example a `maximum` vault on
a small laptop), it says so and stops *before* allocating anything, instead of
being killed by the system halfway. Close programs and try again, or open the
vault on a bigger computer.

```bash
cakepass security                     # level, key file, unlock time measured now
cakepass security --level maximum     # switch (asks for your master password)
```

Switching keeps your master password and all items; the vault and its `.bak`
backup are re-encrypted with a fresh salt. Each step up makes every guess about
four times more expensive for an attacker (and unlocking four times slower for
you). Which level is "enough" depends far more on your master password: see
[How strong is this, really?](#how-strong-is-this-really).

### Key files

A key file is a **second secret** next to your master password: a small file
of random bytes, best kept on a USB stick. With a key file, your vault opens
only with **both**. Someone who steals your vault file (a lost laptop, a
synced backup) cannot even start guessing your password without the key file:
they would have to guess its 256 bits as well. Even a weak or leaked master
password is then not enough.

```bash
cakepass keyfile create /run/media/$USER/USB/cakepass.key   # 64 random bytes, never overwrites a file
cakepass security --new-keyfile /run/media/$USER/USB/cakepass.key
```

After that, CakePass remembers **only the path** of the key file in your
settings (`keyfile=…` in `~/.config/cakepass/config`), never its contents, and
reads the file whenever it unlocks: plug in the stick, then unlock as usual.
Other ways to point to it, in this order: `--keyfile PATH`, the environment
variable `CAKEPASS_KEYFILE`, the setting.

> ⚠️ **Losing the key file means losing the vault.** There is no recovery, not
> even with the right password. Keep a **copy of the key file** in a second safe
> place (a second USB stick, a safe), and test the copy.

How it works: CakePass condenses the file into a 256-bit "pepper"
(BLAKE2b-256 with its own label) and gives it to Argon2id as its *secret*
input, together with your password and the salt. The vault header records
that a key file is needed (and that flag is protected like the rest of the
header). A wrong key file gives exactly the same message as a wrong password,
on purpose.

Good to know:

- **Any file** of 1 byte to 1 MiB works, but a file made by `cakepass keyfile
  create` is best: if you use a photo or document, it must never change by a
  single bit (re-saving it in an editor would lock you out).
- Keep the key file **away from the vault**: a key file in the same folder (or
  on the same backup disk) as the vault protects nothing when both are stolen.
  CakePass warns you when they are in the same folder.
- The key file should be readable only by you (`chmod 600`); CakePass warns
  otherwise. On a FAT/exFAT USB stick that cannot be set; keep the stick safe.
- **USB stick not plugged in?** CakePass says it cannot read the key file and
  names the path; nothing else happens.
- **Turn it off**: `cakepass security --no-keyfile` (asks your master password;
  the master password alone opens the vault again). **Use another one**:
  `cakepass security --new-keyfile NEW` (the old one then opens nothing).
- **Updating** CakePass never touches your key file or opens your vault; the
  extra backup made before an update needs the same key file.
- **Export files** (`cakepass export`) are protected by their own export
  password only, not by the key file. Keep them as safe as the vault.
- Copies of the vault you made *before* turning the key file on still open
  without it. Replace them.

---

## Switching from another password manager (CSV)

`cakepass` reads CSV exports from **Bitwarden, KeePassXC, 1Password, Firefox and
Chrome/Chromium**, among others.

```bash
cakepass import-csv ~/Downloads/bitwarden_export.csv
```

> ⚠️ **A CSV export is NOT encrypted.** Anyone who can read the file sees all
> your passwords. Do it like this:
>
> 1. Export, import and delete right afterwards.
> 2. After importing, `cakepass` offers to overwrite and delete the file. Say yes.
> 3. Also check your trash, your Downloads folder and any backups or sync
>    folders (Nextcloud, Syncthing, Dropbox).
> 4. On SSDs and on btrfs/ZFS, overwriting is no guarantee that the data is
>    really gone. Full-disk encryption (LUKS) is the real protection.

Items with a name that already exists get a sequence number, for example
"GitHub (2)". Identical items are skipped, so importing twice makes no duplicates.

### Encrypted export and import (between your own computers)

```bash
cakepass export /run/media/john/usb/cakepass-export.cakepass   # asks for an export password
cakepass import /path/to/cakepass-export.cakepass               # on the other computer
```

The export file is encrypted with a password of its own (the same strong
encryption as the vault).

---

## Backups

**Make backups!** If your disk dies, you lose everything otherwise.

Which files exist:

| File | What |
|---|---|
| `~/.local/share/cakepass/vault.enc` | your vault (encrypted) |
| `~/.local/share/cakepass/vault.enc.bak` | automatic copy of the **previous** version (encrypted) |
| `~/.local/share/cakepass/vault.enc.pre-update-<time>` | extra copies made before an update (last three kept) |
| `~/.local/share/cakepass/vault.enc.lock` | empty lock file, may be deleted |

How:

1. **Copy `vault.enc` regularly** to a USB stick or external drive, and ideally
   to a second place as well. The file is encrypted, so that is safe as long as
   your master password is strong.
   ```bash
   cp ~/.local/share/cakepass/vault.enc /run/media/$USER/USB/cakepass-$(date +%F).enc
   ```
2. **Test your backup**: open it without changing anything.
   ```bash
   cakepass --vault /run/media/$USER/USB/cakepass-2026-10-29.enc list
   ```
3. Restoring = putting the backup file back as `vault.enc`.
4. Did the last change go wrong? The previous version is in `vault.enc.bak`:
   ```bash
   cakepass --vault ~/.local/share/cakepass/vault.enc.bak list
   ```

Good to know:

- A backup opens with the master password (and key file, and level) that
  applied **when you made it**. After `cakepass passwd` or `cakepass security`,
  an old copy still opens the old way. If your old password leaked, throw away
  old copies and make new ones. (The automatic `.bak` is re-encrypted right away.)
- **Using a key file?** Back up the **key file separately** from the vault: a
  copy of the vault is useless without the key file, and a key file stored on
  the same stick as a vault copy protects nothing. Test a backup with
  `cakepass --keyfile /path/to/key-copy --vault /path/to/vault-copy list`.
- After `cakepass rm`, the removed item is still in `.bak` until the next change.
- CakePass 0.4 writes vault **format 3**, which CakePass 0.3 and older cannot
  read. A vault becomes format 3 the first time 0.4 saves it; the `.bak` and
  the copies made by `--update` keep the older format until then.

---

## Updating

> **Arch family only.** `cakepass --update` and the daily check build with
> `makepkg`. On other Linux systems update with the four lines in
> [Update to a newer version](#update-to-a-newer-version).

When new changes are on GitHub, update with:

```bash
cakepass --update
```

```text
$ cakepass --update
Checking GitHub via git (/home/john/cakepass).
┌───────────────────────────────────────────────────────────────┐
│ There is a new version of CakePass.                           │
│ New:  3 change(s)  (branch main)                              │
│ From: https://github.com/Justcakenl/Passcode-Manager.git      │
└───────────────────────────────────────────────────────────────┘
  • 4f2a9c1 New item type: bank card
  • 9be01d7 Faster logo
Update now? [y/N] y
✔ Extra backup of your vault: ~/.local/share/cakepass/vault.enc.pre-update-1793284980
✔ New code fetched.
…building, testing, installing (you type your password once)…
✔ CakePass has been updated. Start `cakepass` again to use the new version.
```

**You do not lose your data.**

- Your vault is in `~/.local/share/cakepass/`, outside the installation. An update
  never touches that folder.
- Before every update `cakepass` makes an extra copy (`vault.enc.pre-update-<time>`;
  the last three are kept). It opens like any vault: `cakepass --vault <copy> list`.
- New versions read your old vault and convert it automatically to the newest
  format the next time they save it. An older version refuses a newer format with a
  clear message ("file version 3 is not supported"), so nothing breaks; the copy
  made before the update still has the old format.
- If building, a test or the installation fails, everything is restored and
  your current version keeps working.
- Your settings (`~/.config/cakepass/`) are not touched either.

**What `cakepass --update` does and does not do:**

- It does not unlock your vault; there is no key in memory while updating.
- It only fetches new commits that do not rewrite your history
  (`git merge --ff-only`). If you changed something in `~/cakepass`, it stops.
- It builds with `makepkg` and runs all tests; only then it installs.
- You see where the update comes from and what is in it, and must confirm.

Options: `cakepass --update --check` (only look), `--yes` (no confirmation),
`--source <dir>` (another source folder).

### Automatic checking

```bash
cakepass --update --auto on       # check every day (turn off: off, look: status)
```

Once a day a small systemd timer looks for a new version. If there is one you
get a desktop notification (with `libnotify`) and a line in `cakepass` and
`cakepass info`. **You install it yourself** with `cakepass --update`.

> **Why not install fully automatically?** A password manager that replaces
> itself without you looking is risky: if someone got into your GitHub account,
> they could make code run on your computer that can reach your vault. The
> installation also needs your sudo password. This way you see what changes
> first. Turn on **two-factor authentication** on your GitHub account.
>
> The automatic check only works without a password prompt if your GitHub access
> works by itself (an SSH key without passphrase or with ssh-agent, or
> `gh auth setup-git`). If that does not work, manual `cakepass --update` still does.

---

## Forgot your master password?

**Then your data is gone. There is no recovery.** The same goes for a lost
**key file** (if you use one) without a copy.

That is not a bug but exactly how it is supposed to work:

- Your vault is encrypted with a key that can only be made from your master
  password. The password is stored nowhere, not even "encrypted" or as a hash.
- There is no "forgot password" button, no back door and no server that could
  help. Even the author of this program cannot open your vault.
- Guessing costs a lot of time and memory per attempt because of Argon2id. With
  a good master password that takes longer than a lifetime.

What you can do to prevent it:

1. Pick a passphrase you can remember (the setup wizard makes one, or
   `cakepass generate --passphrase --show -w 7`) and use it often during the
   first weeks.
2. Write the master password on paper and keep that somewhere safe (for example
   with your passport). Against online attackers, paper is safe.
3. Not sure you still know it? Test it with `cakepass list` before you change it.
4. Using a key file? Keep a tested copy of it in a second place.

If you really cannot remember it, the only thing left is to create a new vault
(`cakepass setup` with another `--vault`, or first delete `~/.local/share/cakepass/`)
and set new passwords on every website via "forgot password".

---

## How the security works

In plain language:

1. Your master password is turned into a 256-bit key with **Argon2id** (by
   default 256 MiB memory, 3 rounds, 4 lanes, a random 32-byte salt; see
   [security levels](#security-levels)). Argon2id is slow and memory-hungry on
   purpose, which makes guessing with expensive graphics cards very costly. With
   a **key file**, its 256-bit pepper is Argon2id's secret input as well.
2. **Two layers of encryption.** From that key, HKDF-SHA256 makes two separate keys:
   - the **file key** encrypts the whole vault on disk;
   - the **item key** additionally encrypts **all the content of every item
     separately**: username, e-mail address, URL, password or API key, and notes.
     Every field has its own random nonce.

   Even while your vault is open (for example on the screen or in the line mode), that
   content is only in memory in encrypted form. Only the name, type and tags are
   readable inside the program while it is open, so you can search (on disk they
   are encrypted by the first layer like everything else). A field is decrypted
   only at the moment it is needed (`get`; `list` shows usernames and URLs) and
   wiped right afterwards. Tested: in the memory of an open vault the password,
   API key, note, username, e-mail address and URL are found 0 times as readable
   text, also right after `list` and `get --show`.
   Tested too: after adding, editing, exporting and changing settings, **no
   readable piece of your data is in any file the program wrote** (vault, backup,
   export). The only plain-text file is the settings file (`animation=off`,
   `lock_timeout_minutes=7`): it holds no user data and is needed before you log in.
3. The whole vault is encrypted with **XChaCha20-Poly1305**. That encrypts and
   checks at the same time ("authenticated encryption"). If even one bit in the
   file changes, `cakepass` refuses to open it. Every save uses a new random nonce.
4. The file starts with a header with version number, the "needs a key file"
   flag and the Argon2 settings. The header is part of the check, so it cannot be
   tampered with either.
5. Saving is **atomic**: first to a temporary file, then `fsync`, then rename. After a
   power failure you always have either the old or the new vault.
6. Files get permissions 600, the folder 700. Only you can access them.
7. Secrets are wiped from memory after use (`zeroize`, `secrecy` and an allocator
   that wipes all released memory, including Argon2's working memory). The keys
   and the decrypted vault live in memory locked with `mlock`, so not in swap.
   The key file and its pepper exist in memory only while Argon2 runs. Core dumps
   are off and other programs cannot look into the memory (`PR_SET_DUMPABLE=0`).
   Tested (release build, vault with a key file): while CakePass is unlocked and
   idle, in the line mode and the screen mode, also after re-keying, the memory
   contains the master password, the key file bytes (or any 16-byte piece of
   them) and the pepper **0 times**.
8. All randomness comes from the operating system (`getrandom`).
9. `cakepass` itself contains no network code. Only the command `cakepass --update`
   starts `git` to fetch your repository, and then your vault is not open.
10. **The screen (arrow keys)** decrypts only what it shows: the usernames of the
    rows you see, the fields of the selected item, and a password, API key or note
    only when you reveal or copy it (and again for every redraw, instead of
    keeping a copy). The picture it draws is kept in a buffer that is wiped on
    every redraw and when you leave, and the bytes for the terminal are written
    straight to it (no buffered output) and wiped. It draws on the terminal's
    "alternate screen", so nothing ends up in your scrollback, and it clears the
    screen when you leave. Tested: after revealing, hiding and editing, the memory
    of the running program contains the password, API key, notes, username,
    e-mail address and URL 0 times as readable text; only the screen cells of the
    item you have selected (its username, e-mail and URL) are in memory while
    they are on screen.

The crates used (among others `argon2`, `chacha20poly1305`, `hkdf`, `sha2`,
`blake2`, `zeroize` and `subtle`) come from the RustCrypto project. `cakepass`
implements no cryptography itself. More details are in [`docs/DESIGN.md`](docs/DESIGN.md).

---

## How strong is this, really?

The short, honest answer: the encryption is as strong as what banks use, and
it is not the weak point. What decides whether a **stolen vault file** stays
closed is your **master password**, plus the **key file** if you use one.

**Compared with banks.** Banks mostly protect stored data with AES-256, and
keep their keys in hardware security modules (HSMs): devices that never let a
key out. CakePass encrypts with XChaCha20-Poly1305, also with 256-bit keys:
the same strength class. Nobody can break either by trying keys, so "better
than banks" is not something another encryption algorithm could honestly give
you. The real difference is elsewhere: a bank's data sits on servers that
attackers can only reach online, where guesses are limited and watched. Your
vault is a file. Someone who copies it can try passwords **offline**, as fast
as their hardware allows, and nobody notices. Argon2id makes every guess
expensive; how many guesses they need depends on your password.

**What guessing costs.** Rough estimates of the average time to find the
master password (half of all possibilities), for an attacker who has the vault
file but **not** the key file:

| Master password | Standard, 1 GPU | Standard, 1,000 GPUs | High, 1,000 GPUs | Maximum, 1,000 GPUs |
|---|---|---|---|---|
| Made up by a person, just passes CakePass's check (zxcvbn score 3: about 10⁸ to 10¹⁰ guesses) | 1 day to 3 months | 1 minute to 2 hours | 5 minutes to 8 hours | 20 minutes to 1.5 days |
| 4 random words (52 bits) | 45,000 years | 45 years | 175 years | 700 years |
| 5 random words (65 bits) | 350 million years | 350,000 years | 1.4 million years | 5.6 million years |
| 6 random words (78 bits) | 3 × 10¹² years | 3 × 10⁹ years | 10¹⁰ years | 4 × 10¹⁰ years |
| 7 random words (90 bits; what the setup wizard makes) | 2 × 10¹⁶ years | 2 × 10¹³ years | 8 × 10¹³ years | 3 × 10¹⁴ years |
| Any of these **plus a key file** they do not have | not feasible: they must also guess 256 random bits | | | |

(The universe is about 1.4 × 10¹⁰ years old.)

Assumptions, so you can redo the sums with your own fears:

- **Speed per GPU**: one top consumer graphics card of today (about 1 TB/s of
  memory bandwidth) at the theoretical limit of that bandwidth, because Argon2id
  is limited by memory traffic: roughly 1,300 guesses per second at Standard,
  330 at High, 80 at Maximum. Real cracking tools are usually slower; we take
  the number that favours the attacker. Hardware gets faster every year, and
  special chips or a nation state can have far more than 1,000 GPUs (renting
  1,000 GPUs costs very roughly $1,000–2,000 per hour). Divide the times by the
  factor you fear.
- **Random words**: chosen at random by the generator from the EFF list of
  7,776 words (12.9 bits per word), and the attacker knows the list and the
  number of words. Words you pick yourself are much weaker.
- **A person's own password**: zxcvbn's estimate of how many guesses a smart
  attacker needs; a guess, not a guarantee.
- These are **rough estimates, not promises**. They say nothing about malware
  on your computer, which simply reads your password as you type it.

What this means: with a password you made up yourself, the level matters a
lot and may still not be enough against a determined attacker. With **6 or 7
random words** the time is astronomical at any level. With a **key file**
kept apart from the vault, a stolen vault file alone is useless.

**Quantum computers.** A large quantum computer could in theory search keys
faster with Grover's algorithm, which halves the effective key length: a
256-bit key then still offers about 128 bits, far out of reach. Everything in
CakePass is symmetric or hash-based (XChaCha20-Poly1305, HKDF-SHA256, BLAKE2b,
Argon2id); there is no RSA, no elliptic curves, no public-key cryptography at
all, so the quantum attacks that break those (Shor's algorithm) have nothing to
attack. Grover could in theory also speed up password guessing, but only by
running Argon2id with gigabytes of memory *inside* a quantum computer, which
nobody knows how to build; even then a 7-word passphrase would take about 2⁴⁵
Argon2id runs one after another.

**What no encryption protects against** (out of scope): malware or a keylogger
on your computer, someone with root access, an "evil maid" (someone who changes
your computer or CakePass while you are away and catches your password later),
being forced to give your password ("rubber-hose"), and someone watching you
type.

**What we deliberately did *not* do, and why:**

- **Stack several ciphers** (AES + Twofish + Serpent, as some tools offer): the
  cipher is not the weak link, and every extra layer is extra code that can
  have mistakes. One well-studied 256-bit authenticated cipher is enough.
- **Our own cryptography**, or extra "hash it a million times" steps: home-made
  constructions are where real-world cryptography breaks. Argon2id is the tool
  designed for making guessing slow; we only turn its dials.
- **A key-commitment tag.** XChaCha20-Poly1305 is not "key-committing": in
  theory someone can build a ciphertext that decrypts under two different keys.
  That matters for systems where many keys meet one ciphertext (messages for
  several recipients, servers that try many keys); for one local file under one
  key it gives an attacker nothing, and the header is already authenticated.
- **Hardware keys** (a YubiKey/FIDO2 key or the TPM): a genuinely stronger
  second factor, but it needs extra libraries and hardware. The key file is the
  simple, auditable version; a hardware key is an idea for later.

---

## Security review and remaining risks

The project went through its own code and found and fixed these problems:

| Found | Fixed |
|---|---|
| In `cakepass shell` the inactivity timer did not work if you walked away in the middle of a question (e.g. at "Username:") | A watchdog now locks then too, and restores the terminal |
| If the clipboard-clearing helper could not start, the password stayed on the clipboard indefinitely | The clipboard is then cleared immediately |
| A malicious import or CSV file could contain control characters (ANSI escapes) that manipulate your terminal | They are rejected or replaced on import, and made visible as `\u{1b}` with `--show` |
| A password you displayed could stay behind in Rust's output buffer | Secrets are written to the terminal without a buffer, and wiped |

Also checked and fine: no option accepts a password as an argument (there is a
test for it). A wrong password and a tampered file give the same message on
purpose. Comparisons of secrets are constant-time. Broken files give clean errors
(tested with every bit flip and every truncated length). Symlinks are refused.
Writing from two terminals at the same time is detected. `cargo audit` reports
no known vulnerabilities.

**Remaining risks** (no password manager can fully protect against these):

1. **Malware and keyloggers.** If malicious software runs under your user or as
   root, it can intercept your master password while you type it, or read your
   memory and clipboard. Only install software you trust.
2. **Swap and hibernation.** The keys and the decrypted vault live in locked
   memory, and item contents stay encrypted in memory. Item names and tags, the
   one field you just asked for, and Argon2's working memory are not locked and
   can end up in swap. Hibernation writes all memory to disk. Use encrypted swap
   (LUKS), zram, or no swap at all.
3. **The clipboard.** While a password is on the clipboard (max. 20 s), any
   program in your session can read it. Clipboard managers (KDE Klipper,
   cliphist, CopyQ, GNOME extensions) sometimes keep a **history** that `cakepass`
   cannot clear. Turn that off or exclude cakepass.
4. **Onlookers and scrollback.** `--show` puts the password on your screen and
   in your terminal's scrollback. On the screen (arrow keys) a revealed password
   is visible for up to 10 seconds; it is not in the scrollback, but a terminal
   recorder (`script`, asciinema) or a terminal emulator's own memory can still
   hold what was shown.
5. **A weak or leaked master password.** Everything stands or falls with your
   master password (unless you use a key file). Do not use it anywhere else.
   See [How strong is this, really?](#how-strong-is-this-really).
6. **Physical access to a running, unlocked computer.** Lock your screen.
   Cold-boot and DMA attacks are out of scope.
7. **Backups with an old password** still open with that old password (see
   [Backups](#backups)); copies made before you turned on a key file open
   without it.
8. **File system.** On SSDs and copy-on-write systems (btrfs, ZFS), old
   unencrypted data (such as a CSV export) may remain. Disk encryption (LUKS) solves that.
9. **Root and the operating system.** Root can do anything, including `ptrace`
   and reading memory. `PR_SET_DUMPABLE=0` only protects against other
   processes of the same user.
10. **Updating from GitHub.** `cakepass --update` installs code from the
    repository you cloned. Anyone with write access to it (or who takes over the
    maintainer's GitHub account) can prepare a malicious update. You see what changes and must
    confirm, but you will probably not read the code itself. Maintainers: limit who has write
    access and turn on two-factor authentication. Users: only install updates you
    expect, and consider reading the changes (`git -C ~/cakepass log -p`) first.
11. **Piping a script into bash.** The one-line installer runs a script you
    downloaded. Read [`install.sh`](install.sh) first; it is short and does
    nothing hidden.
12. **This code has not been externally audited.** The cryptography comes from
    audited crates, but the glue around it was written and reviewed only by the project itself.
13. **A lost key file** locks you out for good, and a key file kept next to the
    vault protects nothing. Keep a copy, and keep it apart from the vault.
14. **Argon2's working memory** (up to 1 GiB) is not locked against swapping
    (it is far above the usual `mlock` limit). It is wiped when Argon2 is done,
    but while it runs it can be swapped; it holds values derived from your
    password, not the password itself. Use encrypted swap or none.

---

## Troubleshooting

| Message | Fix |
|---|---|
| `command not found: cakepass` | The folder you installed to is not in your `PATH`. Do step 5 of the [install](#step-5-install-the-program) and open a new terminal. |
| `error: linker \`cc\` not found` while building | Install a compiler: `sudo apt install build-essential` (Debian family), `sudo dnf install gcc` (Fedora), `sudo zypper install gcc` (openSUSE). |
| `requires rustc 1.88` or `edition2024 is required` while building | Your Rust is too old. Install a current one with `rustup` ([step 2](#step-2-install-rust-version-188-or-newer)) and open a new terminal. |
| The build is killed or `out of memory` | Build with fewer jobs: `cargo build --release --locked -j 1`, or close other programs. A small board may need swap space. |
| `CakePass needs about … MiB of free memory` | The security level does not fit in free memory right now. Close programs, or use the Standard level (`cakepass security --level standard`). |
| `no clipboard tool found` | Install `wl-clipboard` (Wayland) or `xclip` (X11), or use `--show`. Check with `cakepass info`. |
| `Memory could not be locked (mlock)` | Your limit is too low. See it with `ulimit -l` (Arch default: 8192 KiB, plenty). You can raise it in `/etc/security/limits.conf`. |
| `wrong master password, or the file is damaged` | Check Caps Lock and your keyboard layout. Is the file damaged? Try `--vault …/vault.enc.bak` or a backup. With a key file: also check that it is the right key file (the message names the one used). |
| `this vault needs its key file …` | Plug in the USB stick, then give the path once: `cakepass config set keyfile /path/to/cakepass.key` (or `--keyfile PATH`, `CAKEPASS_KEYFILE`). |
| `the key file … cannot be read: it does not exist` | The USB stick is not plugged in or not mounted (`lsblk`), or it is mounted somewhere else; fix the path with `cakepass config set keyfile …`. |
| `… was made with a security level that this computer cannot run at the moment` | Not enough free memory for the vault's Argon2 level. Close programs (a browser) and try again, or open it on a bigger computer and lower the level there with `cakepass security --level high`. |
| `file version 3 is not supported` | An older CakePass (0.3 or earlier) met a vault saved by 0.4. Update CakePass (`cakepass --update`). |
| `the vault was changed by another cakepass process` | You had two terminals open. Run the command again. Your other change was kept. |
| `is a symbolic link` | Give the real path with `--vault`. |
| After Ctrl+C you cannot see what you type | Type `reset` and press Enter. |
| The screen shows odd characters instead of lines | Your terminal or locale is not UTF-8. Set `LANG` to a UTF-8 locale (e.g. `en_US.UTF-8`), or use `cakepass shell`. |
| "Terminal too small" | Make the window at least 60 columns by 16 rows, or use `cakepass shell`. |
| The arrow-key screen does not appear | `cakepass` falls back to the line mode when input or output is not a terminal, with `TERM=dumb`, or in a tiny window. |
| The logo looks wrong or choppy | Try a wider/other terminal, or turn the animation off: `cakepass config set animation off`. |
| Installer: `could not download the code` | Check your internet connection. For a private repository or fork: log in with `gh auth login` (or set up an SSH key), then run the installer again. |
| `cakepass --update`: `I do not know where the source code is` | You did not install with `makepkg -si`/the installer, or the folder was moved. Give it: `cakepass --update --source ~/cakepass`. |
| `cakepass --update`: `git fetch failed` | No internet, or GitHub does not know you. Test with `git -C ~/cakepass fetch` and log in (SSH key or `gh auth login`). |
| `cakepass --update`: `local changes` or `differs from GitHub` | You changed something in `~/cakepass`. Look with `git -C ~/cakepass status`; nothing is overwritten. |

---

## For later

Deliberately not in this version (fewer features that work well beats many):

- Mouse support and themes for the screen (arrow keys); an export button there.
- **TOTP** (two-factor codes, like Google Authenticator).
- A hardware key (YubiKey/FIDO2 `hmac-secret`) as a second factor, next to the key file.
- Turning a key file on or off from the screen (arrow keys); for now that is
  `cakepass security`.
- **Browser integration** (auto-fill).
- More item types (bank card, SSH keys, file attachments).
- Editing notes in `$EDITOR`. Not in yet on purpose: an editor writes temporary
  files unencrypted to disk.
- A translated interface and a non-English diceware word list.
- Configurable clipboard time and a `--clip-time` option.
- Telling clipboard managers that it is a password (`x-kde-passwordManagerHint`).
- Man page (`clap_mangen`).
- Synchronization between devices (e.g. via Syncthing, with conflict detection).

---

## Project structure

```text
install.sh          the one-line installer
src/
├── lib.rs          core library (reusable for a TUI/GUI)
├── error.rs        error messages (without secrets)
├── secure_mem.rs   wiping allocator, mlock, core dumps off      ← critical
├── crypto.rs       Argon2id + HKDF + XChaCha20-Poly1305, levels ← critical
├── keyfile.rs      key files: reading, creating                 ← critical
├── format.rs       file format with version header              ← critical
├── storage.rs      XDG path, atomic write, backup, lock         ← critical
├── vault.rs        items and operations; content encrypted      ← critical
├── generator.rs    passwords and passphrases                    ← critical
├── import.rs       CSV import
├── clipboard.rs    clipboard with automatic clearing            ← critical
├── main.rs         start: allocator + process hardening
└── cli/            arguments, prompts, commands, line mode (shell.rs),
                    setup.rs + config.rs: first-time setup and settings
                    logo.rs: the 3D login screen
                    update.rs: cakepass --update (via git and makepkg)
                    tui/: the screen with arrow keys (no extra libraries)  ← critical
build.rs            records which git commit it was built from
tests/              integration tests (cli, tui in a pseudo-terminal, update, installer)
packaging/arch/     PKGBUILD + systemd timer for the update check
assets/             EFF word list (CC BY 3.0 US)
docs/DESIGN.md      design and threat analysis
PROGRESS.md         progress and what still needs testing on Arch
```

Developing:

```bash
cargo test                                   # all tests
cargo clippy --all-targets -- -D warnings    # lint
cargo audit                                  # known vulnerabilities (cargo install cargo-audit)
```

## Contributing and security

Bug reports and pull requests are welcome. Please run the three commands above
before you open a pull request, and keep the style of the surrounding code. A
security problem? Do **not** open a public issue; follow [SECURITY.md](SECURITY.md).

## License

CakePass is released under the MIT license,
see [`LICENSE`](LICENSE). The EFF word list is under CC BY 3.0 US,
see [`assets/README.md`](assets/README.md).
