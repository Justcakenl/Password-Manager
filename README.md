# CakePass 🍰

![CakePass login screen](docs/cakepass-login.gif)

An **offline vault for the terminal** on Arch Linux, for **passwords, API keys
and secure notes**. The command is called `cakepass`.
Everything lives in one encrypted file on your own computer.
No cloud, no account, no telemetry. The program itself never makes a network
connection; only `cakepass --update` lets `git` fetch your newest version.

> 🔒 This is a **private repository**. Only people you give access on GitHub
> (Settings → Collaborators) can see and install the code. Your vault itself is
> never in this repository: vault files are kept out of git by `.gitignore`.

## Install in one line

You need an Arch Linux computer and a GitHub login that can see this
repository. The installer uses **your** GitHub access, so log in once with the
GitHub CLI (`sudo pacman -S github-cli && gh auth login`), then run:

```bash
gh api repos/Justcakenl/passcode-manager-cli-/contents/install.sh \
  -H "Accept: application/vnd.github.raw" | bash
```

Or the same thing with `curl`:

```bash
curl -fsSL -H "Authorization: Bearer $(gh auth token)" \
  -H "Accept: application/vnd.github.raw" \
  https://api.github.com/repos/Justcakenl/passcode-manager-cli-/contents/install.sh | bash
```

> **Why not a plain `curl https://raw.githubusercontent.com/…` link?** For a
> private repository GitHub answers that with "404 Not Found", because the
> download has no login. The commands above add your login. If you ever make the
> repository (or just the installer) public, this simple link works too:
>
> ```bash
> curl -fsSL https://raw.githubusercontent.com/Justcakenl/passcode-manager-cli-/main/install.sh | bash
> ```

Add options after `bash -s --`, for example `... | bash -s -- --yes --no-setup`.

**What the installer does** (it is a short, readable script; look at
[`install.sh`](install.sh) before you run it, as you should with any script you pipe into `bash`):

1. Checks that you are on Arch Linux, not as root.
2. Installs the tools it needs with `pacman` (`base-devel`, `git`, `rust`, and a
   clipboard tool for your session). Asks for your sudo password.
3. Downloads the source code with `git` into `~/cakepass` (via `gh`, an SSH key,
   or a login prompt).
4. Builds, **tests** and installs the package with `makepkg`.
5. Starts the **first-time setup**: do you want the intro animation, after how
   many minutes should it auto-lock, and your **master password**.

Your vault is never touched by the installer. Run it again any time to update.
Options: `--yes` (no confirmations), `--no-setup`, `--dir DIR`, `--branch B`,
`--uninstall` (removes the program, keeps your vault), `--help`.

Prefer to do it by hand? See [Manual install](#manual-install).

> **Coming from the first version?** The command used to be called `kluis`. It is
> now `cakepass`. Run the installer again: the old package is replaced and your
> old `kluis` folders are moved to `cakepass` automatically, so your vault is kept.

## Contents

1. [First-time setup](#first-time-setup)
2. [Using the screen (arrow keys)](#using-the-screen-arrow-keys)
3. [Daily use (commands)](#daily-use-commands)
4. [Item types: logins, API keys and notes](#item-types-logins-api-keys-and-notes)
5. [Generating passwords](#generating-passwords)
6. [Login screen, settings and auto-lock](#login-screen-settings-and-auto-lock)
7. [Switching from another password manager (CSV)](#switching-from-another-password-manager-csv)
8. [Backups](#backups)
9. [Updating](#updating)
10. [Forgot your master password?](#forgot-your-master-password)
11. [How the security works](#how-the-security-works)
12. [Security review and remaining risks](#security-review-and-remaining-risks)
13. [Troubleshooting](#troubleshooting)
14. [Manual install](#manual-install)
15. [For later](#for-later)

---

## First-time setup

The installer starts it for you. You can also run it yourself at any time:

```bash
cakepass setup
```

```text
Step 1 of 3 — Startup animation
  Play the animation at startup? [Y/n]
Step 2 of 3 — Auto-lock
  Lock after how many minutes of inactivity? [5]
Step 3 of 3 — Master password
  New master password:
  Repeat master password:
✔ Vault created: ~/.local/share/cakepass/vault.enc
```

- **Animation**: the 3D CakePass logo that spins in when you start the program.
  Turn it off if you prefer a still logo; change it later with
  `cakepass config set animation off`.
- **Auto-lock**: after this many idle minutes CakePass (the screen and the line
  mode) locks itself and wipes your secrets from memory.
- **Master password**: the **only** key to your vault. `cakepass` checks it with
  zxcvbn (score 3 of 4 or higher). A great choice is a phrase of five or more
  random words; let cakepass make one: `cakepass generate --passphrase --show`.
  If you forget it, your data is gone ([details](#forgot-your-master-password)).

If a vault already exists, `cakepass setup` only asks the first two questions and
leaves your vault exactly as it is.

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
first, then a new strong one twice), and information about your vault, the
version and the clipboard tool. Changes are saved at once.

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
word). Six words give about 77 bits, which is plenty for a master password.

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

- A backup opens with the master password that applied **when you made it**.
  After `cakepass passwd`, an old copy still works with the old password. If your
  old password leaked, throw away old copies and make new ones. (The automatic
  `.bak` is re-encrypted with the new password right away.)
- After `cakepass rm`, the removed item is still in `.bak` until the next change.

---

## Updating

When you (or someone with write access) pushed changes to GitHub, update with:

```bash
cakepass --update
```

```text
$ cakepass --update
Checking GitHub via git (/home/john/cakepass).
┌──────────────────────────────────────────────────────────────┐
│ There is a new version of CakePass.                          │
│ New:  3 change(s)  (branch main)                             │
│ From: git@github.com:Justcakenl/passcode-manager-cli-.git    │
└──────────────────────────────────────────────────────────────┘
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
  format the next time you unlock. An older version refuses a newer format with a
  clear message, so nothing breaks.
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

**Then your data is gone. There is no recovery.**

That is not a bug but exactly how it is supposed to work:

- Your vault is encrypted with a key that can only be made from your master
  password. The password is stored nowhere, not even "encrypted" or as a hash.
- There is no "forgot password" button, no back door and no server that could
  help. Even the author of this program cannot open your vault.
- Guessing costs a lot of time and memory per attempt because of Argon2id. With
  a good master password that takes longer than a lifetime.

What you can do to prevent it:

1. Pick a passphrase you can remember (`cakepass generate --passphrase --show`) and
   use it often during the first weeks.
2. Write the master password on paper and keep that somewhere safe (for example
   with your passport). Against online attackers, paper is safe.
3. Not sure you still know it? Test it with `cakepass list` before you change it.

If you really cannot remember it, the only thing left is to create a new vault
(`cakepass setup` with another `--vault`, or first delete `~/.local/share/cakepass/`)
and set new passwords on every website via "forgot password".

---

## How the security works

In plain language:

1. Your master password is turned into a 256-bit key with **Argon2id** (64 MiB
   memory, 3 rounds, 4 lanes, a random 32-byte salt). Argon2id is slow and
   memory-hungry on purpose, which makes guessing with expensive graphics cards
   very costly.
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
4. The file starts with a header with version number and settings. The header is
   part of the check, so it cannot be tampered with either.
5. Saving is **atomic**: first to a temporary file, then `fsync`, then rename. After a
   power failure you always have either the old or the new vault.
6. Files get permissions 600, the folder 700. Only you can access them.
7. Secrets are wiped from memory after use (`zeroize`, `secrecy` and an allocator
   that wipes all released memory). The keys and the decrypted vault live in
   memory locked with `mlock`, so not in swap. Core dumps are off and other
   programs cannot look into the memory (`PR_SET_DUMPABLE=0`).
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

## Security review and remaining risks

I went through the code myself and found and fixed these problems:

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
   master password. Do not use it anywhere else.
6. **Physical access to a running, unlocked computer.** Lock your screen.
   Cold-boot and DMA attacks are out of scope.
7. **Backups with an old password** still open with that old password (see
   [Backups](#backups)).
8. **File system.** On SSDs and copy-on-write systems (btrfs, ZFS), old
   unencrypted data (such as a CSV export) may remain. Disk encryption (LUKS) solves that.
9. **Root and the operating system.** Root can do anything, including `ptrace`
   and reading memory. `PR_SET_DUMPABLE=0` only protects against other
   processes of the same user.
10. **Updating from GitHub.** `cakepass --update` installs code from your
    repository. Anyone with write access to it (or who takes over your GitHub
    account) can prepare a malicious update. You see what changes and must
    confirm, but you will probably not read the code itself. Limit who has write
    access, turn on two-factor authentication, and only install updates you expect.
11. **Piping a script into bash.** The one-line installer runs a script you
    downloaded. Read [`install.sh`](install.sh) first; it is short and does
    nothing hidden.
12. **This code has not been externally audited.** The cryptography comes from
    audited crates, but the glue around it was written by me and only reviewed by me.

---

## Troubleshooting

| Message | Fix |
|---|---|
| `no clipboard tool found` | Install `wl-clipboard` (Wayland) or `xclip` (X11), or use `--show`. Check with `cakepass info`. |
| `Memory could not be locked (mlock)` | Your limit is too low. See it with `ulimit -l` (Arch default: 8192 KiB, plenty). You can raise it in `/etc/security/limits.conf`. |
| `wrong master password, or the file is damaged` | Check Caps Lock and your keyboard layout. Is the file damaged? Try `--vault …/vault.enc.bak` or a backup. |
| `the vault was changed by another cakepass process` | You had two terminals open. Run the command again. Your other change was kept. |
| `is a symbolic link` | Give the real path with `--vault`. |
| After Ctrl+C you cannot see what you type | Type `reset` and press Enter. |
| The screen shows odd characters instead of lines | Your terminal or locale is not UTF-8. Set `LANG` to a UTF-8 locale (e.g. `en_US.UTF-8`), or use `cakepass shell`. |
| "Terminal too small" | Make the window at least 60 columns by 16 rows, or use `cakepass shell`. |
| The arrow-key screen does not appear | `cakepass` falls back to the line mode when input or output is not a terminal, with `TERM=dumb`, or in a tiny window. |
| The logo looks wrong or choppy | Try a wider/other terminal, or turn the animation off: `cakepass config set animation off`. |
| Installer: `could not download the code` | The repository is private. Log in: `gh auth login`, or set up an SSH key, then run the installer again. |
| `cakepass --update`: `I do not know where the source code is` | You did not install with `makepkg -si`/the installer, or the folder was moved. Give it: `cakepass --update --source ~/cakepass`. |
| `cakepass --update`: `git fetch failed` | No internet, or GitHub does not know you. Test with `git -C ~/cakepass fetch` and log in (SSH key or `gh auth login`). |
| `cakepass --update`: `local changes` or `differs from GitHub` | You changed something in `~/cakepass`. Look with `git -C ~/cakepass status`; nothing is overwritten. |

---

## Manual install

```bash
sudo pacman -S --needed base-devel git rust
sudo pacman -S wl-clipboard   # Wayland (GNOME, KDE Plasma 6, Sway, Hyprland)
sudo pacman -S xclip          # X11 (i3, Xfce, older sessions)
```

Wondering whether you use Wayland? Type `echo $XDG_SESSION_TYPE`.

The repository is private, so `git` needs your GitHub access. Pick one:

```bash
# a) with an SSH key that belongs to your GitHub account
git clone git@github.com:Justcakenl/passcode-manager-cli-.git ~/cakepass

# b) with the GitHub CLI (pacman -S github-cli)
gh auth login
gh repo clone Justcakenl/passcode-manager-cli- ~/cakepass
```

Then:

```bash
cd ~/cakepass/packaging/arch
makepkg -si
cakepass setup
```

> **Keep the folder `~/cakepass`.** `cakepass --update` uses it to fetch new versions.

`makepkg` builds the program, runs all tests and then installs `/usr/bin/cakepass`,
shell completions for bash, zsh and fish, and the daily update check (off by
default). Skip the tests (faster): `makepkg -si --nocheck`.

Only build, without installing:

```bash
cargo build --release --locked
./target/release/cakepass --help
```

---

## For later

Deliberately not in this version (fewer features that work well beats many):

- Mouse support and themes for the screen (arrow keys); an export button there.
- **TOTP** (two-factor codes, like Google Authenticator).
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
├── crypto.rs       Argon2id + HKDF + XChaCha20-Poly1305         ← critical
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

## License

MIT, see [`LICENSE`](LICENSE). The EFF word list is under CC BY 3.0 US,
see [`assets/README.md`](assets/README.md).
