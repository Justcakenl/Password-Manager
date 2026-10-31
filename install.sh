#!/usr/bin/env bash
# CakePass installer for Arch Linux (and derivatives).
#
#   curl -fsSL <link-to-this-file> | bash
#   curl -fsSL <link-to-this-file> | bash -s -- --yes
#
# What it does (nothing is hidden; read this file before you run it):
#   1. checks that you are on Arch Linux and not running as root
#   2. installs the build tools it needs with pacman (asks for your sudo password)
#   3. downloads the CakePass source code with git into ~/cakepass
#      (it uses YOUR GitHub access: gh, an SSH key, or a login prompt)
#   4. builds, tests and installs the package with makepkg
#   5. starts the first-time setup (`cakepass setup`): animation on/off and your
#      master password
#
# Your vault is never touched by this script. Running it again simply updates
# CakePass (the same thing `cakepass --update` does).
#
# Options:
#   -y, --yes        do not ask for confirmations (sudo still asks for your password)
#       --no-setup   install only; skip the first-time setup
#       --dir DIR    where to keep the source code (default: ~/cakepass)
#       --branch B   which branch to install (default: main)
#       --uninstall  remove the CakePass program (your vault is kept)
#   -h, --help       show this help
#
# Environment: CAKEPASS_REPO (owner/name, default Justcakenl/Passcode-Manager),
#              CAKEPASS_DIR, CAKEPASS_BRANCH.
#
# The whole script is wrapped in main() and only runs on the very last line, so
# a download that is cut off halfway can never run half a script.

usage() {
  cat <<'USAGE'
CakePass installer for Arch Linux

Usage: curl -fsSL <link-to-install.sh> | bash [-s -- OPTIONS]
       bash install.sh [OPTIONS]

Options:
  -y, --yes        do not ask for confirmations (sudo still asks for your password)
      --no-setup   install only; skip the first-time setup
      --dir DIR    where to keep the source code (default: ~/cakepass)
      --branch B   which branch to install (default: main)
      --uninstall  remove the CakePass program (your vault is kept)
  -h, --help       show this help

Environment: CAKEPASS_REPO (owner/name), CAKEPASS_DIR, CAKEPASS_BRANCH.
USAGE
}

main() {
  set -euo pipefail

  local REPO="${CAKEPASS_REPO:-Justcakenl/Passcode-Manager}"
  local DIR="${CAKEPASS_DIR:-$HOME/cakepass}"
  local BRANCH="${CAKEPASS_BRANCH:-main}"
  local YES=0 SETUP=1 UNINSTALL=0

  # ── pretty output (colors only on a terminal) ──
  local PINK="" GREEN="" YELLOW="" RED="" DIM="" BOLD="" OFF=""
  if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != "dumb" ]; then
    PINK=$'\033[38;5;205m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'
    DIM=$'\033[2m'; BOLD=$'\033[1m'; OFF=$'\033[0m'
  fi
  step() { printf '\n%s%s%s\n' "$PINK$BOLD" "$*" "$OFF"; }
  say()  { printf '  %s\n' "$*"; }
  ok()   { printf '  %s✔%s %s\n' "$GREEN" "$OFF" "$*"; }
  warn() { printf '  %swarning:%s %s\n' "$YELLOW" "$OFF" "$*" >&2; }
  die()  { printf '\n%serror:%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }

  # ── arguments ──
  while [ $# -gt 0 ]; do
    case "$1" in
      -y|--yes) YES=1 ;;
      --no-setup) SETUP=0 ;;
      --uninstall) UNINSTALL=1 ;;
      --dir) [ $# -ge 2 ] || die "--dir needs a folder"; DIR="$2"; shift ;;
      --branch) [ $# -ge 2 ] || die "--branch needs a name"; BRANCH="$2"; shift ;;
      -h|--help) usage; return 0 ;;
      *) die "unknown option: $1 (try --help)" ;;
    esac
    shift
  done

  # A terminal for questions: when the script comes from a pipe (curl | bash),
  # stdin is the script itself, so we read answers from /dev/tty instead.
  local HAVE_TTY=0
  if [ -r /dev/tty ] && [ -w /dev/tty ] && (: </dev/tty) 2>/dev/null; then HAVE_TTY=1; fi
  tty_run() {
    if [ "$HAVE_TTY" -eq 1 ]; then "$@" </dev/tty; else "$@" </dev/null; fi
  }
  local NOCONFIRM=()
  if [ "$YES" -eq 1 ] || [ "$HAVE_TTY" -eq 0 ]; then NOCONFIRM=(--noconfirm); fi

  printf '\n%s  CakePass installer 🍰%s\n%s  offline · encrypted · yours alone%s\n' "$PINK$BOLD" "$OFF" "$DIM" "$OFF"

  # ── 1. checks ──
  step "[1/5] Checking your system"
  command -v pacman >/dev/null 2>&1 || die "this installer is for Arch Linux (pacman was not found)."
  if [ "$(id -u)" -eq 0 ] && [ -z "${CAKEPASS_INSTALL_ALLOW_ROOT:-}" ]; then
    die "do not run this as root. Run it as your normal user; it asks for sudo when needed."
  fi
  command -v sudo >/dev/null 2>&1 || die "sudo is needed (sudo pacman -S sudo, then add yourself to the wheel group)."
  ok "Arch Linux with pacman and sudo"

  if [ "$UNINSTALL" -eq 1 ]; then
    step "Removing CakePass"
    tty_run sudo pacman -R ${NOCONFIRM[@]+"${NOCONFIRM[@]}"} cakepass
    ok "The cakepass program was removed."
    say "Your vault in ~/.local/share/cakepass was NOT removed, and neither was the source folder $DIR."
    say "Remove them yourself only if you are sure you no longer need them."
    return 0
  fi

  # ── 2. packages ──
  step "[2/5] Installing the tools CakePass needs"
  local WANT=(base-devel git rust) MISSING=() p
  if [ -n "${WAYLAND_DISPLAY:-}" ]; then WANT+=(wl-clipboard)
  elif [ -n "${DISPLAY:-}" ]; then WANT+=(xclip)
  else say "${DIM}No desktop session detected; skipping the clipboard tool (install wl-clipboard or xclip later).${OFF}"; fi
  for p in "${WANT[@]}"; do pacman -Q "$p" >/dev/null 2>&1 || MISSING+=("$p"); done
  if [ "${#MISSING[@]}" -gt 0 ]; then
    say "Installing: ${MISSING[*]}  (sudo will ask for your password)"
    tty_run sudo pacman -S --needed ${NOCONFIRM[@]+"${NOCONFIRM[@]}"} "${MISSING[@]}"
  fi
  ok "tools are ready (${WANT[*]})"

  # ── 3. source code ──
  step "[3/5] Getting the CakePass source code"
  command -v git >/dev/null 2>&1 || die "git is still missing after the installation."
  if [ -d "$DIR/.git" ]; then
    say "Found an existing copy in $DIR; updating it."
    if [ -n "$(git -C "$DIR" status --porcelain)" ]; then
      die "there are local changes in $DIR. Commit or remove them first (git -C $DIR status)."
    fi
    tty_run git -C "$DIR" fetch --quiet origin "$BRANCH" || die "could not reach GitHub. Check your internet and your GitHub login."
    git -C "$DIR" checkout --quiet "$BRANCH" 2>/dev/null || true
    git -C "$DIR" merge --ff-only --quiet FETCH_HEAD \
      || die "$DIR has diverged from GitHub (you made commits there). Sort that out with git first."
  else
    [ -e "$DIR" ] && die "$DIR already exists and is not a CakePass copy. Use --dir to choose another folder."
    clone_repo "$REPO" "$BRANCH" "$DIR"
  fi
  ok "source code in $DIR ($(git -C "$DIR" rev-parse --short=12 HEAD))"
  [ -f "$DIR/packaging/arch/PKGBUILD" ] || die "$DIR does not look like CakePass (no packaging/arch/PKGBUILD)."

  # ── 4. build and install ──
  step "[4/5] Building, testing and installing"
  say "This takes a few minutes the first time. You will be asked for your sudo password."
  if pacman -Q kluis >/dev/null 2>&1; then
    say "Replacing the old 'kluis' program by 'cakepass' (same program, new name)."
    say "${DIM}Your vault is not touched; its folder is renamed automatically the first time you run cakepass.${OFF}"
    tty_run sudo pacman -R ${NOCONFIRM[@]+"${NOCONFIRM[@]}"} kluis
  fi
  ( cd "$DIR/packaging/arch" && tty_run makepkg -si -f ${NOCONFIRM[@]+"${NOCONFIRM[@]}"} ) \
    || die "the build or installation failed. Nothing was changed about an existing CakePass."
  command -v cakepass >/dev/null 2>&1 || die "cakepass was not found after installing. Open a new terminal and try again."
  ok "installed: $(cakepass --version 2>/dev/null || echo cakepass)"

  # ── 5. first-time setup ──
  step "[5/5] First-time setup"
  if [ "$SETUP" -eq 1 ] && [ "$HAVE_TTY" -eq 1 ]; then
    say "A short wizard follows: animation on/off, auto-lock time and your master password."
    printf '\n'
    tty_run cakepass setup || warn "setup was cancelled. Run it again any time with:  cakepass setup"
  else
    say "Run the setup when you are ready:  ${BOLD}cakepass setup${OFF}"
  fi

  printf '\n%s  All done! 🍰%s\n' "$GREEN$BOLD" "$OFF"
  say "Start CakePass:   ${BOLD}cakepass${OFF}"
  say "Update later:     ${BOLD}cakepass --update${OFF}"
  say "Keep the folder ${BOLD}$DIR${OFF} – the updater uses it."
  printf '\n'
}

# Download the repository. A public repository needs no login at all; for a
# private one (or a private fork) this uses YOUR GitHub access.
# Order: explicit URL (forks/tests) → anonymous HTTPS → gh (logged in) → SSH key
# → HTTPS login prompt.
clone_repo() {
  local repo="$1" branch="$2" dir="$3"
  if [ -n "${CAKEPASS_REPO_URL:-}" ]; then
    say "Cloning from $CAKEPASS_REPO_URL"
    tty_run git clone --quiet --branch "$branch" "$CAKEPASS_REPO_URL" "$dir" \
      || die "could not clone $CAKEPASS_REPO_URL"
    return 0
  fi
  if GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=true git clone --quiet --branch "$branch" \
       "https://github.com/$repo.git" "$dir" >/dev/null 2>&1; then
    return 0
  fi
  rm -rf "$dir"
  if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    say "Cloning with the GitHub CLI (gh)"
    if tty_run gh repo clone "$repo" "$dir" -- --quiet --branch "$branch"; then return 0; fi
    warn "gh could not clone it; trying SSH."
    rm -rf "$dir"
  fi
  if GIT_SSH_COMMAND="ssh -o BatchMode=yes -o ConnectTimeout=15" \
       git ls-remote --exit-code "git@github.com:$repo.git" HEAD >/dev/null 2>&1; then
    say "Cloning over SSH"
    if tty_run git clone --quiet --branch "$branch" "git@github.com:$repo.git" "$dir"; then return 0; fi
    rm -rf "$dir"
  fi
  say "Cloning over HTTPS (git may ask for your GitHub username and a personal access token)"
  if tty_run git clone --quiet --branch "$branch" "https://github.com/$repo.git" "$dir"; then return 0; fi
  rm -rf "$dir"
  die "could not download the code. Check your internet connection. If the repository is
  private, git needs your GitHub login. Easiest fixes (pick one, then run this installer again):
    • sudo pacman -S github-cli && gh auth login
    • add an SSH key to your GitHub account (ssh-keygen, then github.com/settings/keys)
    • create a personal access token and use it as the password when git asks"
}

main "$@"
