# Security policy

CakePass keeps passwords, API keys and notes, so security reports are taken
seriously.

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Use GitHub's private reporting instead: on the repository page go to
**Security → Report a vulnerability**. Describe what you found, how to reproduce
it, and which version you used (`cakepass --version`). You will get an answer as
soon as possible, and you will be credited in the fix if you wish.

## What is in scope

- Ways to read vault contents without the master password.
- Secrets left readable on disk, in memory after they should be wiped, in the
  terminal scrollback, or in error messages and logs.
- Problems in the update or installer flow (`cakepass --update`, `install.sh`).

## Known limits

The design and its remaining risks are described in
[README.md](README.md#security-review-and-remaining-risks) and
[docs/DESIGN.md](docs/DESIGN.md). CakePass has not been audited by an outside
expert.

## Supported versions

Only the latest release (the `main` branch) receives fixes. Update with
`cakepass --update`.
