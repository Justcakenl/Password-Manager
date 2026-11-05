# App icon

The CakePass app icon: the cake-padlock symbol on a dark cocoa rounded square.
It is the icon application launchers show for `packaging/cakepass.desktop`; the
PKGBUILD installs it into the hicolor icon theme as `cakepass`.

- `cakepass-app-icon.svg`: the scalable icon (`hicolor/scalable/apps`)
- `cakepass-app-icon-32.png`, `-256.png`, `-512.png`: the same icon as PNG at
  32, 256 and 512 px (`hicolor/<size>x<size>/apps`)

They come unmodified from the maintainer's CakePass logo set (the
`CakePass-logo/` folder kept next to this repository). That set also holds the
branding logo and other icon variants; only the `cakepass-app-icon*` files are
used here.

| File | SHA-256 |
|---|---|
| `cakepass-app-icon.svg` | `b9f29832aadaeca56e34156e5a2a764fee872bc204958b7d19e86a27b2f854bc` |
| `cakepass-app-icon-32.png` | `f28c433ae87b218e11f4b736b7d6fbdc200839937342a3cbdf1b5d86a774db4e` |
| `cakepass-app-icon-256.png` | `b37a317c5a14b1db2659498c428ba78c9785ff313b93640e2a21c50528150cbe` |
| `cakepass-app-icon-512.png` | `4697836969066a280dff4d1f68f9cbf870cc30745d2f32c13195be279751bf28` |

## Not covered by the MIT license

The CakePass name and logo — this app icon, the branding logo used
elsewhere in the README (`docs/cakepass-logo.png`), and the rest of the
maintainer's CakePass logo set — identify this specific project. Unlike
the code, they are **not** licensed under the MIT license (see the root
[`LICENSE`](../../LICENSE)).

You may use them, unmodified, to refer to CakePass itself: packaging,
documentation, articles, an unmodified fork that stays CakePass. You may
**not** use them to identify, endorse or promote any other software, or
any modified/forked version of CakePass, without the maintainer's
permission. The MIT-licensed code is unaffected by this — you can still
freely fork, modify and redistribute CakePass itself, just not under its
name or logo.
