//! Tests for the packaging files: the PKGBUILD's `install` lines, the desktop
//! entry and the app icons. They read the files as text (no `makepkg`
//! needed), so a renamed asset, an icon in the folder of the wrong size, or a
//! desktop entry that names another icon is caught before a real package
//! build.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const PKGBUILD: &str = include_str!("../packaging/arch/PKGBUILD");
const AUR_PKGBUILD: &str = include_str!("../packaging/aur/PKGBUILD");
const AUR_SRCINFO: &str = include_str!("../packaging/aur/.SRCINFO");
const DESKTOP: &str = include_str!("../packaging/cakepass.desktop");

/// Every `install -Dm<mode> <source> "<destination>"` line of `package()`:
/// (mode, source, destination with `$pkgdir` removed).
fn installed_files() -> Vec<(String, String, String)> {
    installed_files_of(PKGBUILD)
}

fn installed_files_of(pkgbuild: &str) -> Vec<(String, String, String)> {
    pkgbuild
        .lines()
        .filter_map(|l| l.trim().strip_prefix("install -Dm"))
        .map(|rest| {
            let mut parts = rest.split_whitespace();
            let mode = parts.next().unwrap().to_string();
            let source = parts.next().unwrap().to_string();
            let dest = parts.next().unwrap().trim_matches('"').replace("$pkgdir", "");
            assert!(parts.next().is_none(), "one file per line: {rest}");
            (mode, source, dest)
        })
        .collect()
}

/// Width and height from a PNG's header (the IHDR chunk).
fn png_size(path: &Path) -> (u32, u32) {
    let data = fs::read(path).unwrap();
    assert_eq!(&data[..8], b"\x89PNG\r\n\x1a\n", "{} is not a PNG", path.display());
    assert_eq!(&data[12..16], b"IHDR");
    let num = |at: usize| u32::from_be_bytes(data[at..at + 4].try_into().unwrap());
    (num(16), num(20))
}

#[test]
fn every_installed_data_file_exists_and_is_not_executable() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = installed_files();
    assert!(files.len() >= 10, "{files:?}");
    for (mode, source, dest) in &files {
        if source.contains('$') {
            continue; // the binary, built in $srcdir
        }
        assert!(root.join(source).is_file(), "the PKGBUILD installs {source}, which does not exist");
        assert_eq!(mode, "0644", "{source} -> {dest} is data and must not be executable");
        assert!(dest.starts_with("/usr/"), "{dest}");
    }
}

#[test]
fn the_desktop_entry_and_app_icons_are_installed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = installed_files();
    let source_of = |dest: &str| {
        files.iter().find(|(_, _, d)| d == dest).map(|(_, s, _)| s.clone()).unwrap_or_else(|| {
            panic!("the PKGBUILD does not install {dest}");
        })
    };
    assert_eq!(source_of("/usr/share/applications/cakepass.desktop"), "packaging/cakepass.desktop");
    let svg = source_of("/usr/share/icons/hicolor/scalable/apps/cakepass.svg");
    assert!(fs::read_to_string(root.join(svg)).unwrap().trim_start().starts_with("<svg"));
    // Each PNG goes into the folder of its real size.
    for size in [32, 256, 512] {
        let png = source_of(&format!("/usr/share/icons/hicolor/{size}x{size}/apps/cakepass.png"));
        assert_eq!(png_size(&root.join(&png)), (size, size), "{png}");
    }
    // The folders belong to hicolor-icon-theme, so the package depends on it.
    let depends = PKGBUILD.lines().find(|l| l.starts_with("depends=")).unwrap();
    assert!(depends.contains("'hicolor-icon-theme'"), "{depends}");
}

#[test]
fn the_desktop_entry_starts_cakepass_in_a_terminal() {
    let mut lines = DESKTOP.lines();
    assert_eq!(lines.next(), Some("[Desktop Entry]"));
    let keys: Vec<(&str, &str)> = lines.filter_map(|l| l.split_once('=')).collect();
    let get = |k: &str| keys.iter().find(|(key, _)| *key == k).map(|(_, v)| *v);
    assert_eq!(get("Type"), Some("Application"));
    assert_eq!(get("Name"), Some("CakePass"));
    assert_eq!(get("Exec"), Some("cakepass"));
    assert_eq!(get("Terminal"), Some("true"), "CakePass is a terminal program");
    // The icon name is the file name the PKGBUILD installs (cakepass.png/.svg).
    assert_eq!(get("Icon"), Some("cakepass"));
    assert!(get("Categories").is_some_and(|c| c.ends_with(';')), "a list ends with ';'");
    // The same description as the package itself.
    let comment = get("Comment").unwrap();
    assert!(PKGBUILD.contains(&format!("pkgdesc=\"{comment} (CakePass)\"")), "{comment}");
    // No key twice.
    let mut names: Vec<&str> = keys.iter().map(|(k, _)| *k).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), keys.len());
}

/// Every file `package()` puts in the package: the `install` destinations and
/// the generated ones (`... > "$pkgdir/..."`). The licence folder is named
/// after the package (cakepass / cakepass-git), so it is compared as `<pkg>`.
fn package_contents(pkgbuild: &str) -> BTreeSet<String> {
    let mut files: BTreeSet<String> = installed_files_of(pkgbuild).into_iter().map(|(_, _, d)| d).collect();
    for line in pkgbuild.lines() {
        if let Some((_, dest)) = line.split_once("> \"$pkgdir") {
            files.insert(dest.trim_end_matches('"').to_string());
        }
    }
    files
        .into_iter()
        .map(|f| {
            f.replace("/licenses/$pkgname/", "/licenses/<pkg>/")
                .replace("/licenses/cakepass/", "/licenses/<pkg>/")
        })
        .collect()
}

#[test]
fn the_aur_package_installs_what_the_local_one_does() {
    let local = package_contents(PKGBUILD);
    let aur = package_contents(AUR_PKGBUILD);
    assert!(
        local.len() >= 17 && aur.is_subset(&local),
        "only in the AUR package: {:?}",
        aur.difference(&local)
    );
    // Only what needs a local checkout (`cakepass --update`) is left out.
    let only_local: Vec<&String> = local.difference(&aur).collect();
    assert_eq!(
        only_local,
        [
            "/usr/lib/systemd/user/cakepass-update.service",
            "/usr/lib/systemd/user/cakepass-update.timer",
            "/usr/share/cakepass/source-dir"
        ]
    );
    // Every file it copies exists and is plain data.
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (mode, source, dest) in installed_files_of(AUR_PKGBUILD) {
        if source.contains('$') {
            continue;
        }
        assert!(root.join(&source).is_file(), "{source} does not exist");
        assert_eq!(mode, "0644", "{source} -> {dest}");
    }
    // The real repository, not a local stand-in used for testing.
    assert!(AUR_PKGBUILD.contains(
        "source=(\"$pkgname::git+https://github.com/Justcakenl/Password-Manager.git#branch=main\")"
    ));
    assert!(AUR_PKGBUILD.contains("\npkgver() {\n"), "a -git package computes its version");
}

/// The items of a bash array `name=(...)` in a PKGBUILD (it may span lines).
fn array(pkgbuild: &str, name: &str) -> Vec<String> {
    let start = pkgbuild.find(&format!("\n{name}=(")).map(|i| i + name.len() + 3);
    let Some(start) = start else { return Vec::new() };
    let body = &pkgbuild[start..start + pkgbuild[start..].find(')').unwrap()];
    body.split(['\'', '"'])
        .skip(1)
        .step_by(2)
        .map(|s| s.replace("$_pkgname", "cakepass").replace("$pkgname", "cakepass-git"))
        .collect()
}

#[test]
fn the_aur_srcinfo_is_up_to_date() {
    // .SRCINFO is what the AUR reads; it must be regenerated after every
    // change to the PKGBUILD (`makepkg --printsrcinfo > .SRCINFO`).
    let srcinfo = |key: &str| -> Vec<&str> {
        AUR_SRCINFO.lines().filter_map(|l| l.trim().strip_prefix(&format!("{key} = "))).collect()
    };
    let var = |name: &str| {
        AUR_PKGBUILD
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{name}=")))
            .unwrap()
            .trim_matches('"')
            .to_string()
    };
    assert_eq!(srcinfo("pkgbase"), ["cakepass-git"]);
    assert_eq!(srcinfo("pkgname"), [var("pkgname")]);
    assert_eq!(srcinfo("pkgver"), [var("pkgver")]);
    assert_eq!(srcinfo("pkgrel"), [var("pkgrel")]);
    assert_eq!(srcinfo("pkgdesc"), [var("pkgdesc")]);
    assert_eq!(srcinfo("url"), [var("url")]);
    for key in ["arch", "license", "depends", "makedepends", "optdepends", "provides", "conflicts", "source"]
    {
        assert_eq!(srcinfo(key), array(AUR_PKGBUILD, key), "{key}: run makepkg --printsrcinfo > .SRCINFO");
    }
    // Same program, same needs as the local package.
    for key in ["arch", "license", "depends", "makedepends"] {
        assert_eq!(array(AUR_PKGBUILD, key), array(PKGBUILD, key), "{key}");
    }
    assert_eq!(
        var("pkgdesc"),
        PKGBUILD.lines().find_map(|l| l.strip_prefix("pkgdesc=")).unwrap().trim_matches('"')
    );
}
