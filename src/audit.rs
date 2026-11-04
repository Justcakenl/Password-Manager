//! Password health check (`cakepass audit`): a read-only report on the
//! logins and API keys in a vault. Fully offline.
//!
//! SECURITY-CRITICAL: the check decrypts the password or API key of every
//! login and API key, so the report may only ever contain item **names**
//! and counts: never a secret, its length, a hash of it or anything else
//! derived from it. The decrypted values live in `Zeroizing` strings for the
//! length of the check and are wiped when it returns.
//!
//! What it reports, for logins and API keys only (a card number, private
//! key or document number is not a password you choose or rotate):
//! - **weak**: the strength check says it is too weak. The check itself is
//!   passed in by the caller, so the program uses the same zxcvbn estimate
//!   and the same minimum score it applies to master passwords;
//! - **reused**: the same password or key in more than one item, compared
//!   in constant time (as `Vault::merge` compares items);
//! - **stale**: the item was not changed for longer than a number of days
//!   (the modification date covers every field, not only the password: the
//!   vault does not record when the password itself changed);
//! - **empty**: no password or key at all.
//!
//! An empty item is only reported as empty (there is nothing to judge or
//! renew).

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::crypto::ItemKey;
use crate::error::Result;
use crate::vault::{Kind, Vault};

/// Report items not changed in more than this many days, unless told
/// otherwise (`--older-than`).
pub const DEFAULT_STALE_DAYS: u64 = 365;

const DAY_SECS: u64 = 86_400;

/// The outcome of a check: item names only, in the vault's order (by name).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    /// How many logins and API keys were checked.
    pub checked: usize,
    /// Items whose password or key is too weak.
    pub weak: Vec<String>,
    /// Groups of two or more items that share the same password or key.
    pub reused: Vec<Vec<String>>,
    /// Items not changed in more than the given number of days.
    pub stale: Vec<String>,
    /// Items without a password or key.
    pub empty: Vec<String>,
}

impl Report {
    /// Whether nothing was found.
    pub fn is_clean(&self) -> bool {
        self.weak.is_empty() && self.reused.is_empty() && self.stale.is_empty() && self.empty.is_empty()
    }
}

/// Check the logins and API keys of `vault`.
///
/// `now` is the current time in seconds since 1970 and `stale_days` the age
/// from which an item counts as stale; `is_weak` judges one password or key.
pub fn audit(
    vault: &Vault,
    key: &ItemKey,
    now: u64,
    stale_days: u64,
    is_weak: impl Fn(&str) -> bool,
) -> Result<Report> {
    let cutoff = now.saturating_sub(stale_days.saturating_mul(DAY_SECS));
    let mut report = Report::default();
    // (name, decrypted secret) of every checked item that has one. Wiped
    // when this function returns.
    let mut secrets: Vec<(&str, Zeroizing<String>)> = Vec::new();
    for e in vault.entries().iter().filter(|e| matches!(e.kind(), Kind::Login | Kind::Api)) {
        report.checked += 1;
        if !e.has_password() {
            report.empty.push(e.name().to_string());
            continue;
        }
        // An unknown date (0, very old vaults) counts as stale.
        if e.modified() < cutoff {
            report.stale.push(e.name().to_string());
        }
        let secret = e.password(key)?;
        if is_weak(&secret) {
            report.weak.push(e.name().to_string());
        }
        secrets.push((e.name(), secret));
    }
    report.reused = reused_groups(&secrets);
    Ok(report)
}

/// Group the names of items with the same secret (constant-time compare).
fn reused_groups(secrets: &[(&str, Zeroizing<String>)]) -> Vec<Vec<String>> {
    let same = |a: &str, b: &str| bool::from(a.as_bytes().ct_eq(b.as_bytes()));
    let mut taken = vec![false; secrets.len()];
    let mut groups = Vec::new();
    for i in 0..secrets.len() {
        if taken[i] {
            continue;
        }
        let mut group = vec![secrets[i].0.to_string()];
        for j in i + 1..secrets.len() {
            if !taken[j] && same(&secrets[i].1, &secrets[j].1) {
                taken[j] = true;
                group.push(secrets[j].0.to_string());
            }
        }
        if group.len() > 1 {
            groups.push(group);
        }
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::test_item_key;
    use crate::vault::{Entry, NewEntry, now};

    fn vault_with(items: &[(&str, Kind, &str)], key: &ItemKey) -> Vault {
        let mut v = Vault::new();
        for &(name, kind, secret) in items {
            let fields = NewEntry { name: name.into(), kind, password: secret.into(), ..Default::default() };
            v.add(Entry::new(fields, key).unwrap()).unwrap();
        }
        v
    }

    /// A stand-in for zxcvbn: short means weak.
    fn short(s: &str) -> bool {
        s.len() < 8
    }

    #[test]
    fn finds_weak_reused_stale_and_empty_logins_and_api_keys() {
        let key = test_item_key(1);
        let v = vault_with(
            &[
                ("Bank", Kind::Login, "aaaa"),
                ("Forum", Kind::Login, "shared-Secret-1"),
                ("Mail", Kind::Login, "shared-Secret-1"),
                ("Cloud", Kind::Api, "shared-Secret-1"),
                ("Shop", Kind::Login, "unique-Secret-2"),
                ("Other", Kind::Api, "unique-Secret-3"),
                ("Empty", Kind::Login, ""),
                ("Visa", Kind::Card, "4111"),
                ("Server", Kind::SshKey, "k"),
                ("Passport", Kind::Identity, "X1"),
                ("Codes", Kind::Note, ""),
            ],
            &key,
        );
        let fresh = audit(&v, &key, now(), DEFAULT_STALE_DAYS, short).unwrap();
        assert_eq!(fresh.checked, 7, "only logins and API keys");
        assert_eq!(fresh.weak, ["Bank"], "short card numbers, keys and numbers are not judged");
        assert_eq!(
            fresh.reused,
            [vec!["Cloud", "Forum", "Mail"]],
            "a login and an API key may share a secret"
        );
        assert!(fresh.stale.is_empty());
        assert_eq!(fresh.empty, ["Empty"]);
        assert!(!fresh.is_clean());

        // A year and a day later, everything with a secret is stale.
        let later = now() + (DEFAULT_STALE_DAYS + 1) * 86_400;
        let r = audit(&v, &key, later, DEFAULT_STALE_DAYS, short).unwrap();
        assert_eq!(
            r.stale,
            ["Bank", "Cloud", "Forum", "Mail", "Other", "Shop"],
            "the empty item is only 'empty'"
        );
        // ...but not with a longer threshold.
        assert!(audit(&v, &key, later, DEFAULT_STALE_DAYS + 2, short).unwrap().stale.is_empty());
    }

    #[test]
    fn reused_groups_are_exact_and_separate() {
        let key = test_item_key(2);
        let v = vault_with(
            &[
                ("A", Kind::Login, "one-Secret-x"),
                ("B", Kind::Login, "two-Secret-x"),
                ("C", Kind::Login, "one-Secret-x"),
                ("D", Kind::Login, "two-Secret-x"),
                ("E", Kind::Login, "one-Secret-x "),
                ("F", Kind::Login, "ONE-Secret-x"),
            ],
            &key,
        );
        let r = audit(&v, &key, now(), DEFAULT_STALE_DAYS, short).unwrap();
        assert_eq!(r.reused, [vec!["A", "C"], vec!["B", "D"]], "a space or other case is another password");
    }

    #[test]
    fn a_clean_vault_and_an_empty_vault() {
        let key = test_item_key(3);
        let v = vault_with(&[("A", Kind::Login, "long-enough-1"), ("B", Kind::Api, "long-enough-2")], &key);
        let r = audit(&v, &key, now(), DEFAULT_STALE_DAYS, short).unwrap();
        assert!(r.is_clean() && r.checked == 2, "{r:?}");
        let r = audit(&Vault::new(), &key, now(), DEFAULT_STALE_DAYS, short).unwrap();
        assert_eq!(r, Report::default());
    }

    #[test]
    fn the_report_holds_no_secret() {
        let key = test_item_key(4);
        let secrets = ["zq7", "Reused-Secret-zq1", "Reused-Secret-zq1"];
        let v = vault_with(
            &[("W", Kind::Login, secrets[0]), ("R1", Kind::Login, secrets[1]), ("R2", Kind::Api, secrets[2])],
            &key,
        );
        let r = audit(&v, &key, now() + 999 * 86_400, 1, short).unwrap();
        let text = format!("{r:?}");
        for s in secrets {
            assert!(!text.contains(s), "{s} in {text}");
        }
        assert!(!r.is_clean());
    }

    #[test]
    fn a_wrong_key_is_an_error_not_a_clean_report() {
        let v = vault_with(&[("A", Kind::Login, "secret-value-1")], &test_item_key(5));
        assert!(audit(&v, &test_item_key(6), now(), DEFAULT_STALE_DAYS, short).is_err());
    }
}
