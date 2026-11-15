//! Password and passphrase generator.
//!
//! SECURITY-CRITICAL. All randomness comes from the OS CSPRNG (`SysRng`, via
//! `getrandom`). Characters and words are chosen uniformly with `rand`'s
//! `random_range` (no "modulo bias"). When every selected character class
//! must appear at least once we use "rejection sampling": a password that
//! does not satisfy that is thrown away and drawn again. This keeps the
//! result uniform over all valid passwords.

use std::sync::OnceLock;

use rand::RngExt;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const DIGITS: &str = "0123456789";
/// Symbols without space, quotes, backslash and backtick
/// (those often cause trouble in forms and shells).
const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";
/// Characters that look alike.
const LOOKALIKES: &str = "0O1lI|";

pub const MIN_LENGTH: usize = 8;
pub const MAX_LENGTH: usize = 256;
pub const MIN_WORDS: usize = 4;
pub const MAX_WORDS: usize = 20;

static EFF_WORDLIST_RAW: &str = include_str!("../assets/eff_large_wordlist.txt");

/// The EFF "large" diceware word list (7776 words, 12.9 bits per word).
pub fn wordlist() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| EFF_WORDLIST_RAW.lines().filter_map(|l| l.split_whitespace().nth(1)).collect())
}

fn rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

/// Settings for a random password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordOptions {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_lookalikes: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        PasswordOptions {
            length: 24,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            exclude_lookalikes: false,
        }
    }
}

impl PasswordOptions {
    fn classes(&self) -> Vec<Vec<char>> {
        let mut classes = Vec::new();
        for (enabled, set) in
            [(self.uppercase, UPPER), (self.lowercase, LOWER), (self.digits, DIGITS), (self.symbols, SYMBOLS)]
        {
            if enabled {
                let chars: Vec<char> =
                    set.chars().filter(|c| !(self.exclude_lookalikes && LOOKALIKES.contains(*c))).collect();
                classes.push(chars);
            }
        }
        classes
    }

    fn validate(&self) -> Result<Vec<Vec<char>>> {
        if !(MIN_LENGTH..=MAX_LENGTH).contains(&self.length) {
            return Err(Error::InvalidInput(format!(
                "the length must be between {MIN_LENGTH} and {MAX_LENGTH}"
            )));
        }
        let classes = self.classes();
        if classes.is_empty() {
            return Err(Error::InvalidInput("choose at least one kind of characters".into()));
        }
        Ok(classes)
    }

    /// Estimated strength in bits: length × log2(number of possible characters).
    pub fn entropy_bits(&self) -> f64 {
        let pool: usize = self.classes().iter().map(Vec::len).sum();
        self.length as f64 * (pool as f64).log2()
    }
}

/// The longest word of your own that can go into a generated password.
pub const MAX_OWN_WORD: usize = 32;

/// Check a word of your own (see [`generate_password_with`]): 1 to
/// [`MAX_OWN_WORD`] characters, no spaces at the ends, no control characters.
pub fn check_own_word(word: &str) -> Result<()> {
    let n = word.chars().count();
    if n == 0 || n > MAX_OWN_WORD {
        return Err(Error::InvalidInput(format!("your own word must be 1 to {MAX_OWN_WORD} characters")));
    }
    if word.trim() != word || word.chars().any(char::is_control) {
        return Err(Error::InvalidInput(
            "your own word may not start or end with a space, or hold control characters".into(),
        ));
    }
    Ok(())
}

/// A random password, with `own` (a word of your own) put in at a random
/// place. The random part keeps the full length, so the password is never
/// weaker than without the word. SECURITY: the word adds no strength (it may
/// be guessable: a name, a site), so [`PasswordOptions::entropy_bits`]
/// counts only the random part.
pub fn generate_password_with(opts: &PasswordOptions, own: Option<&str>) -> Result<Zeroizing<String>> {
    let random = generate_password(opts)?;
    let Some(word) = own else { return Ok(random) };
    check_own_word(word)?;
    let at = rng().random_range(0..=opts.length);
    let mut out = Zeroizing::new(String::with_capacity(random.len() + word.len()));
    out.extend(random.chars().take(at));
    out.push_str(word);
    out.extend(random.chars().skip(at));
    Ok(out)
}

/// A passphrase with `own` as one extra word at a random place (between the
/// separators). As with [`generate_password_with`], the generated words
/// keep their number and only they count for the strength.
pub fn generate_passphrase_with(opts: &PassphraseOptions, own: Option<&str>) -> Result<Zeroizing<String>> {
    let Some(word) = own else { return generate_passphrase(opts) };
    check_own_word(word)?;
    let at = rng().random_range(0..=opts.words);
    passphrase(opts, Some((at, word)))
}

/// Generate a random password.
pub fn generate_password(opts: &PasswordOptions) -> Result<Zeroizing<String>> {
    let classes = opts.validate()?;
    let pool: Vec<char> = classes.iter().flatten().copied().collect();
    let mut rng = rng();
    loop {
        let mut out = Zeroizing::new(String::with_capacity(opts.length));
        for _ in 0..opts.length {
            out.push(pool[rng.random_range(0..pool.len())]);
        }
        // Rejection sampling: every selected character class must be present.
        if classes.iter().all(|class| out.chars().any(|c| class.contains(&c))) {
            return Ok(out);
        }
    }
}

/// Settings for a diceware passphrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: String,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        PassphraseOptions { words: 6, separator: "-".into() }
    }
}

impl PassphraseOptions {
    pub fn entropy_bits(&self) -> f64 {
        self.words as f64 * (wordlist().len() as f64).log2()
    }
}

/// Generate a passphrase from the EFF word list.
pub fn generate_passphrase(opts: &PassphraseOptions) -> Result<Zeroizing<String>> {
    passphrase(opts, None)
}

/// The passphrase; `own` puts that word in before generated word `at`.
fn passphrase(opts: &PassphraseOptions, own: Option<(usize, &str)>) -> Result<Zeroizing<String>> {
    if !(MIN_WORDS..=MAX_WORDS).contains(&opts.words) {
        return Err(Error::InvalidInput(format!(
            "the number of words must be between {MIN_WORDS} and {MAX_WORDS}"
        )));
    }
    if opts.separator.chars().count() > 3 || opts.separator.chars().any(char::is_control) {
        return Err(Error::InvalidInput("the separator may be at most 3 plain characters".into()));
    }
    let words = wordlist();
    let mut rng = rng();
    let mut out = Zeroizing::new(String::with_capacity((opts.words + 1) * (10 + opts.separator.len())));
    let mut put = |w: &str| {
        if !out.is_empty() {
            out.push_str(&opts.separator);
        }
        out.push_str(w);
    };
    for i in 0..=opts.words {
        if let Some((_, word)) = own.filter(|(at, _)| *at == i) {
            put(word);
        }
        if i < opts.words {
            put(words[rng.random_range(0..words.len())]);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn your_own_word_goes_in_at_a_random_place_and_the_rest_stays_random() {
        let opts = PasswordOptions { length: 16, ..Default::default() };
        let mut places = HashSet::new();
        for _ in 0..300 {
            let pw = generate_password_with(&opts, Some("Justin")).unwrap();
            let at = pw.find("Justin").expect("the word is in it");
            places.insert(at);
            let rest: String = pw.replacen("Justin", "", 1);
            assert_eq!(rest.chars().count(), 16, "the random part keeps its full length");
        }
        assert!(places.contains(&0) && places.contains(&16), "start and end are possible");
        assert!(places.len() > 10, "{places:?}");
        // Without a word: as before.
        assert_eq!(generate_password_with(&opts, None).unwrap().chars().count(), 16);
        // In a passphrase: one extra word between the separators.
        let p = PassphraseOptions { words: 5, separator: ".".into() };
        let mut at = HashSet::new();
        for _ in 0..200 {
            let phrase = generate_passphrase_with(&p, Some("Café")).unwrap();
            let parts: Vec<&str> = phrase.split('.').collect();
            assert_eq!(parts.len(), 6, "{}", phrase.as_str());
            at.insert(parts.iter().position(|w| *w == "Café").unwrap());
        }
        assert_eq!(at.len(), 6, "every place, first to last: {at:?}");
    }

    #[test]
    fn your_own_word_is_checked() {
        let opts = PasswordOptions::default();
        for bad in ["", " x", "x ", "a\u{1b}b", "tab\there", &"x".repeat(MAX_OWN_WORD + 1)] {
            assert!(generate_password_with(&opts, Some(bad)).is_err(), "{bad:?}");
            assert!(generate_passphrase_with(&PassphraseOptions::default(), Some(bad)).is_err(), "{bad:?}");
        }
        assert!(check_own_word("two words").is_ok() && check_own_word(&"é".repeat(MAX_OWN_WORD)).is_ok());
    }

    #[test]
    fn word_list_is_complete() {
        let w = wordlist();
        assert_eq!(w.len(), 7776);
        assert_eq!(w.iter().collect::<HashSet<_>>().len(), 7776, "all words unique");
        assert_eq!(w[0], "abacus");
        assert_eq!(w[7775], "zoom");
        assert!(w.iter().all(|s| s.chars().all(|c| c.is_ascii_lowercase() || c == '-')));
    }

    #[test]
    fn password_length_and_character_sets() {
        let opts = PasswordOptions { length: 40, ..Default::default() };
        for _ in 0..50 {
            let pw = generate_password(&opts).unwrap();
            assert_eq!(pw.chars().count(), 40);
            assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
            assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
            assert!(pw.chars().any(|c| c.is_ascii_digit()));
            assert!(pw.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn digits_only_and_without_lookalikes() {
        let opts = PasswordOptions {
            length: 64,
            uppercase: false,
            lowercase: false,
            symbols: false,
            exclude_lookalikes: true,
            ..Default::default()
        };
        let pw = generate_password(&opts).unwrap();
        assert!(pw.chars().all(|c| c.is_ascii_digit() && c != '0' && c != '1'));
        let opts = PasswordOptions { length: 200, exclude_lookalikes: true, ..Default::default() };
        let pw = generate_password(&opts).unwrap();
        assert!(!pw.chars().any(|c| LOOKALIKES.contains(c)));
    }

    #[test]
    fn invalid_options() {
        let none = PasswordOptions {
            uppercase: false,
            lowercase: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        assert!(generate_password(&none).is_err());
        assert!(generate_password(&PasswordOptions { length: 7, ..Default::default() }).is_err());
        assert!(generate_password(&PasswordOptions { length: 257, ..Default::default() }).is_err());
        assert!(generate_passphrase(&PassphraseOptions { words: 3, ..Default::default() }).is_err());
        assert!(generate_passphrase(&PassphraseOptions { words: 6, separator: "\n".into() }).is_err());
    }

    #[test]
    fn passwords_differ_and_are_spread_out() {
        let opts = PasswordOptions { length: 16, ..Default::default() };
        let set: HashSet<String> = (0..200).map(|_| generate_password(&opts).unwrap().to_string()).collect();
        assert_eq!(set.len(), 200);
        // Rough distribution test: all 10 digits occur in 2000 digit characters.
        let digits = PasswordOptions {
            length: 200,
            uppercase: false,
            lowercase: false,
            symbols: false,
            ..Default::default()
        };
        let mut seen = HashSet::new();
        for _ in 0..10 {
            seen.extend(generate_password(&digits).unwrap().chars());
        }
        assert_eq!(seen.len(), 10);
    }

    #[test]
    fn passphrase() {
        let p = generate_passphrase(&PassphraseOptions { words: 7, separator: ".".into() }).unwrap();
        let parts: Vec<&str> = p.split('.').collect();
        assert_eq!(parts.len(), 7);
        assert!(parts.iter().all(|w| wordlist().contains(w)));
        let e = PassphraseOptions::default().entropy_bits();
        assert!((e - 77.5).abs() < 0.1, "6 words ≈ 77.5 bits, got {e}");
    }

    #[test]
    fn entropy_estimate() {
        let o = PasswordOptions::default();
        let pool = 26 + 26 + 10 + SYMBOLS.len();
        assert!((o.entropy_bits() - 24.0 * (pool as f64).log2()).abs() < 1e-9);
    }
}
