//! Wachtwoord- en passphrase-generator.
//!
//! BEVEILIGINGSKRITIEK. Alle willekeur komt van de OS-CSPRNG (`SysRng`, via
//! `getrandom`). Tekens en woorden worden uniform gekozen met `rand`'s
//! `random_range` (zonder "modulo bias"). Als elk gekozen tekentype minstens
//! één keer moet voorkomen, gebruiken we "rejection sampling": we gooien een
//! wachtwoord weg dat daar niet aan voldoet en trekken opnieuw. Zo blijft de
//! uitkomst uniform over alle geldige wachtwoorden.

use std::sync::OnceLock;

use rand::RngExt;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const DIGITS: &str = "0123456789";
/// Leestekens zonder spatie, aanhalingstekens, backslash en backtick
/// (die geven vaak problemen in formulieren en shells).
const SYMBOLS: &str = "!#$%&()*+,-./:;<=>?@[]^_{|}~";
/// Tekens die op elkaar lijken.
const LOOKALIKES: &str = "0O1lI|";

pub const MIN_LENGTH: usize = 8;
pub const MAX_LENGTH: usize = 256;
pub const MIN_WORDS: usize = 4;
pub const MAX_WORDS: usize = 20;

static EFF_WORDLIST_RAW: &str = include_str!("../assets/eff_large_wordlist.txt");

/// De EFF "large" diceware-woordenlijst (7776 woorden, 12,9 bits per woord).
pub fn wordlist() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| EFF_WORDLIST_RAW.lines().filter_map(|l| l.split_whitespace().nth(1)).collect())
}

fn rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

/// Instellingen voor een willekeurig wachtwoord.
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
                "de lengte moet tussen {MIN_LENGTH} en {MAX_LENGTH} liggen"
            )));
        }
        let classes = self.classes();
        if classes.is_empty() {
            return Err(Error::InvalidInput("kies minstens één soort tekens".into()));
        }
        Ok(classes)
    }

    /// Geschatte sterkte in bits: lengte × log2(aantal mogelijke tekens).
    pub fn entropy_bits(&self) -> f64 {
        let pool: usize = self.classes().iter().map(Vec::len).sum();
        self.length as f64 * (pool as f64).log2()
    }
}

/// Genereer een willekeurig wachtwoord.
pub fn generate_password(opts: &PasswordOptions) -> Result<Zeroizing<String>> {
    let classes = opts.validate()?;
    let pool: Vec<char> = classes.iter().flatten().copied().collect();
    let mut rng = rng();
    loop {
        let mut out = Zeroizing::new(String::with_capacity(opts.length));
        for _ in 0..opts.length {
            out.push(pool[rng.random_range(0..pool.len())]);
        }
        // Rejection sampling: elk gekozen tekentype moet erin zitten.
        if classes.iter().all(|class| out.chars().any(|c| class.contains(&c))) {
            return Ok(out);
        }
    }
}

/// Instellingen voor een diceware-passphrase.
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

/// Genereer een passphrase uit de EFF-woordenlijst.
pub fn generate_passphrase(opts: &PassphraseOptions) -> Result<Zeroizing<String>> {
    if !(MIN_WORDS..=MAX_WORDS).contains(&opts.words) {
        return Err(Error::InvalidInput(format!(
            "het aantal woorden moet tussen {MIN_WORDS} en {MAX_WORDS} liggen"
        )));
    }
    if opts.separator.chars().count() > 3 || opts.separator.chars().any(char::is_control) {
        return Err(Error::InvalidInput("het scheidingsteken mag hoogstens 3 gewone tekens zijn".into()));
    }
    let words = wordlist();
    let mut rng = rng();
    let mut out = Zeroizing::new(String::with_capacity(opts.words * (10 + opts.separator.len())));
    for i in 0..opts.words {
        if i > 0 {
            out.push_str(&opts.separator);
        }
        out.push_str(words[rng.random_range(0..words.len())]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn woordenlijst_is_compleet() {
        let w = wordlist();
        assert_eq!(w.len(), 7776);
        assert_eq!(w.iter().collect::<HashSet<_>>().len(), 7776, "alle woorden uniek");
        assert_eq!(w[0], "abacus");
        assert_eq!(w[7775], "zoom");
        assert!(w.iter().all(|s| s.chars().all(|c| c.is_ascii_lowercase() || c == '-')));
    }

    #[test]
    fn wachtwoord_lengte_en_tekensets() {
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
    fn alleen_cijfers_en_zonder_lookalikes() {
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
    fn ongeldige_opties() {
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
    fn wachtwoorden_zijn_verschillend_en_gespreid() {
        let opts = PasswordOptions { length: 16, ..Default::default() };
        let set: HashSet<String> = (0..200).map(|_| generate_password(&opts).unwrap().to_string()).collect();
        assert_eq!(set.len(), 200);
        // Ruwe spreidingstest: alle 10 cijfers komen voor in 2000 cijfertekens.
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
        assert!((e - 77.5).abs() < 0.1, "6 woorden ≈ 77,5 bits, kreeg {e}");
    }

    #[test]
    fn entropie_schatting() {
        let o = PasswordOptions::default();
        let pool = 26 + 26 + 10 + SYMBOLS.len();
        assert!((o.entropy_bits() - 24.0 * (pool as f64).log2()).abs() < 1e-9);
    }
}
