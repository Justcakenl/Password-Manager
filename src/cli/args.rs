//! Command-line arguments (clap).
//!
//! SECURITY: there is deliberately NO option that accepts a password as a
//! value. Passwords are always read through a hidden prompt or stdin, so they
//! are not visible in `ps` or in your shell history.

use std::path::PathBuf;

use cakepass::crypto::SecurityLevel;
use cakepass::vault::Kind;
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};

use super::update::AutoMode;

/// Version for `cakepass --version`: number + the git commit it was built from.
const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (commit ", env!("CAKEPASS_GIT_COMMIT"), ")");

/// Parse an item type ("login", "api" or "note") for clap.
fn parse_kind(s: &str) -> Result<Kind, String> {
    Kind::parse(s).ok_or_else(|| format!("unknown type '{s}'; choose login, api or note"))
}

/// Parse a security level ("standard", "high" or "maximum") for clap.
fn parse_level(s: &str) -> Result<SecurityLevel, String> {
    SecurityLevel::parse(s).ok_or_else(|| format!("unknown level '{s}'; choose standard, high or maximum"))
}

const HELP_TEMPLATE: &str = "{about-with-newline}\nUsage: {usage}\n\n{all-args}{after-help}";

/// Apply the shared help template to a command and all its subcommands.
fn with_template(cmd: clap::Command) -> clap::Command {
    cmd.help_template(HELP_TEMPLATE).mut_subcommands(with_template)
}

/// The full command-line definition of `cakepass`.
pub fn command() -> clap::Command {
    use clap::CommandFactory;
    with_template(Cli::command())
}

/// The definition used to parse lines typed inside `cakepass shell`.
pub fn shell_command() -> clap::Command {
    use clap::CommandFactory;
    with_template(ShellLine::command())
}

#[derive(Parser, Debug)]
#[command(
    name = "cakepass",
    version = VERSION,
    about = "CakePass – offline, encrypted vault for passwords, API keys and notes\n(command: cakepass)",
    help_template = HELP_TEMPLATE,
    disable_help_flag = true,
    disable_version_flag = true,
    disable_help_subcommand = true,
    subcommand_help_heading = "Commands",
    subcommand_value_name = "COMMAND",
    next_help_heading = "Options",
    after_help = "Examples:\n  \
        cakepass setup                   first-time setup (animation, master password)\n  \
        cakepass                         open CakePass: login, then a screen you use with the arrow keys\n  \
        cakepass shell                   the line mode: unlock once, then type commands (list, get, ...)\n  \
        cakepass add GitHub              add a login (asks for every field)\n  \
        cakepass add OpenAI --type api   store an API key\n  \
        cakepass add Recovery --type note   secure note\n  \
        cakepass get GitHub              copy the password to the clipboard (20 s)\n  \
        cakepass generate --passphrase   make a passphrase\n  \
        cakepass generate --save Mail    generate, change it if you like, save it\n  \
        cakepass config set animation off   turn the intro animation off\n  \
        cakepass security                show the security level and key file; change them\n  \
        cakepass security --level maximum   make guessing your password even more expensive\n  \
        cakepass keyfile create /run/media/$USER/USB/cakepass.key   a key file for a USB stick\n  \
        cakepass --update                update CakePass to the newest version (your vault is kept)\n\n\
        Passwords are never passed as arguments; you type them in a hidden prompt."
)]
pub struct Cli {
    /// Path to the vault file [default: ~/.local/share/cakepass/vault.enc]
    #[arg(long, global = true, env = "CAKEPASS_VAULT", hide_env_values = true, value_name = "PATH")]
    pub vault: Option<PathBuf>,

    /// Key file, for a vault that needs one [default: the `keyfile` setting]
    #[arg(long, global = true, env = "CAKEPASS_KEYFILE", hide_env_values = true, value_name = "PATH")]
    pub keyfile: Option<PathBuf>,

    /// Do not use colors
    #[arg(long, global = true)]
    pub no_color: bool,

    /// No animation on the login screen (show the logo still)
    #[arg(long, global = true)]
    pub no_animation: bool,

    /// Without a command: use the line mode (typed commands) instead of the arrow-key screen
    #[arg(long, global = true)]
    pub no_tui: bool,

    /// Show this help
    #[arg(short = 'h', long = "help", action = ArgAction::Help, global = true)]
    help: Option<bool>,

    /// Show the version
    #[arg(short = 'V', long = "version", action = ArgAction::Version)]
    version: Option<bool>,

    /// Without a command, the login screen opens, then the arrow-key screen.
    #[command(subcommand)]
    pub command: Option<Cmd>,
}

/// Used to parse lines inside `cakepass shell`.
#[derive(Parser, Debug)]
#[command(
    name = "cakepass",
    help_template = "{all-args}",
    disable_help_flag = true,
    disable_version_flag = true,
    disable_help_subcommand = true,
    subcommand_help_heading = "Commands",
    subcommand_value_name = "COMMAND"
)]
pub struct ShellLine {
    /// Show help
    #[arg(short = 'h', long = "help", action = ArgAction::Help, global = true)]
    help: Option<bool>,

    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// First-time setup: animation, lock timeout, security level, master password, key file
    Setup {
        #[command(flatten)]
        kdf: KdfArgs,
    },

    /// Create a new, empty vault (without the setup questions)
    Init {
        #[command(flatten)]
        kdf: KdfArgs,
    },

    /// Add a login, API key or note (without options, cakepass asks for everything)
    Add(AddArgs),

    /// Show an item and copy its secret (password, key, note) to the clipboard
    #[command(alias = "show")]
    Get(GetArgs),

    /// Change an item (without options, cakepass asks for each field)
    Edit(EditArgs),

    /// Remove an item
    #[command(alias = "remove", alias = "delete")]
    Rm {
        /// Name of the item
        name: String,
        /// Do not ask for confirmation
        #[arg(short = 'y', long)]
        yes: bool,
    },

    /// List all items (without secrets)
    #[command(alias = "ls")]
    List {
        /// Only items with this tag
        #[arg(short, long)]
        tag: Option<String>,
        /// Only this type: login, api or note
        #[arg(long = "type", value_name = "TYPE", value_parser = parse_kind)]
        kind: Option<Kind>,
    },

    /// Search name, type, tags, username, e-mail address and URL
    #[command(alias = "find")]
    Search {
        /// Search term (case-insensitive)
        query: String,
    },

    /// Generate a password or passphrase; in a terminal you can view, edit,
    /// regenerate, copy or save it straight into the vault
    #[command(alias = "gen")]
    Generate {
        /// Show the result on screen instead of copying it
        #[arg(long)]
        show: bool,
        /// Save the result as a new login with this name (asks for the master password)
        #[arg(long, value_name = "NAME")]
        save: Option<String>,
        #[command(flatten)]
        opts: GenArgs,
    },

    /// Change the master password (and optionally the Argon2 settings)
    #[command(alias = "change-password")]
    Passwd {
        #[command(flatten)]
        kdf: KdfChangeArgs,
    },

    /// Export the vault to a new, encrypted file
    Export {
        /// Destination file (must not exist yet)
        file: PathBuf,
    },

    /// Add items from an encrypted export file
    Import {
        /// Export file made with `cakepass export`
        file: PathBuf,
    },

    /// Add items from a CSV export of another manager (UNENCRYPTED!)
    ImportCsv {
        /// CSV file (Bitwarden, KeePassXC, 1Password, Firefox, Chrome, ...)
        file: PathBuf,
    },

    /// Show information about the vault and security (no password needed)
    Info,

    /// Show the security level and key file; with options, change them
    /// (asks for the master password)
    Security(SecurityArgs),

    /// Key files: a second secret for your vault, e.g. on a USB stick
    Keyfile {
        #[command(subcommand)]
        action: KeyfileAction,
    },

    /// Show or change settings (animation, lock timeout)
    Config {
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },

    /// Show the CakePass logo (with animation)
    Logo,

    /// Update CakePass to the newest version on GitHub (your vault is left untouched)
    Update(UpdateArgs),

    /// Line mode: unlock once, type commands; locks after inactivity
    Shell {
        /// Lock automatically after this many seconds without input
        /// [default: 300, or the value set with `cakepass config`]
        #[arg(long, value_name = "SECONDS")]
        timeout: Option<u64>,
    },

    /// Print a shell completion script (bash, zsh or fish)
    Completions {
        /// bash, zsh or fish
        shell: clap_complete::Shell,
    },
}

/// What `cakepass config` can do.
#[derive(Subcommand, Debug, Clone)]
pub enum ConfigAction {
    /// Show the current settings
    Show,
    /// Change a setting
    Set {
        /// Which setting
        #[arg(value_enum)]
        key: ConfigKey,
        /// The new value (animation: on/off; lock-timeout: minutes; keyfile: a path, or none)
        value: String,
    },
}

/// Settings you can change.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigKey {
    /// Play the intro animation of the login screen (on/off)
    Animation,
    /// Lock CakePass (screen and line mode) after this many minutes of inactivity
    LockTimeout,
    /// Where your key file is, for a vault that needs one (only the path is stored)
    Keyfile,
}

/// What `cakepass keyfile` can do.
#[derive(Subcommand, Debug, Clone)]
pub enum KeyfileAction {
    /// Make a new key file with 64 random bytes (never overwrites a file)
    Create {
        /// Where to put it, e.g. on a USB stick
        path: PathBuf,
    },
}

#[derive(Args, Debug, Clone)]
pub struct SecurityArgs {
    /// Switch to this level: standard (64 MiB), high (256 MiB) or maximum (1 GiB)
    #[arg(long, value_parser = parse_level, value_name = "LEVEL")]
    pub level: Option<SecurityLevel>,
    /// From now on, require this key file (turns the key file on, or changes it)
    #[arg(long, value_name = "PATH", conflicts_with = "no_keyfile")]
    pub new_keyfile: Option<PathBuf>,
    /// Stop requiring a key file (the master password alone opens the vault)
    #[arg(long)]
    pub no_keyfile: bool,
}

impl SecurityArgs {
    /// Whether anything should change (otherwise: only show).
    pub fn changes_something(&self) -> bool {
        self.level.is_some() || self.new_keyfile.is_some() || self.no_keyfile
    }
}

#[derive(Args, Debug, Clone)]
pub struct UpdateArgs {
    /// Only check whether there is a new version; install nothing
    #[arg(long)]
    pub check: bool,
    /// Do not ask for confirmation (for people who are sure)
    #[arg(short = 'y', long)]
    pub yes: bool,
    /// With --check: send a desktop notification when there is an update
    #[arg(long, requires = "check")]
    pub notify: bool,
    /// Folder with the source code [default: the folder CakePass was installed from]
    #[arg(long, value_name = "DIR")]
    pub source: Option<PathBuf>,
    /// Turn the daily automatic check on or off (on, off or status)
    #[arg(long, value_enum, value_name = "ON/OFF", conflicts_with_all = ["check", "yes", "notify", "source"])]
    pub auto: Option<AutoMode>,
}

#[derive(Args, Debug, Clone, Default)]
#[command(next_help_heading = "Security level (Argon2id settings)")]
pub struct KdfArgs {
    /// standard (64 MiB), high (256 MiB) or maximum (1 GiB) [default: high; setup asks]
    #[arg(long, value_parser = parse_level, value_name = "LEVEL")]
    pub level: Option<SecurityLevel>,
    /// Memory use in MiB (overrides the level)
    #[arg(long, value_name = "MiB")]
    pub kdf_memory: Option<u32>,
    /// Number of iterations (overrides the level)
    #[arg(long, value_name = "N")]
    pub kdf_iterations: Option<u32>,
    /// Number of parallel lanes (overrides the level)
    #[arg(long, value_name = "N")]
    pub kdf_parallelism: Option<u32>,
}

impl KdfArgs {
    /// Nothing given: the setup wizard asks for the level.
    pub fn default_values() -> KdfArgs {
        KdfArgs::default()
    }

    /// Whether the command line chose the Argon2 settings.
    pub fn is_explicit(&self) -> bool {
        self.level.is_some()
            || self.kdf_memory.is_some()
            || self.kdf_iterations.is_some()
            || self.kdf_parallelism.is_some()
    }
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Argon2id settings (default: unchanged)")]
pub struct KdfChangeArgs {
    /// Memory use in MiB
    #[arg(long, value_name = "MiB")]
    pub kdf_memory: Option<u32>,
    /// Number of iterations
    #[arg(long, value_name = "N")]
    pub kdf_iterations: Option<u32>,
    /// Number of parallel lanes
    #[arg(long, value_name = "N")]
    pub kdf_parallelism: Option<u32>,
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Generator")]
pub struct GenArgs {
    /// Length of the password
    #[arg(short = 'l', long, default_value_t = 24, value_name = "N")]
    pub length: usize,
    /// No uppercase letters
    #[arg(long)]
    pub no_uppercase: bool,
    /// No lowercase letters
    #[arg(long)]
    pub no_lowercase: bool,
    /// No digits
    #[arg(long)]
    pub no_digits: bool,
    /// No symbols
    #[arg(long)]
    pub no_symbols: bool,
    /// Exclude characters that look alike (0 O 1 l I |)
    #[arg(long)]
    pub no_lookalikes: bool,
    /// Make a passphrase of words (diceware, EFF word list)
    #[arg(short = 'p', long)]
    pub passphrase: bool,
    /// Number of words in the passphrase
    #[arg(short = 'w', long, default_value_t = 6, value_name = "N")]
    pub words: usize,
    /// Separator between the words
    #[arg(long, default_value = "-", value_name = "CHAR")]
    pub separator: String,
}

#[derive(Args, Debug)]
pub struct AddArgs {
    /// Name of the item, e.g. "GitHub"
    pub name: String,
    /// Type of item: login, api (API key/token) or note
    #[arg(long = "type", short = 'k', value_name = "TYPE", value_parser = parse_kind, default_value = "login")]
    pub kind: Kind,
    /// Username (for an API key: account or key ID)
    #[arg(short, long)]
    pub username: Option<String>,
    /// E-mail address that belongs to this item
    #[arg(short, long)]
    pub email: Option<String>,
    /// Web address (for an API key: the service)
    #[arg(long)]
    pub url: Option<String>,
    /// Tags, separated by commas
    #[arg(short, long, value_delimiter = ',')]
    pub tags: Option<Vec<String>>,
    /// Generate the password (instead of typing it yourself)
    #[arg(short, long)]
    pub generate: bool,
    #[command(flatten)]
    pub gen_opts: GenArgs,
}

#[derive(Args, Debug)]
pub struct GetArgs {
    /// Name of the item
    pub name: String,
    /// Show the secret and notes on screen (beware of onlookers!)
    #[arg(long)]
    pub show: bool,
    /// Copy the username instead of the secret
    #[arg(long, conflicts_with_all = ["show", "copy_email"])]
    pub copy_username: bool,
    /// Copy the e-mail address instead of the secret
    #[arg(long, conflicts_with_all = ["show", "copy_username"])]
    pub copy_email: bool,
    /// Copy nothing
    #[arg(long, conflicts_with_all = ["copy_username", "copy_email"])]
    pub no_copy: bool,
}

#[derive(Args, Debug)]
pub struct EditArgs {
    /// Name of the item
    pub name: String,
    /// New name
    #[arg(long, value_name = "NAME")]
    pub rename: Option<String>,
    /// New username
    #[arg(short, long)]
    pub username: Option<String>,
    /// New e-mail address
    #[arg(short, long)]
    pub email: Option<String>,
    /// New web address
    #[arg(long)]
    pub url: Option<String>,
    /// New tags (replaces the old ones), separated by commas
    #[arg(short, long, value_delimiter = ',')]
    pub tags: Option<Vec<String>>,
    /// Type a new password or API key (hidden prompt)
    #[arg(long, conflicts_with = "generate")]
    pub password: bool,
    /// Generate a new password
    #[arg(short, long)]
    pub generate: bool,
    /// Type new notes (for a note: the new contents)
    #[arg(long)]
    pub notes: bool,
    #[command(flatten)]
    pub gen_opts: GenArgs,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_definition_is_valid() {
        command().debug_assert();
        shell_command().debug_assert();
        let help = command().find_subcommand_mut("generate").unwrap().render_help().to_string();
        assert!(help.contains("[default: 24]") && help.contains("Usage:"));
        let help = command().find_subcommand_mut("security").unwrap().render_help().to_string();
        assert!(help.contains("--level") && help.contains("--new-keyfile") && help.contains("--no-keyfile"));
        let help = command().render_help().to_string();
        assert!(help.contains("--keyfile"), "the global key file option");
    }

    #[test]
    fn levels_and_key_files_on_the_command_line() {
        use clap::FromArgMatches;
        let parse = |args: &[&str]| {
            let m = command().try_get_matches_from(std::iter::once("cakepass").chain(args.iter().copied()));
            m.and_then(|m| Cli::from_arg_matches(&m))
        };
        let cli = parse(&["init", "--level", "Maximum"]).unwrap();
        let Some(Cmd::Init { kdf }) = cli.command else { panic!() };
        assert_eq!(kdf.level, Some(SecurityLevel::Maximum));
        assert!(kdf.is_explicit());
        assert!(!KdfArgs::default_values().is_explicit());
        assert!(parse(&["init", "--level", "ultra"]).is_err());
        // The global key file option works before and after the command.
        let cli = parse(&["list", "--keyfile", "/k"]).unwrap();
        assert_eq!(cli.keyfile.as_deref(), Some(std::path::Path::new("/k")));
        let cli = parse(&["--keyfile", "/k", "security", "--new-keyfile", "/n"]).unwrap();
        let Some(Cmd::Security(s)) = cli.command else { panic!() };
        assert!(s.changes_something() && s.new_keyfile.is_some() && cli.keyfile.is_some());
        assert!(parse(&["security", "--new-keyfile", "/n", "--no-keyfile"]).is_err(), "conflict");
        let cli = parse(&["security"]).unwrap();
        let Some(Cmd::Security(s)) = cli.command else { panic!() };
        assert!(!s.changes_something());
    }

    #[test]
    fn no_option_takes_a_password_as_a_value() {
        // Security requirement: passwords never via arguments.
        fn check(cmd: &clap::Command) {
            for arg in cmd.get_arguments() {
                let id = arg.get_id().as_str().to_lowercase();
                if id.contains("password") || id.contains("secret") {
                    assert!(
                        !arg.get_action().takes_values(),
                        "option {id} of {} accepts a value",
                        cmd.get_name()
                    );
                }
            }
            for sub in cmd.get_subcommands() {
                check(sub);
            }
        }
        check(&command());
    }
}
