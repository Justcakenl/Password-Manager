//! Command-line argumenten (clap).
//!
//! BEVEILIGING: er is bewust GEEN enkele optie die een wachtwoord als waarde
//! accepteert. Wachtwoorden worden altijd via een verborgen prompt of stdin
//! gelezen, zodat ze niet zichtbaar zijn in `ps` of de shellgeschiedenis.

use std::path::PathBuf;

use clap::{ArgAction, Args, Parser, Subcommand};

const HELP_TEMPLATE: &str = "{about-with-newline}\nGebruik: {usage}\n\n{all-args}{after-help}";

/// Maak de hulpteksten van alle (sub)opdrachten Nederlands: kopjes
/// "Argumenten"/"Opties" en "[standaard: …]" in plaats van "[default: …]".
pub fn localize(cmd: clap::Command) -> clap::Command {
    cmd.help_template(HELP_TEMPLATE)
        .mut_args(|mut a| {
            if a.get_help_heading().is_none() {
                let heading = if a.is_positional() { "Argumenten" } else { "Opties" };
                a = a.help_heading(heading);
            }
            let defaults = a.get_default_values();
            if !defaults.is_empty() && !a.is_hide_default_value_set() {
                let d: Vec<String> = defaults.iter().map(|v| v.to_string_lossy().into_owned()).collect();
                let help = a.get_help().map(ToString::to_string).unwrap_or_default();
                a = a.help(format!("{help} [standaard: {}]", d.join(","))).hide_default_value(true);
            }
            a
        })
        .mut_subcommands(localize)
}

#[derive(Parser, Debug)]
#[command(
    name = "kluis",
    version,
    about = "kluis – offline, versleutelde wachtwoordmanager voor de terminal",
    help_template = HELP_TEMPLATE,
    disable_help_flag = true,
    disable_version_flag = true,
    disable_help_subcommand = true,
    subcommand_help_heading = "Opdrachten",
    subcommand_value_name = "OPDRACHT",
    next_help_heading = "Opties",
    after_help = "Voorbeelden:\n  \
        kluis init                    nieuwe kluis maken\n  \
        kluis add GitHub              item toevoegen (vraagt alles één voor één)\n  \
        kluis get GitHub              wachtwoord naar klembord (20 s)\n  \
        kluis generate --passphrase   passphrase maken\n  \
        kluis shell                   één keer ontgrendelen, auto-vergrendeling\n\n\
        Wachtwoorden worden nooit als argument meegegeven; je typt ze in een verborgen prompt."
)]
pub struct Cli {
    /// Pad naar het kluisbestand [standaard: ~/.local/share/kluis/vault.enc]
    #[arg(long, global = true, env = "KLUIS_VAULT", hide_env_values = true, value_name = "PAD")]
    pub vault: Option<PathBuf>,

    /// Gebruik geen kleuren
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Toon deze hulp
    #[arg(short = 'h', long = "help", action = ArgAction::Help, global = true)]
    help: Option<bool>,

    /// Toon de versie
    #[arg(short = 'V', long = "version", action = ArgAction::Version)]
    version: Option<bool>,

    #[command(subcommand)]
    pub command: Cmd,
}

/// Wordt gebruikt om regels in `kluis shell` te ontleden.
#[derive(Parser, Debug)]
#[command(
    name = "kluis",
    help_template = "{all-args}",
    disable_help_flag = true,
    disable_version_flag = true,
    disable_help_subcommand = true,
    subcommand_help_heading = "Opdrachten",
    subcommand_value_name = "OPDRACHT"
)]
pub struct ShellLine {
    /// Toon hulp
    #[arg(short = 'h', long = "help", action = ArgAction::Help, global = true)]
    help: Option<bool>,

    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Maak een nieuwe, lege kluis
    Init {
        #[command(flatten)]
        kdf: KdfArgs,
    },

    /// Voeg een item toe (zonder opties vraagt kluis alle velden)
    Add(AddArgs),

    /// Toon een item en kopieer het wachtwoord naar het klembord
    #[command(alias = "show")]
    Get(GetArgs),

    /// Wijzig een item (zonder opties vraagt kluis elk veld)
    Edit(EditArgs),

    /// Verwijder een item
    #[command(alias = "remove", alias = "delete")]
    Rm {
        /// Naam van het item
        name: String,
        /// Niet om bevestiging vragen
        #[arg(short = 'y', long)]
        yes: bool,
    },

    /// Toon alle items (zonder wachtwoorden)
    #[command(alias = "ls")]
    List {
        /// Alleen items met deze tag
        #[arg(short, long)]
        tag: Option<String>,
    },

    /// Zoek in naam, gebruikersnaam, URL en tags
    #[command(alias = "find")]
    Search {
        /// Zoekterm (hoofdletters maken niet uit)
        query: String,
    },

    /// Genereer een wachtwoord of passphrase (naar het klembord)
    #[command(alias = "gen")]
    Generate {
        /// Toon het resultaat op het scherm in plaats van te kopiëren
        #[arg(long)]
        show: bool,
        #[command(flatten)]
        opts: GenArgs,
    },

    /// Wijzig het hoofdwachtwoord (en eventueel de Argon2-instellingen)
    #[command(alias = "change-password")]
    Passwd {
        #[command(flatten)]
        kdf: KdfChangeArgs,
    },

    /// Exporteer de kluis naar een nieuw, versleuteld bestand
    Export {
        /// Doelbestand (mag nog niet bestaan)
        file: PathBuf,
    },

    /// Voeg items toe uit een versleuteld exportbestand
    Import {
        /// Exportbestand gemaakt met `kluis export`
        file: PathBuf,
    },

    /// Voeg items toe uit een CSV-export van een andere manager (ONVERSLEUTELD!)
    ImportCsv {
        /// CSV-bestand (Bitwarden, KeePassXC, 1Password, Firefox, Chrome, ...)
        file: PathBuf,
    },

    /// Toon informatie over de kluis en de beveiliging (geen wachtwoord nodig)
    Info,

    /// Interactieve modus: één keer ontgrendelen, vergrendelt bij inactiviteit
    Shell {
        /// Automatisch vergrendelen na zoveel seconden zonder invoer
        #[arg(long, default_value_t = 300, value_name = "SECONDEN")]
        timeout: u64,
    },

    /// Print een shell-completionscript (bash, zsh of fish)
    Completions {
        /// bash, zsh of fish
        shell: clap_complete::Shell,
    },
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Argon2id-instellingen")]
pub struct KdfArgs {
    /// Geheugengebruik in MiB
    #[arg(long, default_value_t = 64, value_name = "MiB")]
    pub kdf_memory: u32,
    /// Aantal iteraties
    #[arg(long, default_value_t = 3, value_name = "N")]
    pub kdf_iterations: u32,
    /// Aantal parallelle lanes
    #[arg(long, default_value_t = 4, value_name = "N")]
    pub kdf_parallelism: u32,
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Argon2id-instellingen (standaard: ongewijzigd)")]
pub struct KdfChangeArgs {
    /// Geheugengebruik in MiB
    #[arg(long, value_name = "MiB")]
    pub kdf_memory: Option<u32>,
    /// Aantal iteraties
    #[arg(long, value_name = "N")]
    pub kdf_iterations: Option<u32>,
    /// Aantal parallelle lanes
    #[arg(long, value_name = "N")]
    pub kdf_parallelism: Option<u32>,
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Generator")]
pub struct GenArgs {
    /// Lengte van het wachtwoord
    #[arg(short = 'l', long, default_value_t = 24, value_name = "N")]
    pub length: usize,
    /// Geen hoofdletters
    #[arg(long)]
    pub no_uppercase: bool,
    /// Geen kleine letters
    #[arg(long)]
    pub no_lowercase: bool,
    /// Geen cijfers
    #[arg(long)]
    pub no_digits: bool,
    /// Geen leestekens
    #[arg(long)]
    pub no_symbols: bool,
    /// Sluit tekens uit die op elkaar lijken (0 O 1 l I |)
    #[arg(long)]
    pub no_lookalikes: bool,
    /// Maak een passphrase van woorden (diceware, EFF-woordenlijst)
    #[arg(short = 'p', long)]
    pub passphrase: bool,
    /// Aantal woorden in de passphrase
    #[arg(short = 'w', long, default_value_t = 6, value_name = "N")]
    pub words: usize,
    /// Scheidingsteken tussen de woorden
    #[arg(long, default_value = "-", value_name = "TEKEN")]
    pub separator: String,
}

#[derive(Args, Debug)]
pub struct AddArgs {
    /// Naam van het item, bijv. "GitHub"
    pub name: String,
    /// Gebruikersnaam of e-mailadres
    #[arg(short, long)]
    pub username: Option<String>,
    /// Webadres
    #[arg(long)]
    pub url: Option<String>,
    /// Tags, gescheiden door komma's
    #[arg(short, long, value_delimiter = ',')]
    pub tags: Option<Vec<String>>,
    /// Genereer het wachtwoord (in plaats van het zelf in te typen)
    #[arg(short, long)]
    pub generate: bool,
    #[command(flatten)]
    pub gen_opts: GenArgs,
}

#[derive(Args, Debug)]
pub struct GetArgs {
    /// Naam van het item
    pub name: String,
    /// Toon wachtwoord en notities op het scherm (let op meekijkers!)
    #[arg(long)]
    pub show: bool,
    /// Kopieer de gebruikersnaam in plaats van het wachtwoord
    #[arg(long, conflicts_with = "show")]
    pub copy_username: bool,
    /// Kopieer niets
    #[arg(long, conflicts_with = "copy_username")]
    pub no_copy: bool,
}

#[derive(Args, Debug)]
pub struct EditArgs {
    /// Naam van het item
    pub name: String,
    /// Nieuwe naam
    #[arg(long, value_name = "NAAM")]
    pub rename: Option<String>,
    /// Nieuwe gebruikersnaam
    #[arg(short, long)]
    pub username: Option<String>,
    /// Nieuw webadres
    #[arg(long)]
    pub url: Option<String>,
    /// Nieuwe tags (vervangt de oude), gescheiden door komma's
    #[arg(short, long, value_delimiter = ',')]
    pub tags: Option<Vec<String>>,
    /// Typ een nieuw wachtwoord in (verborgen prompt)
    #[arg(long, conflicts_with = "generate")]
    pub password: bool,
    /// Genereer een nieuw wachtwoord
    #[arg(short, long)]
    pub generate: bool,
    /// Typ nieuwe notities in
    #[arg(long)]
    pub notes: bool,
    #[command(flatten)]
    pub gen_opts: GenArgs,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definitie_is_geldig() {
        Cli::command().debug_assert();
        ShellLine::command().debug_assert();
        localize(Cli::command()).debug_assert();
        let help =
            localize(Cli::command()).find_subcommand_mut("generate").unwrap().render_help().to_string();
        assert!(help.contains("[standaard: 24]") && help.contains("Gebruik:") && !help.contains("[default"));
    }

    #[test]
    fn geen_enkele_optie_neemt_een_wachtwoord_als_waarde() {
        // Beveiligingseis: wachtwoorden nooit via argumenten.
        fn check(cmd: &clap::Command) {
            for arg in cmd.get_arguments() {
                let id = arg.get_id().as_str().to_lowercase();
                if id.contains("password") || id.contains("wachtwoord") || id.contains("secret") {
                    assert!(
                        !arg.get_action().takes_values(),
                        "optie {id} van {} accepteert een waarde",
                        cmd.get_name()
                    );
                }
            }
            for sub in cmd.get_subcommands() {
                check(sub);
            }
        }
        check(&Cli::command());
    }
}
