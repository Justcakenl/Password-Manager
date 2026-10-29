//! De command-line interface. Dit is een dunne laag boven de bibliotheek;
//! een latere TUI of GUI kan dezelfde bibliotheek gebruiken.

pub mod args;
pub mod commands;
pub mod logo;
pub mod prompt;
pub mod shell;
pub mod ui;
pub mod update;
