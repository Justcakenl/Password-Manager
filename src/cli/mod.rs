//! The command-line interface. This is a thin layer on top of the library;
//! a later TUI or GUI can use the same library.

pub mod args;
pub mod commands;
pub mod config;
pub mod logo;
pub mod prompt;
pub mod setup;
pub mod shell;
pub mod ui;
pub mod update;
