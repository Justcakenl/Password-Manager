//! The command-line interface. This is a thin layer on top of the library;
//! the screen mode (`tui`) uses the same library.

pub mod args;
pub mod commands;
pub mod config;
pub mod logo;
pub mod prompt;
pub mod setup;
pub mod shell;
pub mod tui;
pub mod ui;
pub mod update;
