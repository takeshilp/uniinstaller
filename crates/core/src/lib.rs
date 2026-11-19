//! Uniinstaller core: no UI, shared by the CLI and the GUI.
pub mod command;
pub mod elevation;
pub mod env;
pub mod force;
pub mod inventory;
pub mod model;
pub mod native;
pub mod ops;
pub mod paths;
pub mod scan;
pub mod registry;
pub mod sandbox;
pub mod safety;
pub mod shortcuts;
pub mod trace;

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq)]
pub struct Error(pub String);

pub type Result<T> = std::result::Result<T, Error>;

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error(e.to_string())
    }
}
impl From<windows::core::Error> for Error {
    fn from(e: windows::core::Error) -> Self {
        Error(e.to_string())
    }
}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error(e.to_string())
    }
}
impl From<String> for Error {
    fn from(e: String) -> Self {
        Error(e)
    }
}
impl From<&str> for Error {
    fn from(e: &str) -> Self {
        Error(e.to_string())
    }
}

/// Milliseconds since the Unix epoch. The UI formats dates; Rust has no date code.
pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}
