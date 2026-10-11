//! The unit every input path produces: one Click'n'Load package.

use serde::Serialize;

/// Where a package came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Origin {
    /// `POST /flash/addcrypted2` on the listener.
    Addcrypted2,
    /// `POST /flash/add` with plain links on the listener.
    Add,
    /// A `CNLPOP(...)` call found in page HTML.
    Cnlpop,
    /// Hidden `jk` / `crypted` form inputs found in page HTML.
    Form,
    /// `cnlman decrypt` with values given on the command line.
    Manual,
}

/// A decoded Click'n'Load package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Package {
    /// How the package was obtained.
    pub origin: Origin,
    /// Package name as sent by the page, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Archive passwords as sent by the page, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passwords: Option<String>,
    /// The page the package came from (`source` field or `Referer`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// The decrypted links.
    pub links: Vec<String>,
}

/// Turns an empty or whitespace-only string into `None`.
#[must_use]
pub fn non_empty(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}
