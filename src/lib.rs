//! cnlman receives and decodes Click'n'Load packages and hands their links to
//! pyLoad. The binary wraps these modules in a command line meant for scripts
//! and agents: JSON on stdout, diagnostics on stderr.

pub mod crypto;
pub mod html;
pub mod package;
pub mod pyload;
pub mod server;
