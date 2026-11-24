//! vault-server: the sync and backup server for Secret Vault.
//!
//! It keeps each vault's encrypted file and hands it to that vault's
//! devices, speaking the same sync API (version 1) as the Cloudflare Worker
//! in the vault repo. It never has a key: merging and decryption happen on
//! the devices. See docs/how-it-works.md.

pub mod api;
pub mod backup;
pub mod files;
pub mod import;
pub mod server;
pub mod store;
pub mod tls;
pub mod util;
