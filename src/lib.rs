#![doc = include_str!("../README.md")]
#![recursion_limit = "1024"]

mod compression;
pub mod config;
pub(crate) mod crypt;
pub mod db;
pub(crate) mod format;

mod key;

pub use self::db::Database;
pub use self::key::{DatabaseKey, DatabaseKeyError};
