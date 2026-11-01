[![Crates.io](https://img.shields.io/crates/v/kplib.svg)](https://crates.io/crates/kplib)
[![Documentation](https://docs.rs/kplib/badge.svg)](https://docs.rs/kplib/)
[![Build Status](https://github.com/pepa65/keepass-rs/actions/workflows/ci.yml/badge.svg?branch=new)](https://github.com/pepa65/keepass-rs/actions/)
[![dependency status](https://deps.rs/crate/kplib/latest/status.svg)](https://deps.rs/crate/kplib)
[![License file](https://img.shields.io/github/license/pepa65/keepass-rs)](https://github.com/pepa65/keepass-rs/blob/master/LICENSE)
# kplib v0.19.0
**KeePass database file parser for KDB, KDBX3 and KDBX4, that writes to KDBX4.1**

* This is a security-hardened and dressed-down version of the Rust keepass-rs library crate,
  made specifically for `kptui` (a highly secure TUI password manager for KeePass KDBX vaults).
* `kptui`: https://github.com/pepa65/kptui
* Published on https://crates.io as `kplib` (from the `new` branch of the repo).
* Repo: https://github.com/pepa65/keepass-rs/tree/new
* After: https://github.com/sseemayer/keepass-rs
* License: MIT

## Usage
Add the following to the `[dependencies]` section of your `Cargo.toml`:

`keepass = { package = "kplib", version = "0.18.1" }`

This allows you to use the `keepass::` prefix.
If you're happy using the `kplib::` prefix, just use:

`kplib = "0.18"`
