//! Programmatic round-trip coverage for KDBX 4.1-specific surface.
//! Each test builds a database via the public API, saves it, reopens it,
//! and asserts the 4.1 fields survive intact.

#![forbid(unsafe_code)]
#![allow(missing_docs)]

use keepass::{
	DatabaseKey,
	config::{DatabaseConfig, KdfConfig},
	db::{Database, EntryId, Value, fields},
};

const PASSWORD: &str = "demopass";

fn fast_kdbx41_config() -> DatabaseConfig {
	let mut cfg = DatabaseConfig::default();
	cfg.kdf_config = KdfConfig::Argon2 { iterations: 1, memory: 64 * 1024, parallelism: 1, version: argon2::Version::Version13 };
	cfg
}

fn save_then_open(db: &Database) -> Database {
	let mut buf = Vec::new();
	db.save(&mut buf, DatabaseKey::new().with_password(PASSWORD)).expect("save");
	Database::open(&mut buf.as_slice(), DatabaseKey::new().with_password(PASSWORD)).expect("open")
}

/// Build a database touching every public KDBX 4.1 field we can reach.
/// Returns the database and the id of the entry carrying the rich fields,
/// for tests that want to inspect a specific entry post-roundtrip.
fn build_kdbx41_rich_database() -> (Database, EntryId) {
	let mut db = Database::with_config(fast_kdbx41_config());
	let entry_id = {
		let mut root = db.root_mut();
		root.name = "Root".to_string();
		let mut entry = root.add_entry();
		entry.set_unprotected(fields::TITLE, "feature-bag");
		entry.set_unprotected(fields::USERNAME, "alice");
		entry.set_protected(fields::PASSWORD, "hunter2");
		entry.set_unprotected(fields::URL, "https://example.com");
		entry.set_protected(fields::NOTES, "These are private notes");
		entry.id()
	};

	{
		let mut root = db.root_mut();
		let mut bin = root.add_group();
		bin.name = "Recycle Bin".to_string();
		let mut deleted = bin.add_entry();
		deleted.set_unprotected(fields::TITLE, "tombstone");
	}

	(db, entry_id)
}

#[test]
fn database_round_trips_supported_fields() {
	let (db, id) = build_kdbx41_rich_database();
	let parsed = save_then_open(&db);

	assert_eq!(parsed.config, db.config);

	let entry = parsed.entry(id).expect("entry survives");

	assert_eq!(entry.id(), id);
	assert_eq!(entry.get(fields::TITLE), Some("feature-bag"));
	assert_eq!(entry.get(fields::USERNAME), Some("alice"));
	assert_eq!(entry.get(fields::PASSWORD), Some("hunter2"));

	assert!(matches!(entry.fields.get(fields::PASSWORD), Some(Value::Protected(_))));

	assert_eq!(entry.times.last_modification, db.entry(id).unwrap().times.last_modification);
	assert_eq!(entry.get(fields::URL), Some("https://example.com"));
	assert_eq!(entry.get(fields::NOTES), Some("These are private notes"));
	assert!(matches!(entry.fields.get(fields::NOTES), Some(Value::Protected(_))));
}

#[test]
fn protected_password_round_trips_and_decrypts() {
	let (db, id) = build_kdbx41_rich_database();
	let parsed = save_then_open(&db);
	let root = parsed.root();
	let entry = root.entry(id).expect("entry survives");
	let pw = entry.fields.get(fields::PASSWORD).expect("password field present");
	assert!(matches!(pw, Value::Protected(_)));
	assert_eq!(entry.get(fields::PASSWORD), Some("hunter2"));
}
