//! tests for round-tripping of generated databases
#![forbid(unsafe_code)]
#![allow(clippy::indexing_slicing, clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{Combo, baseline_combo, round_trip_combos};
use keepass::{Database, db::Value};

#[test]
fn matrix_round_trip_minimal_database() {
	for combo in &round_trip_combos() {
		let db = combo.minimal_database();
		let bytes = common::save_to_vec(&db, combo.get_key());
		assert!(bytes.len() > 32, "combo {} produced suspiciously small output ({} bytes)", combo.label, bytes.len());
		assert_eq!(&bytes[..4], &[0x03, 0xd9, 0xa2, 0x9a], "combo {} missing kdbx magic", combo.label);
		let parsed = Database::open(&mut bytes.as_slice(), combo.get_key()).unwrap_or_else(|e| panic!("combo {} reopen failed: {:?}", combo.label, e));
		assert_eq!(parsed, db, "combo {} round-trip mismatch", combo.label);
	}
}

#[test]
fn matrix_round_trip_rich_database_subset() {
	let combos = round_trip_combos();
	let subset: Vec<&Combo> = combos
		.iter()
		.filter(|c| {
			c.label.contains("aes256+gz+inner-chacha20+argon2d")
				|| c.label.contains("chacha20+gz+inner-chacha20+argon2id")
				|| c.label.contains("aes256+none+inner-salsa20+aeskdf")
		})
		.collect();
	for combo in &subset {
		let db = combo.rich_database();
		let bytes = common::save_to_vec(&db, combo.get_key());
		let parsed = Database::open(&mut bytes.as_slice(), combo.get_key()).unwrap_or_else(|e| panic!("combo {} reopen failed: {:?}", combo.label, e));

		assert_eq!(parsed.root().entries().count(), 10, "{} root entry count", combo.label);
		assert_eq!(parsed.root().groups().count(), 0, "{} root group count", combo.label);
	}
}

#[test]
fn second_save_is_self_consistent() {
	let combo = baseline_combo();
	let db = combo.rich_database();
	let bytes_a = common::save_to_vec(&db, combo.get_key());
	let parsed_a = Database::open(&mut bytes_a.as_slice(), combo.get_key()).unwrap();

	let bytes_b = common::save_to_vec(&parsed_a, combo.get_key());
	let parsed_b = Database::open(&mut bytes_b.as_slice(), combo.get_key()).unwrap();

	assert_eq!(parsed_a, parsed_b);
}

#[test]
fn protected_field_decrypts_after_round_trip() {
	let combo = baseline_combo();
	let db = combo.rich_database();
	let bytes = common::save_to_vec(&db, combo.get_key());
	let parsed = Database::open(&mut bytes.as_slice(), combo.get_key()).unwrap();

	let root = parsed.root();
	let entry = root.entries().find(|e| e.get_title().is_some_and(|t| t.starts_with("entry-"))).expect("at least one entry-NN");
	let pw = entry.get("Password").expect("password is decryptable");
	assert!(pw.starts_with("pw-"));

	let mut found = false;
	for e in parsed.root().entries() {
		for (k, v) in &e.fields {
			if k.starts_with("custom.protected.")
				&& let Value::Protected(_) = v
			{
				found = true;
				break;
			}
		}
	}
	assert!(found, "no Protected custom field round-tripped");
}
