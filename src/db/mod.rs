//! KeePass database types and operations.
pub mod fields;
mod open;
mod otp;
mod save;
mod types;

pub use open::{DatabaseFormatError, DatabaseOpenError};
pub use otp::{TOTP, TOTPAlgorithm, TOTPError};
pub use save::DatabaseSaveError;
pub use types::*;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod database_tests {
	use crate::{Database, DatabaseKey};

	#[test]
	fn test_open_invalid_version_header_size() {
		assert!(Database::parse(&[], DatabaseKey::new().with_password("testing")).is_err());
		assert!(Database::parse(&[0, 0, 0, 0, 0, 0, 0, 0], DatabaseKey::new().with_password("testing")).is_err());
		assert!(Database::parse(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], DatabaseKey::new().with_password("testing")).is_err());
	}

	#[test]
	fn test_save() {
		use crate::format::variant_dictionary::VariantDictionary;
		let mut db = Database::new();

		let mut public_custom_data = VariantDictionary::new();
		public_custom_data.set("example", 42);

		db.config.public_custom_data = Some(public_custom_data);

		db.root_mut().add_entry();
		db.root_mut().add_entry();
		db.root_mut().add_entry();

		let mut buffer = Vec::new();

		db.save(&mut buffer, DatabaseKey::new().with_password("testing")).unwrap();

		let db_loaded = Database::open(&mut buffer.as_slice(), DatabaseKey::new().with_password("testing")).unwrap();

		assert_eq!(db.config, db_loaded.config);
		assert_eq!(db.root, db_loaded.root);
		assert_eq!(db.entries, db_loaded.entries);
	}
}
