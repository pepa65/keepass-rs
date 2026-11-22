use thiserror::Error;

use crate::{DatabaseKey, config::DatabaseVersion, db::Database};

impl Database {
	/// Saves the database to the given destination, using the provided key for encryption.
	pub fn save(&self, destination: &mut dyn std::io::Write, key: &DatabaseKey) -> Result<(), DatabaseSaveError> {
		use crate::format::kdbx4::dump_kdbx4;

		match self.config.version {
			DatabaseVersion::KDB(_) => Err(DatabaseSaveError::UnsupportedVersion),
			DatabaseVersion::KDB2(_) => Err(DatabaseSaveError::UnsupportedVersion),
			DatabaseVersion::KDB3(_) => Err(DatabaseSaveError::UnsupportedVersion),
			DatabaseVersion::KDB4(_) => dump_kdbx4(self, key, destination),
		}
	}
}

/// Errors that can occur during saving of the database to a KDBX file
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DatabaseSaveError {
	/// I/O errors that can occur while writing the database to the destination, such as file system errors
	#[error(transparent)]
	Io(#[from] std::io::Error),

	/// Errors related to XML serialization of the database
	#[error(transparent)]
	Serialization(#[from] quick_xml::SeError),

	/// Errors related to database key operations
	#[error(transparent)]
	Key(#[from] crate::key::DatabaseKeyError),

	/// Errors related to encryption operations
	#[error(transparent)]
	Cryptography(#[from] crate::crypt::CryptographyError),

	/// Errors related to random number generation
	#[error(transparent)]
	Random(#[from] getrandom::Error),

	/// Attempted to save a database with an unsupported version (e.g., KDB, KDBX2, or KDBX3)
	#[error("Unsupported database version")]
	UnsupportedVersion,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
	use super::*;
	use crate::db::fields;

	#[test]
	fn saves_and_reopens_both_kdbx4_versions() {
		let key = DatabaseKey::new().with_password("format-test");
		for minor in [0, 1] {
			let mut db = Database::new();
			db.config.version = DatabaseVersion::KDB4(minor);
			{
				let mut root = db.root_mut();
				let mut entry = root.add_entry();
				entry.set_unprotected(fields::TITLE, "Format test");
				entry.set_protected(fields::PASSWORD, "test-secret");
				entry.set_unprotected(fields::NOTES, "ลำ น้ำ");
			}
			let mut bytes = Vec::new();
			db.save(&mut bytes, &key).unwrap();
			assert_eq!(&bytes[8..12], &[minor as u8, 0, 4, 0]);
			let reopened = Database::open(&mut bytes.as_slice(), key.clone()).unwrap();
			assert_eq!(reopened.config.version, DatabaseVersion::KDB4(minor));
			let entry = reopened.iter_all_entries().next().unwrap();
			assert_eq!(entry.get_title(), Some("Format test"));
			assert_eq!(entry.get_password(), Some("test-secret"));
			assert_eq!(entry.get(fields::NOTES), Some("ลำ น้ำ"));
		}
	}

	#[test]
	fn rejects_unknown_kdbx4_versions_before_writing() {
		let mut db = Database::new();
		db.config.version = DatabaseVersion::KDB4(2);
		let key = DatabaseKey::new().with_password("format-test");
		let mut bytes = Vec::new();
		assert!(matches!(db.save(&mut bytes, &key), Err(DatabaseSaveError::UnsupportedVersion)));
		assert!(bytes.is_empty());
	}
}
