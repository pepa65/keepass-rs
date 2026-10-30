//! XML (de)serialization for KeePass databases.
//!
//! This module provides types that mirror the ones in `crate::db`, but are tailored to closely fit
//! the XML structure of KeePass databases for easy `#[derive(Serialize, Deserialize)]`.
//!
//! See <https://keepass.info/help/download/KDBX_XML.xsd> for an XML schema.

pub mod custom_serde;
pub mod entry;
pub mod group;
pub mod meta;
pub mod times;
pub mod timestamp;

use serde::{Deserialize, Serialize, Serializer};

use base64::{Engine as _, engine::general_purpose as base64_engine};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{crypt::CryptographyError, db::DatabaseSaveError};
use crate::{
	crypt::ciphers::Cipher,
	db::GroupId,
	format::xml_db::{custom_serde::cs_opt_string, entry::UnprotectError, group::Group, meta::Meta, timestamp::Timestamp},
};

pub fn parse_xml(data: &[u8], inner_decryptor: &mut dyn Cipher) -> Result<crate::db::Database, ParseXmlError> {
	let kdbx: KeePassFile = quick_xml::de::from_reader(data)?;
	Ok(kdbx.xml_to_db(inner_decryptor)?)
}

/// Errors that can occur during parsing of the inner XML database of a KDBX file
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ParseXmlError {
	/// Errors related to XML deserialization or serialization.
	#[error("Error parsing XML inside KDBX: {0}")]
	Xml(#[from] quick_xml::DeError),

	/// Errors related to unprotecting entries, such as decryption failures or unsupported
	/// encryption methods.
	#[error("Error unprotecting entry: {0}")]
	Unprotect(#[from] UnprotectError),
}

pub fn to_xml(db: &crate::db::Database, inner_encryptor: &mut dyn Cipher) -> Result<Zeroizing<Vec<u8>>, DatabaseSaveError> {
	let kdbx = KeePassFile::db_to_xml(db, inner_encryptor)?;
	let xml = quick_xml::se::to_string_with_root("KeePassFile", &kdbx)?.into_bytes();
	Ok(Zeroizing::new(xml))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct KeePassFile {
	meta: Meta,
	root: Root,
}

impl KeePassFile {
	/// Convert from XML representation to database representation.
	fn xml_to_db(self, inner_decryptor: &mut dyn Cipher) -> Result<crate::db::Database, UnprotectError> {
		let mut db = crate::db::Database::new_with_root_id(GroupId::from_uuid(self.root.group.uuid.0));
		self.root.group.xml_to_db_handle(db.root_mut(), inner_decryptor)?;
		Ok(db)
	}

	/// Convert from database representation to XML representation.
	fn db_to_xml(db: &crate::db::Database, inner_cipher: &mut dyn Cipher) -> Result<Self, CryptographyError> {
		let group = Group::db_to_xml(db.root(), inner_cipher)?;
		let meta = Meta::default();
		let deleted_objects = None;
		Ok(KeePassFile { meta, root: Root { group, deleted_objects } })
	}
}

/// A UUID deserialized from a Base64 string.
#[allow(clippy::upper_case_acronyms)] // Keep the name consistent with KeePass XML schema
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct UUID(Uuid);

impl<'de> Deserialize<'de> for UUID {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let input = String::deserialize(deserializer)?;

		let v = base64_engine::STANDARD.decode(input).map_err(serde::de::Error::custom)?;

		let uuid = Uuid::from_slice(&v).map_err(serde::de::Error::custom)?;
		Ok(UUID(uuid))
	}
}

impl Serialize for UUID {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let b64 = base64_engine::STANDARD.encode(self.0.as_bytes());
		serializer.serialize_str(&b64)
	}
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Root {
	#[serde(rename = "Group")]
	pub group: Group,

	#[serde(default, rename = "DeletedObjects")]
	pub deleted_objects: Option<DeletedObjects>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeletedObjects {
	#[serde(default, rename = "DeletedObject")]
	pub objects: Vec<DeletedObject>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeletedObject {
	#[serde(rename = "UUID")]
	uuid: UUID,

	#[serde(default, rename = "DeletionTime", alias = "deletion_time", with = "cs_opt_string")]
	deletion_time: Option<Timestamp>,
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
	use super::*;
	#[derive(Serialize, Deserialize)]
	struct Test<T>(T);

	#[test]
	fn test_deserialize_uuid() {
		let uuid_str = "AAECAwQFBgcICQoLDA0ODw==";
		let uuid: UUID = quick_xml::de::from_str(uuid_str).unwrap();
		assert_eq!(uuid.0.as_bytes(), &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
	}

	#[test]
	fn test_serialize_uuid() {
		let uuid = UUID(Uuid::from_bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]));
		let serialized = quick_xml::se::to_string(&Test(uuid)).unwrap();
		assert_eq!(serialized, "<Test>AAECAwQFBgcICQoLDA0ODw==</Test>");
	}

	#[test]
	fn test_serialize_deleted_object_deletion_time() {
		let deleted_object = DeletedObject {
			uuid: UUID(Uuid::nil()),
			deletion_time: Some(Timestamp::new_iso8601(chrono::NaiveDateTime::parse_from_str("2026-08-15T12:34:56", "%Y-%m-%dT%H:%M:%S").unwrap())),
		};

		let serialized = quick_xml::se::to_string_with_root("DeletedObject", &deleted_object).unwrap();

		assert!(serialized.contains("<DeletionTime>"));
		assert!(!serialized.contains("<deletion_time>"));
	}

	#[test]
	fn test_deserialize_legacy_deleted_object_deletion_time() {
		let deleted_object: DeletedObject =
			quick_xml::de::from_str("<DeletedObject><UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID><deletion_time>2026-08-15T12:34:56Z</deletion_time></DeletedObject>")
				.unwrap();

		assert!(deleted_object.deletion_time.is_some());
	}
}

#[cfg(test)]
mod writer_compat_tests;
