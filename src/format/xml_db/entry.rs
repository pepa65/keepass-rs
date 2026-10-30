use base64::{Engine as _, engine::general_purpose as base64_engine};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
	crypt::{CryptographyError, ciphers::Cipher},
	format::xml_db::{
		UUID,
		custom_serde::{cs_bool, cs_opt_bool, cs_opt_string},
		meta::CustomData,
		times::Times,
	},
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Entry {
	#[serde(rename = "UUID")]
	pub uuid: UUID,

	#[serde(default, rename = "OverrideURL", with = "cs_opt_string", skip_serializing_if = "Option::is_none")]
	pub override_url: Option<String>,

	#[serde(default, with = "cs_opt_string", skip_serializing_if = "Option::is_none")]
	pub tags: Option<String>,

	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub times: Option<Times>,

	#[serde(default, rename = "String")]
	pub string_fields: Vec<StringField>,

	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub history: Option<History>,

	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub custom_data: Option<CustomData>,

	#[serde(default, with = "cs_opt_bool", skip_serializing_if = "Option::is_none")]
	pub quality_check: Option<bool>,

	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub previous_parent_group: Option<UUID>,
}

impl Entry {
	fn consume_protected_fields(&self, inner_decryptor: &mut dyn Cipher) -> Result<(), UnprotectError> {
		for field in &self.string_fields {
			if field.value.protected {
				let encoded = field.value.value.as_deref().unwrap_or_default();
				let decoded = Zeroizing::new(base64_engine::STANDARD.decode(encoded)?);
				let _decrypted = inner_decryptor.decrypt(&decoded)?;
			}
		}

		if let Some(history) = &self.history {
			for entry in &history.entries {
				entry.consume_protected_fields(inner_decryptor)?;
			}
		}

		Ok(())
	}

	pub(crate) fn xml_to_db_handle(self, mut target: crate::db::EntryMut<'_>, inner_decryptor: &mut dyn Cipher) -> Result<(), UnprotectError> {
		target.times = self.times.map(|t| t.into()).unwrap_or_default();
		for field in &self.string_fields {
			let fval = field.value.value.as_deref().unwrap_or_default();
			let value = if field.value.protected {
				let fval = Zeroizing::new(base64_engine::STANDARD.decode(fval)?);
				let decrypted = inner_decryptor.decrypt(&fval)?;
				let value = String::from_utf8_lossy(&decrypted).into_owned();
				crate::db::Value::protected(value)
			} else {
				crate::db::Value::unprotected(fval)
			};
			target.fields.insert(field.key.clone(), value);
		}
		if let Some(history) = &self.history {
			for entry in &history.entries {
				entry.consume_protected_fields(inner_decryptor)?;
			}
		}
		Ok(())
	}

	pub(crate) fn db_to_xml(db: crate::db::EntryRef<'_>, inner_encryptor: &mut dyn Cipher) -> Result<Self, CryptographyError> {
		let mut string_fields = Vec::with_capacity(db.fields.len());
		for (k, v) in &db.fields {
			let value = if v.is_protected() {
				let encrypted = inner_encryptor.encrypt(v.get().as_bytes())?;
				let encoded = base64_engine::STANDARD.encode(&encrypted);

				StringValue { protected: true, value: Some(encoded) }
			} else {
				StringValue { protected: false, value: Some(v.as_str().to_string()) }
			};

			string_fields.push(StringField { key: k.clone(), value });
		}

		Ok(Entry {
			uuid: UUID(db.id().uuid()),
			override_url: None,
			tags: None,
			times: Some((&db.times).into()),
			string_fields,
			history: None,
			custom_data: None,
			quality_check: None,
			previous_parent_group: None,
		})
	}
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum UnprotectError {
	#[error("Error base64 decoding protected value: {0}")]
	Base64(#[from] base64::DecodeError),

	#[error("Error decrypting protected value: {0}")]
	Decrypt(#[from] CryptographyError),

	#[error(transparent)]
	Io(#[from] std::io::Error),

	/// the XML database contains two entries with the same UUID
	#[error(transparent)]
	DuplicateEntryId(#[from] crate::db::DuplicateEntryIdError),

	/// the XML database contains two groups with the same UUID
	#[error(transparent)]
	DuplicateGroupId(#[from] crate::db::DuplicateGroupIdError),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct StringField {
	pub key: String,
	pub value: StringValue,
}

#[derive(Debug, Deserialize)]
pub struct StringValue {
	#[serde(default, rename = "@Protected", deserialize_with = "cs_bool::deserialize")]
	protected: bool,

	#[serde(default, rename = "$value", with = "cs_opt_string", skip_serializing_if = "Option::is_none")]
	value: Option<String>,
}

impl Serialize for StringValue {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		use serde::ser::SerializeStruct;

		if self.protected {
			let mut state = serializer.serialize_struct("StringValue", 2)?;
			state.serialize_field("@Protected", if self.protected { "True" } else { "False" })?;

			if let Some(ref val) = self.value {
				state.serialize_field("$value", val)?;
			} else {
				state.serialize_field("$value", "")?;
			}
			state.end()
		} else {
			let mut state = serializer.serialize_struct("StringValue", 1)?;

			if let Some(ref val) = self.value {
				state.serialize_field("$value", val)?;
			} else {
				state.serialize_field("$value", "")?;
			}
			state.end()
		}
	}
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct History {
	#[serde(default, rename = "Entry")]
	pub entries: Vec<Entry>,
}

#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
#[cfg(test)]
mod tests {

	use super::*;

	#[derive(Debug, Serialize, Deserialize)]
	struct Test<T>(T);

	#[test]
	fn test_deserialize_string_field() {
		let xml = r#"<String>
            <Key>Title</Key>
            <Value>Example Title</Value>
        </String>"#;

		let deserialized: Test<StringField> = quick_xml::de::from_str(xml).unwrap();
		assert_eq!(deserialized.0.key, "Title");
		assert_eq!(deserialized.0.value.value.unwrap(), "Example Title");
		assert!(!deserialized.0.value.protected);

		let xml_protected = r#"<String>
            <Key>Password</Key>
            <Value Protected="True">cGFzc3dvcmQ=</Value>
        </String>"#;

		let deserialized_protected: Test<StringField> = quick_xml::de::from_str(xml_protected).unwrap();
		assert_eq!(deserialized_protected.0.key, "Password");
		assert_eq!(deserialized_protected.0.value.value.unwrap(), "cGFzc3dvcmQ=");
		assert!(deserialized_protected.0.value.protected);
	}

	#[test]
	fn test_serialize_string_field() {
		let string_field = StringField { key: "Username".to_string(), value: StringValue { protected: false, value: Some("user123".to_string()) } };

		let serialized = quick_xml::se::to_string(&Test(string_field)).unwrap();
		assert_eq!(serialized, r#"<Test><Key>Username</Key><Value>user123</Value></Test>"#);

		let string_field_protected =
			StringField { key: "Password".to_string(), value: StringValue { protected: true, value: Some("cGFzc3dvcmQ=".to_string()) } };

		let serialized_protected = quick_xml::se::to_string(&Test(string_field_protected)).unwrap();
		assert_eq!(serialized_protected, r#"<Test><Key>Password</Key><Value Protected="True">cGFzc3dvcmQ=</Value></Test>"#);
	}

	#[test]
	fn test_deserialize_entry() {
		let xml = r#"<Entry>
            <UUID>AAECAwQFBgcICQoLDA0ODw==</UUID>
            <IconID>1</IconID>
            <ForegroundColor>#FF0000</ForegroundColor>
            <BackgroundColor>#00FF00</BackgroundColor>
            <OverrideURL>https://example.com</OverrideURL>
            <Tags>tag1;tag2</Tags>
            <Times>
                <CreationTime>2023-10-05T12:34:56Z</CreationTime>
                <LastModificationTime>2023-10-06T12:34:56Z</LastModificationTime>
                <LastAccessTime>2023-10-07T12:34:56Z</LastAccessTime>
                <ExpiryTime>2024-10-05T12:34:56Z</ExpiryTime>
                <Expires>True</Expires>
                <UsageCount>5</UsageCount>
                <LocationChanged>2023-10-08T12:34:56Z</LocationChanged>
            </Times>
            <String>
                <Key>Title</Key>
                <Value>Example Title</Value>
            </String>
            <AutoType>
                <Enabled>True</Enabled>
                <DataTransferObfuscation>0</DataTransferObfuscation>
                <DefaultSequence>{USERNAME}{TAB}{PASSWORD}{ENTER}</DefaultSequence>
            </AutoType>
        </Entry>"#;

		let deserialized: Test<Entry> = quick_xml::de::from_str(xml).unwrap();
		assert_eq!(
			deserialized.0.uuid.0.as_bytes(),
			&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]
		);
		assert_eq!(deserialized.0.override_url.unwrap(), "https://example.com");
		assert_eq!(deserialized.0.tags.unwrap(), "tag1;tag2");
		assert_eq!(deserialized.0.string_fields.len(), 1);
		assert_eq!(deserialized.0.string_fields[0].key, "Title");
		assert_eq!(deserialized.0.string_fields[0].value.value.as_ref().unwrap(), "Example Title");

		assert!(deserialized.0.history.is_none());
	}

	#[test]
	fn test_deserialize_entry_minimal() {
		let xml = r#"<Entry>
            <UUID>AAECAwQFBgcICQoLDA0ODw==</UUID>
            <IconID/>
            <ForegroundColor/>
            <BackgroundColor/>
            <OverrideURL/>
            <Tags/>
            <Times/>
            <AutoType/>
        </Entry>"#;

		let deserialized: Test<Entry> = quick_xml::de::from_str(xml).unwrap();

		println!("{:#?}", deserialized);

		assert!(deserialized.0.override_url.is_none());
		assert!(deserialized.0.tags.is_none());
		assert!(deserialized.0.string_fields.is_empty());
	}

	#[test]
	fn ignores_binary_fields() {
		let xml = r#"<Entry>
            <UUID>AAAAAAAAAAAAAAAAAAAAAA==</UUID>
            <ForegroundColor>#FF0000</ForegroundColor>
            <BackgroundColor>#00FF00</BackgroundColor>
            <Binary>
                <Key>Attachment</Key>
                <Value Ref="1"/>
            </Binary>
        </Entry>"#;

		let entry: Entry = quick_xml::de::from_str(xml).unwrap();
		assert!(entry.string_fields.is_empty());
	}
}
