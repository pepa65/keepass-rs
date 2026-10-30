use std::io::Read;

use base64::{Engine as _, engine::general_purpose as base64_engine};
use quick_xml::{XmlVersion, encoding::EncodingError, events::Event, reader::Reader};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypt::sha256_element;

pub type KeyElement = Zeroizing<Vec<u8>>;
pub type KeyElements = Vec<KeyElement>;

fn parse_xml_keyfile(xml: &[u8]) -> Result<KeyElement, ParseXmlKeyFileError> {
	let mut tag_stack = Vec::new();
	let mut key_version: Option<String> = None;
	let mut key_value: Option<Zeroizing<String>> = None;
	let mut reader = Reader::from_reader(xml);
	let mut xml_version = XmlVersion::Implicit1_0;
	loop {
		match reader.read_event()? {
			Event::Eof => break,

			Event::Decl(e) => {
				xml_version = e.xml_version()?;
			}

			Event::Start(e) => {
				tag_stack.push(e.name().as_ref().to_string());
			}

			Event::End(_) => {
				tag_stack.pop();
			}

			Event::Text(e) => {
				let s = Zeroizing::new(e.xml_content(xml_version).into_owned());

				if tag_stack == ["KeyFile", "Meta", "Version"] {
					key_version = Some(s.to_string());
					continue;
				}

				if tag_stack == ["KeyFile", "Key", "Data"] {
					key_value = Some(s);
					continue;
				}
			}

			_ => (),
		}
	}

	let key_value = key_value.ok_or(ParseXmlKeyFileError::EmptyKey)?;

	if key_version.as_deref() == Some("2.0") {
		// TODO validate hash
		let mut trimmed_key = Zeroizing::new(String::with_capacity(key_value.len()));
		for c in key_value.trim().chars() {
			if !matches!(c, ' ' | '\n' | '\t' | '\r') {
				trimmed_key.push(c);
			}
		}
		if let Ok(key) = hex::decode(trimmed_key.as_bytes()) {
			return Ok(key.into());
		}
		return Ok(key_value.as_bytes().to_vec().into());
	}

	if let Ok(key) = base64_engine::STANDARD.decode(key_value.as_bytes()) {
		Ok(key.into())
	} else {
		Ok(key_value.as_bytes().to_vec().into())
	}
}

/// Errors that can occur when parsing an XML keyfile
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ParseXmlKeyFileError {
	/// No key data element was found in the XML keyfile
	#[error("The XML keyfile is missing a key data element")]
	EmptyKey,

	/// A tag in the XML keyfile contains text that cannot be decoded as UTF-8
	#[error(transparent)]
	Encoding(#[from] EncodingError),

	/// An error occurred while reading the XML keyfile
	#[error(transparent)]
	Xml(#[from] quick_xml::Error),
}

fn parse_keyfile(buffer: &[u8]) -> Result<KeyElement, DatabaseKeyError> {
	// try to parse the buffer as XML, if successful, use that data instead of full file
	if let Ok(v) = parse_xml_keyfile(buffer) {
		return Ok(v);
	}

	// legacy binary key format
	if buffer.len() == 32 {
		return Ok(buffer.to_vec().into());
	}

	// legacy hex key format
	if buffer.len() == 64
		&& let Ok(key_bytes) = hex::decode(buffer)
	{
		return Ok(key_bytes.into());
	}
	Ok(sha256_element(&[buffer]))
}

/// A KeePass key, which might consist of a password and/or a keyfile
#[derive(Debug, Clone, Default, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct DatabaseKey {
	password: Option<Zeroizing<String>>,
	keyfile: Option<Zeroizing<Vec<u8>>>,
}

impl DatabaseKey {
	/// Modify the database key to include a password
	pub fn with_password(mut self, password: &str) -> Self {
		self.password = Some(password.to_string().into());
		self
	}

	/// Modify the database key to include a keyfile
	///
	/// The keyfile is only read as raw data but not parsed until the actual key elements are
	/// requested, so errors with keyfile parsing will only be raised at that point, not when
	/// calling this method.
	pub fn with_keyfile(mut self, keyfile: &mut dyn Read) -> Result<Self, std::io::Error> {
		let mut out: Zeroizing<Vec<u8>> = Vec::with_capacity(4096).into();
		let mut chunk = Zeroizing::new([0u8; 4096]);
		loop {
			let n = match keyfile.read(&mut *chunk) {
				Ok(0) => break,
				Ok(n) => n,
				Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
				Err(e) => return Err(e),
			};
			if out.capacity() - out.len() < n {
				let mut bigger = Zeroizing::new(Vec::with_capacity((out.len() + n).max(out.capacity() * 2)));
				bigger.extend_from_slice(&out);
				out = bigger; // old buffer is wiped on drop
			}
			out.extend_from_slice(chunk.split_at(n).0);
		}
		self.keyfile = Some(out);
		Ok(self)
	}

	/// Create a new, empty database key
	pub fn new() -> Self {
		Default::default()
	}

	pub(crate) fn get_key_elements(&self) -> Result<KeyElements, DatabaseKeyError> {
		let mut out = Vec::new();

		if let Some(p) = &self.password {
			out.push(sha256_element(&[p.as_bytes()]));
		}

		if let Some(ref f) = self.keyfile {
			out.push(parse_keyfile(f)?);
		}

		if out.is_empty() {
			return Err(DatabaseKeyError::EmptyKey);
		}

		Ok(out)
	}

	/// Returns true if the database key is not associated with any key component.
	pub fn is_empty(&self) -> bool {
		if self.password.is_some() || self.keyfile.is_some() {
			return false;
		}
		true
	}
}

/// Errors that can occur when working with database keys
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DatabaseKeyError {
	/// The database key contains no components, i.e. no password, keyfile or challenge-response key
	#[error("The key contains no components")]
	EmptyKey,

	/// The database key is incorrect
	#[error("Incorrect key")]
	IncorrectKey,

	/// An I/O error occurred while reading the keyfile
	#[error("I/O error reading keyfile: {0}")]
	Io(#[from] std::io::Error),

	/// An error occurred while parsing the XML keyfile
	#[error("XML error reading keyfile: {0}")]
	Xml(#[from] quick_xml::Error),

	/// An error occurred while parsing the non-XML keyfile
	#[error("Invalid keyfile format")]
	InvalidKeyFile,
}

#[cfg(test)]
mod key_tests {
	use super::{DatabaseKey, DatabaseKeyError};

	struct Flaky<'a> {
		data: &'a [u8],
		interrupted: bool,
	}

	impl std::io::Read for Flaky<'_> {
		fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
			if !self.interrupted {
				self.interrupted = true;
				return Err(std::io::ErrorKind::Interrupted.into());
			}
			let n = self.data.len().min(buf.len()).min(1000);
			let (head, tail) = self.data.split_at(n);
			let (dst, _) = buf.split_at_mut(n);
			dst.copy_from_slice(head);
			self.data = tail;
			Ok(n)
		}
	}

	fn first(ke: &[super::KeyElement]) -> Result<&[u8], DatabaseKeyError> {
		ke.first().map(|k| k.as_slice()).ok_or(DatabaseKeyError::EmptyKey)
	}

	#[test]
	fn test_key() -> Result<(), DatabaseKeyError> {
		let ke = DatabaseKey::new().with_password("asdf").get_key_elements()?;
		assert_eq!(ke.len(), 1);

		let ke = DatabaseKey::new().with_keyfile(&mut "bare-key-file".as_bytes())?.get_key_elements()?;
		assert_eq!(ke.len(), 1);

		let ke = DatabaseKey::new().with_keyfile(&mut "0123456789ABCDEF0123456789ABCDEF".as_bytes())?.get_key_elements()?;
		assert_eq!(ke.len(), 1);

		let ke = DatabaseKey::new().with_password("asdf").with_keyfile(&mut "bare-key-file".as_bytes())?.get_key_elements()?;
		assert_eq!(ke.len(), 2);

		let ke = DatabaseKey::new()
			.with_keyfile(&mut "<KeyFile><Key><Data>0!23456789ABCDEF0123456789ABCDEF</Data></Key></KeyFile>".as_bytes())?
			.get_key_elements()?;
		assert_eq!(ke.len(), 1);

		let ke = DatabaseKey::new()
			.with_keyfile(&mut "<KeyFile><Key><Data>NXyYiJMHg3ls+eBmjbAjWec9lcOToJiofbhNiFMTJMw=</Data></Key></KeyFile>".as_bytes())?
			.get_key_elements()?;
		assert_eq!(ke.len(), 1);

		let xml_keyfile_v2 = r###"
            <?xml version="1.0" encoding="utf-8"?>
            <KeyFile>
                <Meta>
                    <Version>2.0</Version>
                </Meta>
                <Key>
                    <Data Hash="A65F0C2D">
                        36057B1C 35037FD9 62257893 C0A22403
                        EE3F8FBB 504D9981 08B821CB 00D28F89
                    </Data>
                </Key>
            </KeyFile>
        "###;
		let ke = DatabaseKey::new().with_keyfile(&mut xml_keyfile_v2.trim().as_bytes())?.get_key_elements()?;
		assert_eq!(ke.len(), 1);

		let expected = hex::decode("36057B1C35037FD962257893C0A22403EE3F8FBB504D998108B821CB00D28F89").map_err(|_| DatabaseKeyError::InvalidKeyFile)?;
		assert_eq!(first(&ke)?, expected.as_slice());

		// other XML files will just be hashed as a "bare" keyfile
		let ke = DatabaseKey::new().with_keyfile(&mut "<Not><A><KeyFile></KeyFile></A></Not>".as_bytes())?.get_key_elements()?;
		assert_eq!(ke.len(), 1);

		assert!(DatabaseKey { password: None, keyfile: None }.get_key_elements().is_err());

		Ok(())
	}

	#[test]
	fn test_keyfile_large_and_interrupted() -> Result<(), DatabaseKeyError> {
		let data = vec![7u8; 10_000];
		let ke = DatabaseKey::new().with_keyfile(&mut Flaky { data: &data, interrupted: false })?.get_key_elements()?;

		assert_eq!(first(&ke)?, crate::crypt::calculate_sha256(&[data.as_slice()]).as_slice());

		Ok(())
	}
}
