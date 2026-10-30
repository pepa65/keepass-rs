use std::{
	collections::HashMap,
	ops::{Deref, DerefMut},
};

use uuid::Uuid;

use crate::{
	Database,
	db::{GroupId, Times, Value, fields},
};

/// Unique identifier for an [Entry]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EntryId(Uuid);

impl Default for EntryId {
	fn default() -> Self {
		Self::new()
	}
}

impl EntryId {
	/// Generate a new random `EntryId`.
	pub fn new() -> Self {
		Self(Uuid::new_v4())
	}

	/// Build an `EntryId` from an existing [Uuid].
	///
	/// Useful when an entry's identifier needs to be pinned (e.g. test fixtures or migrations).
	/// Pair with [Group::add_entry_with_id][crate::db::GroupMut::add_entry_with_id] to insert
	/// an entry under a chosen identifier.
	pub const fn from_uuid(uuid: Uuid) -> Self {
		Self(uuid)
	}

	/// Get the Uuid contained inside
	pub fn uuid(&self) -> Uuid {
		self.0
	}
}

impl From<Uuid> for EntryId {
	fn from(uuid: Uuid) -> Self {
		Self::from_uuid(uuid)
	}
}

/// A database entry containing key-value fields.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Entry {
	/// Unique identifier of this entry.
	pub(crate) id: EntryId,

	/// Parent group identifier.
	pub(crate) parent: GroupId,

	/// Key-value fields, including username, password, URL, and notes.
	///
	/// Common field names are available in [crate::db::fields].
	pub fields: HashMap<String, Value<String>>,

	/// Entry timestamps.
	pub times: Times,
}

impl Entry {
	pub(crate) fn with_id(id: EntryId, parent: GroupId) -> Self {
		Self { id, parent, fields: HashMap::new(), times: Times::new() }
	}

	/// Get the unique identifier for the [Entry]
	pub fn id(&self) -> EntryId {
		self.id
	}

	/// Get a field by name, taking care of unprotecting Protected values automatically
	pub fn get(&self, key: &str) -> Option<&str> {
		self.fields.get(key).map(|v| v.as_str())
	}

	/// Set a field's value by name
	pub fn set(&mut self, key: impl Into<String>, value: Value<String>) {
		self.fields.insert(key.into(), value);
	}

	/// Set a field's unprotected value by name
	pub fn set_unprotected(&mut self, key: impl Into<String>, value: impl Into<String>) {
		self.set(key, Value::unprotected(value));
	}

	/// Set a field's protected value by name
	pub fn set_protected(&mut self, key: impl Into<String>, value: impl Into<String>) {
		self.set(key, Value::protected(value));
	}

	/// Convenience method for getting the raw value of the 'otp' field
	pub fn get_raw_otp_value(&self) -> Option<&str> {
		self.get(fields::OTP)
	}

	/// Convenience method for getting the value of the 'Title' field
	pub fn get_title(&self) -> Option<&str> {
		self.get(fields::TITLE)
	}

	/// Convenience method for getting the value of the 'UserName' field
	pub fn get_username(&self) -> Option<&str> {
		self.get(fields::USERNAME)
	}

	/// Convenience method for getting the value of the 'Password' field
	pub fn get_password(&self) -> Option<&str> {
		self.get(fields::PASSWORD)
	}

	/// Convenience method for getting the value of the 'URL' field
	pub fn get_url(&self) -> Option<&str> {
		self.get(fields::URL)
	}
}

impl std::fmt::Display for EntryId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.0)
	}
}

/// An immutable reference to an [Entry]. Implements [Deref] to [&Entry][Entry].
pub struct EntryRef<'a> {
	database: &'a Database,
	id: EntryId,
}

impl EntryRef<'_> {
	pub(crate) fn new(database: &Database, id: EntryId) -> EntryRef<'_> {
		EntryRef { database, id }
	}
}

impl Deref for EntryRef<'_> {
	type Target = Entry;

	#[allow(clippy::expect_used, clippy::missing_panics_doc)] // entry existence is guaranteed
	fn deref(&self) -> &Self::Target {
		// UNWRAP safety: EntryRef can only be constructed with a valid EntryId
		self.database.entries.get(&self.id).expect("Entry not found")
	}
}

/// A mutable reference to an [Entry]. Implements [DerefMut] to [&mut Entry][Entry].
pub struct EntryMut<'a> {
	database: &'a mut Database,
	id: EntryId,
}

impl EntryMut<'_> {
	pub(crate) fn new(database: &mut Database, id: EntryId) -> EntryMut<'_> {
		EntryMut { database, id }
	}

	/// Remove this entry from the database
	#[allow(clippy::expect_used, clippy::missing_panics_doc)] // the entry and parent should always be found
	pub fn remove(self) {
		let entry = self.database.entries.remove(&self.id).expect("Entry not found");
		self.database.group_mut(entry.parent).expect("Parent group not found").entries.shift_remove(&self.id);
	}
}

impl Deref for EntryMut<'_> {
	type Target = Entry;

	#[allow(clippy::expect_used, clippy::missing_panics_doc)] // entry existence is guaranteed
	fn deref(&self) -> &Self::Target {
		// UNWRAP safety: EntryMut can only be constructed with a valid EntryId
		self.database.entries.get(&self.id).expect("Entry not found")
	}
}

impl DerefMut for EntryMut<'_> {
	#[allow(clippy::expect_used, clippy::missing_panics_doc)] // entry existence is guaranteed
	fn deref_mut(&mut self) -> &mut Self::Target {
		// UNWRAP safety: EntryMut can only be constructed with a valid EntryId
		self.database.entries.get_mut(&self.id).expect("Entry not found")
	}
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
	use super::EntryId;

	#[test]
	fn entry_id_new_generates_distinct_ids() {
		assert_ne!(EntryId::new(), EntryId::new());
	}
}
