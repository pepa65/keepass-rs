pub(crate) mod entry;
pub(crate) mod group;
pub(crate) mod times;
pub(crate) mod value;

use std::collections::HashMap;

pub use entry::{Entry, EntryId, EntryMut, EntryRef};
pub use group::{DuplicateEntryIdError, DuplicateGroupIdError, Group, GroupId, GroupMut, GroupRef};
pub use times::Times;
pub use value::Value;

use crate::config::DatabaseConfig;

/// A decrypted KeePass database
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Database {
	/// Encryption, compression, and KDF configuration.
	pub config: DatabaseConfig,

	/// Root group identifier.
	pub(crate) root: GroupId,

	/// All entries.
	pub(crate) entries: HashMap<EntryId, Entry>,

	/// All groups.
	pub(crate) groups: HashMap<GroupId, Group>,
}

impl Database {
	/// Create a new database with a single root group.
	#[allow(clippy::new_without_default)]
	pub fn new() -> Self {
		Self::with_data(DatabaseConfig::default(), GroupId::new())
	}

	/// Create a new database with the given configuration.
	pub fn with_config(config: DatabaseConfig) -> Self {
		Self::with_data(config, GroupId::new())
	}

	/// Create a new database with the given root group ID.
	pub fn new_with_root_id(root_id: GroupId) -> Self {
		Self::with_data(DatabaseConfig::default(), root_id)
	}

	pub(crate) fn with_data(config: DatabaseConfig, root_id: GroupId) -> Self {
		let root = Group::with_id(root_id, None);

		let mut groups = HashMap::new();
		groups.insert(root_id, root);

		Self { config, root: root_id, entries: HashMap::new(), groups }
	}

	/// Get an immutable reference to the root group of the database.
	pub fn root(&self) -> GroupRef<'_> {
		GroupRef::new(self, self.root)
	}

	/// Get a mutable reference to the root group of the database.
	pub fn root_mut(&mut self) -> GroupMut<'_> {
		GroupMut::new(self, self.root)
	}

	/// Iterate over all entries with immutable access.
	pub fn iter_all_entries(&self) -> impl Iterator<Item = EntryRef<'_>> + '_ {
		self.entries.keys().map(move |id| EntryRef::new(self, *id))
	}

	/// Get an immutable reference to the entry with the given ID, if it exists
	pub fn entry(&self, id: EntryId) -> Option<EntryRef<'_>> {
		self.entries.contains_key(&id).then(move || EntryRef::new(self, id))
	}

	/// Get a mutable reference to the entry with the given ID, if it exists
	pub fn entry_mut(&mut self, id: EntryId) -> Option<EntryMut<'_>> {
		self.entries.contains_key(&id).then(move || EntryMut::new(self, id))
	}

	/// Get an immutable reference to the group with the given ID, if it exists
	pub fn group(&self, id: GroupId) -> Option<GroupRef<'_>> {
		self.groups.contains_key(&id).then(move || GroupRef::new(self, id))
	}

	/// Get a mutable reference to the group with the given ID, if it exists
	pub fn group_mut(&mut self, id: GroupId) -> Option<GroupMut<'_>> {
		self.groups.contains_key(&id).then(move || GroupMut::new(self, id))
	}
}
