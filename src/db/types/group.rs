use std::ops::{Deref, DerefMut};

use indexmap::IndexSet;
use thiserror::Error;
use uuid::Uuid;

use crate::{
	Database,
	db::{Entry, EntryId, EntryMut, EntryRef},
};

/// Unique identifier for a [Group]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GroupId(Uuid);

impl Default for GroupId {
	fn default() -> Self {
		Self::new()
	}
}

impl GroupId {
	/// Generate a new random `GroupId`.
	pub fn new() -> Self {
		Self(Uuid::new_v4())
	}

	/// Build a `GroupId` from an existing [Uuid].
	///
	/// Useful when a group's identifier needs to be pinned (e.g. test fixtures or migrations).
	/// Pair with [Group::add_group_with_id][GroupMut::add_group_with_id] to insert
	/// a group under a chosen identifier.
	pub const fn from_uuid(uuid: Uuid) -> Self {
		Self(uuid)
	}

	/// Get the Uuid contained inside
	pub fn uuid(&self) -> Uuid {
		self.0
	}
}

impl From<Uuid> for GroupId {
	fn from(uuid: Uuid) -> Self {
		Self::from_uuid(uuid)
	}
}

impl std::fmt::Display for GroupId {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", self.0)
	}
}

/// A database group containing child groups and entries.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Group {
	/// Unique identifier of the group.
	pub(crate) id: GroupId,

	/// Identifier of the parent group, if any.
	pub(crate) parent: Option<GroupId>,

	/// Name of the group.
	pub name: String,

	/// Child group identifiers.
	pub(crate) groups: IndexSet<GroupId>,

	/// Entry identifiers directly contained in this group.
	pub(crate) entries: IndexSet<EntryId>,
}

impl Group {
	/// Get the unique identifier for this group
	pub fn id(&self) -> GroupId {
		self.id
	}

	pub(crate) fn with_id(id: GroupId, parent: Option<GroupId>) -> Group {
		Group { id, parent, name: String::new(), groups: IndexSet::new(), entries: IndexSet::new() }
	}

	/// Get an iterator over the IDs of all contained groups
	pub fn group_ids(&self) -> impl Iterator<Item = GroupId> + '_ {
		self.groups.iter().cloned()
	}

	/// Get an iterator over the IDs of all contained entries
	pub fn entry_ids(&self) -> impl Iterator<Item = EntryId> + '_ {
		self.entries.iter().cloned()
	}
}

/// Immutable reference to a [Group]. Implements [Deref] to [&Group][Group].
#[derive(Clone)]
pub struct GroupRef<'a> {
	database: &'a crate::db::Database,
	id: GroupId,
}

impl GroupRef<'_> {
	pub(crate) fn new(database: &Database, id: GroupId) -> GroupRef<'_> {
		GroupRef { database, id }
	}

	/// Get a contained group by ID
	pub fn group(&self, id: GroupId) -> Option<GroupRef<'_>> {
		self.groups.contains(&id).then(move || GroupRef::new(self.database, id))
	}

	/// Get a contained entry by ID
	pub fn entry(&self, id: EntryId) -> Option<EntryRef<'_>> {
		self.entries.contains(&id).then(move || EntryRef::new(self.database, id))
	}

	/// Get an iterator over all contained groups
	pub fn groups(&self) -> impl Iterator<Item = GroupRef<'_>> + '_ {
		self.groups.iter().map(move |id| GroupRef::new(self.database, *id))
	}

	/// Get an iterator over all contained entries
	pub fn entries(&self) -> impl Iterator<Item = EntryRef<'_>> + '_ {
		self.entries.iter().map(move |id| EntryRef::new(self.database, *id))
	}
}

impl Deref for GroupRef<'_> {
	type Target = Group;

	#[allow(clippy::expect_used, clippy::missing_panics_doc)] // group existence is guaranteed
	fn deref(&self) -> &Self::Target {
		self.database.groups.get(&self.id).expect("GroupRef points to a non-existing group")
	}
}

/// Mutable reference to a [Group]. Implements [DerefMut] to [&mut Group][Group]
pub struct GroupMut<'a> {
	database: &'a mut crate::db::Database,
	id: GroupId,
}

impl GroupMut<'_> {
	pub(crate) fn new(database: &mut Database, id: GroupId) -> GroupMut<'_> {
		GroupMut { database, id }
	}

	/// Get a mutable reference to a contained group by ID
	pub fn group_mut(&mut self, id: GroupId) -> Option<GroupMut<'_>> {
		self.groups.contains(&id).then(move || GroupMut::new(self.database, id))
	}

	/// Get a mutable reference to a contained entry by ID
	pub fn entry_mut(&mut self, id: EntryId) -> Option<EntryMut<'_>> {
		self.entries.contains(&id).then(move || EntryMut::new(self.database, id))
	}

	/// Convenience method to edit the group in a closure.
	pub fn edit(&mut self, f: impl FnOnce(&mut GroupMut<'_>)) -> &mut Self {
		f(self);
		self
	}

	/// Adds a new subgroup to this group and returns a mutable reference to it.
	#[allow(clippy::missing_panics_doc)]
	pub fn add_group(&mut self) -> GroupMut<'_> {
		#[allow(clippy::expect_used)]
		self.add_group_with_id(GroupId::new()).expect("fresh v4 UUID cannot collide with an existing group identifier")
	}

	/// Adds a new entry to this group and returns a mutable reference to it.
	#[allow(clippy::missing_panics_doc)]
	pub fn add_entry(&mut self) -> EntryMut<'_> {
		#[allow(clippy::expect_used)]
		self.add_entry_with_id(EntryId::new()).expect("fresh v4 UUID cannot collide with an existing entry identifier")
	}
	/// Adds a new entry under a caller-supplied [EntryId] and returns a mutable reference to it.
	///
	/// Returns [DuplicateEntryIdError] if an entry with the same identifier already
	/// exists anywhere in the database.
	///
	/// # Example
	///
	/// ```
	/// use keepass::db::{Database, EntryId, fields};
	/// use uuid::uuid;
	///
	/// let mut db = Database::new();
	/// let entry_id: EntryId = uuid!("00000000-0000-0000-0000-000000000001").into();
	/// let mut root = db.root_mut();
	/// let mut entry = root.add_entry_with_id(entry_id).unwrap();
	/// entry.set_unprotected(fields::TITLE, "Example");
	/// ```
	pub fn add_entry_with_id(&mut self, id: EntryId) -> Result<EntryMut<'_>, DuplicateEntryIdError> {
		if self.database.entries.contains_key(&id) {
			return Err(DuplicateEntryIdError(id));
		}

		let new_entry = Entry::with_id(id, self.id);
		self.entries.insert(id);
		self.database.entries.insert(id, new_entry);

		Ok(EntryMut::new(self.database, id))
	}

	/// Adds a new subgroup under a caller-supplied [GroupId] and returns a mutable reference to
	/// it.
	///
	/// Returns [DuplicateGroupIdError] if a group with the same identifier already
	/// exists anywhere in the database.
	///
	/// # Example
	///
	/// ```
	/// use keepass::db::{Database, GroupId};
	/// use uuid::uuid;
	///
	/// let mut db = Database::new();
	/// let group_id: GroupId = uuid!("00000000-0000-0000-0000-000000000002").into();
	/// db.root_mut()
	///     .add_group_with_id(group_id)
	///     .unwrap()
	///     .edit(|g| g.name = "Pinned group".to_string());
	/// ```
	pub fn add_group_with_id(&mut self, id: GroupId) -> Result<GroupMut<'_>, DuplicateGroupIdError> {
		if self.database.groups.contains_key(&id) {
			return Err(DuplicateGroupIdError(id));
		}

		let new_group = Group::with_id(id, Some(self.id));
		self.groups.insert(id);
		self.database.groups.insert(id, new_group);

		Ok(GroupMut::new(self.database, id))
	}
}

/// Attempted to add a group with an ID that already exists in the database.
#[derive(Debug, Error)]
#[error("a group with ID {0} already exists in the database")]
pub struct DuplicateGroupIdError(pub GroupId);

/// Attempted to add an entry with an ID that already exists in the database.
#[derive(Debug, Error)]
#[error("an entry with ID {0} already exists in the database")]
pub struct DuplicateEntryIdError(pub EntryId);

impl Deref for GroupMut<'_> {
	type Target = Group;

	#[allow(clippy::expect_used, clippy::missing_panics_doc)] // group existence is guaranteed
	fn deref(&self) -> &Self::Target {
		self.database.groups.get(&self.id).expect("GroupMut points to a non-existing group")
	}
}

impl DerefMut for GroupMut<'_> {
	#[allow(clippy::expect_used, clippy::missing_panics_doc)] // group existence is guaranteed
	fn deref_mut(&mut self) -> &mut Self::Target {
		self.database.groups.get_mut(&self.id).expect("GroupMut points to a non-existing group")
	}
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod group_tests {
	use crate::Database;
	use crate::db::fields;

	#[test]
	fn get() {
		let mut db = Database::new();

		let general_group_id = db.root_mut().add_group().edit(|g| g.name = "General".into()).id();
		let sample_entry_id = {
			let mut group = db.group_mut(general_group_id).unwrap();
			let mut entry = group.add_entry();
			entry.set_unprotected(fields::TITLE, "Sample Entry #2");
			entry.id()
		};

		assert_eq!(db.entry(sample_entry_id).unwrap().get(fields::TITLE), Some("Sample Entry #2"));

		let root = db.root();

		assert!(root.group(general_group_id).is_some());
		assert!(db.group(general_group_id).unwrap().entry(sample_entry_id).is_some());
	}

	#[test]
	fn get_mut() {
		let mut db = Database::new();

		let general_group_id = db.root_mut().add_group().edit(|g| g.name = "General".into()).id();

		let sample_entry_id = {
			let mut group = db.group_mut(general_group_id).unwrap();
			let mut entry = group.add_entry();
			entry.set_unprotected(fields::TITLE, "Sample Entry #2");
			entry.id()
		};

		assert_eq!(db.entry_mut(sample_entry_id).unwrap().get(fields::TITLE), Some("Sample Entry #2"));

		assert!(db.root_mut().group_mut(general_group_id).is_some());

		assert!(db.group_mut(general_group_id).unwrap().entry_mut(sample_entry_id).is_some());
	}

	#[test]
	fn add_entry_with_id_uses_supplied_uuid() {
		use crate::db::EntryId;
		use uuid::uuid;

		let mut db = Database::new();
		let pinned_uuid = uuid!("00000000-0000-0000-0000-0000000000aa");
		let pinned: EntryId = pinned_uuid.into();
		let inserted_id = {
			let mut root = db.root_mut();
			let mut entry = root.add_entry_with_id(pinned).unwrap();
			entry.set_unprotected(fields::TITLE, "pinned");
			entry.id()
		};
		assert_eq!(inserted_id, pinned);
		assert_eq!(inserted_id.uuid(), pinned_uuid);
		assert_eq!(db.entry(pinned).unwrap().get(fields::TITLE), Some("pinned"),);
	}

	#[test]
	fn add_entry_with_id_duplicate_returns_error() {
		use crate::db::{DuplicateEntryIdError, EntryId};
		use uuid::uuid;

		let mut db = Database::new();
		let pinned: EntryId = uuid!("00000000-0000-0000-0000-0000000000ab").into();

		db.root_mut().add_entry_with_id(pinned).unwrap();

		assert!(matches!(
			db.root_mut().add_entry_with_id(pinned),
			Err(DuplicateEntryIdError(eid)) if eid == pinned
		));
	}

	#[test]
	fn add_group_with_id_uses_supplied_uuid() {
		use crate::db::GroupId;
		use uuid::uuid;

		let mut db = Database::new();
		let pinned_uuid = uuid!("00000000-0000-0000-0000-0000000000ba");
		let pinned: GroupId = pinned_uuid.into();

		let inserted_id = db.root_mut().add_group_with_id(pinned).unwrap().edit(|g| g.name = "pinned".into()).id();

		assert_eq!(inserted_id, pinned);
		assert_eq!(inserted_id.uuid(), pinned_uuid);
		assert_eq!(db.group(pinned).unwrap().name, "pinned");
	}

	#[test]
	fn add_group_with_id_duplicate_returns_error() {
		use crate::db::{DuplicateGroupIdError, GroupId};
		use uuid::uuid;

		let mut db = Database::new();
		let pinned: GroupId = uuid!("00000000-0000-0000-0000-0000000000bb").into();

		db.root_mut().add_group_with_id(pinned).unwrap();

		assert!(matches!(
			db.root_mut().add_group_with_id(pinned),
			Err(DuplicateGroupIdError(gid)) if gid == pinned
		));
	}

	#[test]
	fn group_id_new_generates_distinct_ids() {
		use crate::db::GroupId;

		assert_ne!(GroupId::new(), GroupId::new());
	}

	#[test]
	fn from_uuid_impls_match_constructors() {
		use crate::db::{EntryId, GroupId};
		use uuid::uuid;

		let raw = uuid!("00000000-0000-0000-0000-0000000000cc");
		let from_entry: EntryId = raw.into();
		let from_entry_ctor = EntryId::from_uuid(raw);
		assert_eq!(from_entry, from_entry_ctor);
		assert_eq!(from_entry.uuid(), raw);

		let from_group: GroupId = raw.into();
		let from_group_ctor = GroupId::from_uuid(raw);
		assert_eq!(from_group, from_group_ctor);
		assert_eq!(from_group.uuid(), raw);
	}
}
