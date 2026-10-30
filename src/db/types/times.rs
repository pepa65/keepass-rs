use chrono::NaiveDateTime;

/// Last modification timestamp for a KeePass entry.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Times {
	/// Time of the last modification, in UTC.
	pub last_modification: Option<NaiveDateTime>,
}

impl Times {
	/// Returns the current UTC time with second precision.
	pub fn now() -> NaiveDateTime {
		let timestamp = chrono::Utc::now().timestamp();
		chrono::DateTime::from_timestamp(timestamp, 0).map_or(chrono::DateTime::UNIX_EPOCH.naive_utc(), |dt| dt.naive_utc())
	}

	/// Creates a new Times instance with the last modification time set to now.
	pub fn new() -> Self {
		Self { last_modification: Some(Self::now()) }
	}
}
