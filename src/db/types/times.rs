use jiff::civil::DateTime;

/// Last modification timestamp for a KeePass entry.
#[derive(Debug, Default, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub struct Times {
	/// Time of the last modification, in UTC.
	pub last_modification: Option<DateTime>,
}

impl Times {
	/// Returns the current UTC time with second precision.
	pub fn now() -> DateTime {
		let now = jiff::Timestamp::now().to_zoned(jiff::tz::TimeZone::UTC).datetime();
		now.date().at(now.hour(), now.minute(), now.second(), 0)
	}

	/// Creates a new Times instance with the last modification time set to now.
	pub fn new() -> Self {
		Self { last_modification: Some(Self::now()) }
	}
}
