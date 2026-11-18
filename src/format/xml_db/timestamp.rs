use base64::{Engine as _, engine::general_purpose as base64_engine};
use jiff::civil::DateTime;
use serde::{Deserialize, Serialize, Serializer};

/// In KDBX4, timestamps are stored as seconds, Base64 encoded, since 0001-01-01 00:00:00.
/// This function returns the epoch baseline used by KDBX for date serialization.
pub fn get_epoch_baseline() -> DateTime {
	jiff::civil::date(1, 1, 1).at(0, 0, 0, 0)
}

#[derive(Debug, Clone, Copy)]
pub enum TimestampMode {
	Base64,
	Iso8601,
}

#[derive(Debug)]
pub struct Timestamp {
	pub mode: TimestampMode,
	pub time: DateTime,
}

impl Timestamp {
	pub fn new_base64(time: DateTime) -> Self {
		Timestamp { mode: TimestampMode::Base64, time }
	}

	pub fn new_iso8601(time: DateTime) -> Self {
		Timestamp { mode: TimestampMode::Iso8601, time }
	}
}

impl Default for Timestamp {
	fn default() -> Self {
		Timestamp::new_base64(jiff::civil::date(1970, 1, 1).at(0, 0, 0, 0))
	}
}

impl From<Timestamp> for DateTime {
	fn from(t: Timestamp) -> Self {
		t.time
	}
}

impl From<DateTime> for Timestamp {
	fn from(t: DateTime) -> Self {
		// always use base64 for serialization since that seems to be most compatible with keepass
		Timestamp::new_base64(t)
	}
}

impl<'de> Deserialize<'de> for Timestamp {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		let t = String::deserialize(deserializer)?;

		match DateTime::strptime("%Y-%m-%dT%H:%M:%SZ", &t) {
			Ok(ndt) => Ok(Timestamp::new_iso8601(ndt)),

			// If we don't have a valid ISO 8601 string, assume we have found a Base64 encoded int.
			_ => {
				let v = base64_engine::STANDARD.decode(t).map_err(serde::de::Error::custom)?;

				let bytes: [u8; 8] = v.try_into().map_err(|_| serde::de::Error::custom("KDBX timestamp must contain exactly 8 bytes"))?;
				let seconds = i64::from_le_bytes(bytes);
				let span = jiff::Span::new()
					.try_days(seconds / 86_400)
					.map_err(serde::de::Error::custom)?
					.seconds(seconds % 86_400);
				let ndt = get_epoch_baseline().checked_add(span).map_err(serde::de::Error::custom)?;

				Ok(Timestamp::new_base64(ndt))
			}
		}
	}
}

impl Serialize for Timestamp {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		match self.mode {
			TimestampMode::Iso8601 => {
				let s = self.time.strftime("%Y-%m-%dT%H:%M:%SZ").to_string();
				serializer.serialize_str(&s)
			}
			TimestampMode::Base64 => {
				let seconds = self.time.duration_since(get_epoch_baseline()).as_secs();
				let b = seconds.to_le_bytes();
				let b64 = base64_engine::STANDARD.encode(b);
				serializer.serialize_str(&b64)
			}
		}
	}
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
	use super::*;

	#[derive(Serialize, Deserialize)]
	struct Test<T>(T);

	#[test]
	fn test_deserialize_timestamp_iso8601() {
		let ts_str = "2023-10-05T12:34:56Z";
		let ts: Timestamp = quick_xml::de::from_str(ts_str).unwrap();
		assert_eq!(ts.time, "2023-10-05T12:34:56".parse::<jiff::civil::DateTime>().unwrap());
		match ts.mode {
			TimestampMode::Iso8601 => (),
			_ => panic!("Expected Iso8601 mode"),
		}
	}

	#[test]
	fn test_deserialize_timestamp_base64() {
		let ts_str = "AQAAAAAAAAA="; // Base64 for 1 second since epoch
		let ts: Timestamp = quick_xml::de::from_str(ts_str).unwrap();
		assert_eq!(ts.time, get_epoch_baseline() + jiff::SignedDuration::from_secs(1));
		match ts.mode {
			TimestampMode::Base64 => (),
			_ => panic!("Expected Base64 mode"),
		}
	}

	#[test]
	fn test_serialize_timestamp_iso8601() {
		let ts = Timestamp { mode: TimestampMode::Iso8601, time: "2023-10-05T12:34:56".parse::<jiff::civil::DateTime>().unwrap() };
		let serialized = quick_xml::se::to_string(&Test(ts)).unwrap();
		assert_eq!(serialized, "<Test>2023-10-05T12:34:56Z</Test>");
	}

	#[test]
	fn test_serialize_timestamp_base64() {
		let ts = Timestamp { mode: TimestampMode::Base64, time: get_epoch_baseline() + jiff::SignedDuration::from_secs(1) };

		let serialized = quick_xml::se::to_string(&Test(ts)).unwrap();
		assert_eq!(serialized, "<Test>AQAAAAAAAAA=</Test>");
	}
	#[test]
	fn malformed_binary_timestamps_return_errors() {
		for bytes in [vec![], vec![0; 7], vec![0; 9], i64::MAX.to_le_bytes().to_vec(), i64::MIN.to_le_bytes().to_vec()] {
			let encoded = base64_engine::STANDARD.encode(bytes);
			assert!(quick_xml::de::from_str::<Timestamp>(&encoded).is_err());
		}
	}

	#[test]
	fn timestamps_round_trip_across_epochs() {
		for value in ["0001-01-01T00:00:00", "1969-12-31T23:59:59", "1970-01-01T00:00:00", "2024-02-29T12:34:56", "9999-12-31T23:59:59"] {
			let time: DateTime = value.parse().unwrap();
			for mode in [TimestampMode::Base64, TimestampMode::Iso8601] {
				let encoded = quick_xml::se::to_string(&Test(Timestamp { mode, time })).unwrap();
				let decoded: Test<Timestamp> = quick_xml::de::from_str(&encoded).unwrap();
				assert_eq!(decoded.0.time, time);
			}
		}
	}

}
