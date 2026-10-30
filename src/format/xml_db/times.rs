use serde::{Deserialize, Serialize};

use crate::format::xml_db::{
	custom_serde::{cs_opt_bool, cs_opt_fromstr, cs_opt_string},
	timestamp::Timestamp,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Times {
	#[serde(default, with = "cs_opt_string", skip_serializing_if = "Option::is_none")]
	pub creation_time: Option<Timestamp>,

	#[serde(default, with = "cs_opt_string", skip_serializing_if = "Option::is_none")]
	pub last_modification_time: Option<Timestamp>,

	#[serde(default, with = "cs_opt_string", skip_serializing_if = "Option::is_none")]
	pub last_access_time: Option<Timestamp>,

	#[serde(default)]
	pub expiry_time: Timestamp,

	#[serde(default, with = "cs_opt_bool", skip_serializing_if = "Option::is_none")]
	pub expires: Option<bool>,

	#[serde(default, with = "cs_opt_fromstr", skip_serializing_if = "Option::is_none")]
	pub usage_count: Option<usize>,

	#[serde(default, with = "cs_opt_string", skip_serializing_if = "Option::is_none")]
	pub location_changed: Option<Timestamp>,
}

impl From<Times> for crate::db::Times {
	fn from(t: Times) -> Self {
		Self { last_modification: t.last_modification_time.map(|ts| ts.time) }
	}
}

impl From<&crate::db::Times> for Times {
	fn from(t: &crate::db::Times) -> Self {
		let modified = t.last_modification.unwrap_or_else(crate::db::Times::now);
		Self {
			creation_time: Some(modified.into()),
			last_modification_time: Some(modified.into()),
			last_access_time: Some(modified.into()),
			expiry_time: chrono::DateTime::UNIX_EPOCH.naive_utc().into(),
			location_changed: Some(modified.into()),
			expires: Some(false),
			usage_count: Some(0),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_deserialize_times() {
		let xml = r#"<Times>
            <CreationTime>2023-10-05T12:34:56Z</CreationTime>
            <LastModificationTime>2023-10-06T12:34:56Z</LastModificationTime>
            <LastAccessTime>2023-10-07T12:34:56Z</LastAccessTime>
            <ExpiryTime>2023-12-31T23:59:59Z</ExpiryTime>
            <Expires>True</Expires>
            <UsageCount>42</UsageCount>
            <LocationChanged>2023-10-08T12:34:56Z</LocationChanged>
        </Times>"#;

		let times: Times = quick_xml::de::from_str(xml).unwrap();

		assert_eq!(
			times.last_modification_time.unwrap().time,
			chrono::NaiveDateTime::parse_from_str("2023-10-06T12:34:56", "%Y-%m-%dT%H:%M:%S").unwrap()
		);
	}
}
