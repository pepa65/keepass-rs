use serde::{Deserialize, Serialize};

use crate::{
	crypt::{CryptographyError, ciphers::Cipher},
	db::{EntryId, GroupId},
	format::xml_db::{
		UUID,
		custom_serde::{cs_opt_bool, cs_opt_fromstr, cs_opt_string},
		entry::{Entry, UnprotectError},
		times::Times,
	},
};

#[allow(dead_code)] // XML metadata needed for deserialization, but discarded.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Group {
	#[serde(rename = "UUID")]
	pub uuid: UUID,

	pub name: String,

	#[serde(default, with = "cs_opt_string", skip_serializing_if = "Option::is_none")]
	pub notes: Option<String>,

	#[serde(default, with = "cs_opt_string", skip_serializing_if = "Option::is_none")]
	pub tags: Option<String>,

	#[serde(default, rename = "IconID", with = "cs_opt_fromstr", skip_serializing_if = "Option::is_none")]
	pub icon_id: Option<usize>,

	#[serde(default, rename = "CustomIconUUID", skip_serializing_if = "Option::is_none")]
	pub custom_icon_uuid: Option<UUID>,

	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub times: Option<Times>,

	#[serde(default, with = "cs_opt_bool", skip_serializing_if = "Option::is_none")]
	pub is_expanded: Option<bool>,

	#[serde(default, with = "cs_opt_bool")]
	pub enable_searching: Option<bool>,

	#[serde(default, skip_serializing)]
	pub default_auto_type_sequence: Option<String>,

	#[serde(default, skip_serializing)]
	pub enable_auto_type: Option<String>,

	#[serde(default, with = "cs_opt_string", skip_serializing_if = "Option::is_none")]
	pub last_top_visible_entry: Option<UUID>,

	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub custom_data: Option<crate::format::xml_db::meta::CustomData>,

	#[serde(default, rename = "$value")]
	pub children: Vec<GroupOrEntry>,

	#[serde(default, skip_serializing_if = "Option::is_none")]
	pub previous_parent_group: Option<UUID>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum GroupOrEntry {
	Group(Group),
	Entry(Entry),
}

impl Group {
	pub(crate) fn xml_to_db_handle(self, mut target: crate::db::GroupMut<'_>, inner_decryptor: &mut dyn Cipher) -> Result<(), UnprotectError> {
		target.name = self.name;
		for child in self.children {
			match child {
				GroupOrEntry::Group(g) => {
					let new_group = target.add_group_with_id(GroupId::from_uuid(g.uuid.0))?;
					g.xml_to_db_handle(new_group, inner_decryptor)?;
				}
				GroupOrEntry::Entry(e) => {
					let new_entry = target.add_entry_with_id(EntryId::from_uuid(e.uuid.0))?;
					e.xml_to_db_handle(new_entry, inner_decryptor)?;
				}
			}
		}

		Ok(())
	}

	pub(crate) fn db_to_xml(source: crate::db::GroupRef<'_>, inner_cipher: &mut dyn Cipher) -> Result<Self, CryptographyError> {
		let mut children = Vec::new();
		for g in source.groups() {
			children.push(GroupOrEntry::Group(Group::db_to_xml(g, inner_cipher)?));
		}
		for e in source.entries() {
			children.push(GroupOrEntry::Entry(Entry::db_to_xml(e, inner_cipher)?));
		}
		Ok(Self {
			uuid: UUID(source.id().uuid()),
			name: source.name.clone(),
			notes: None,
			tags: None,
			icon_id: None,
			custom_icon_uuid: None,
			times: None,
			is_expanded: None,
			enable_searching: None,
			default_auto_type_sequence: None,
			enable_auto_type: None,
			last_top_visible_entry: None,
			custom_data: None,
			children,
			previous_parent_group: None,
		})
	}
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
	use super::*;

	#[derive(Serialize, Deserialize)]
	struct Test<T>(T);

	#[test]
	fn test_deserialize_group() {
		let xml = r#"<Group>
            <UUID>AAECAwQFBgcICQoLDA0ODw==</UUID>
            <Name>Example Group</Name>
            <Notes>This is a test group.</Notes>
            <IconID>48</IconID>
            <CustomIconUUID>oaKjpLGywcLR0tPU1dbX2A==</CustomIconUUID>
            <Times>
                <CreationTime>2023-10-05T12:34:56Z</CreationTime>
                <LastModificationTime>2023-10-06T12:34:56Z</LastModificationTime>
                <LastAccessTime>2023-10-07T12:34:56Z</LastAccessTime>
                <ExpiryTime>2023-12-31T23:59:59Z</ExpiryTime>
                <Expires>True</Expires>
                <UsageCount>42</UsageCount>
                <LocationChanged>2023-10-08T12:34:56Z</LocationChanged>
            </Times>
            <IsExpanded>True</IsExpanded>
            <DefaultAutoTypeSequence>{USERNAME}{TAB}{PASSWORD}{ENTER}</DefaultAutoTypeSequence>
            <EnableAutoType>True</EnableAutoType>
            <EnableSearching>False</EnableSearching>
            <LastTopVisibleEntry>AAECAwQFBgcICQoLDA0ODw==</LastTopVisibleEntry>
            <CustomData>
                <Item>
                    <Key>example_key</Key>
                    <Value>example_value</Value>
                </Item>
            </CustomData>
            <Group>
                <UUID>AAECAwQFBgcICQoLDA0ODw==</UUID>
                <Name>Sub Group</Name>
                <IsExpanded>False</IsExpanded>
            </Group>
            <Entry>
                <UUID>AAECAwQFBgcICQoLDA0ODw==</UUID>
            </Entry>
            <Group>
                <UUID>AAECAwQFBgcICQoLDA0ODw==</UUID>
                <Name>Another Sub Group</Name>
            </Group>
            <Entry>
                <UUID>AAECAwQFBgcICQoLDA0ODw==</UUID>
            </Entry>
        </Group>"#;

		let group: Test<Group> = quick_xml::de::from_str(xml).unwrap();
		assert_eq!(group.0.uuid.0.to_string(), "00010203-0405-0607-0809-0a0b0c0d0e0f");
		assert_eq!(group.0.name, "Example Group");
		assert_eq!(group.0.children.len(), 4);
		assert!(matches!(&group.0.children[0], GroupOrEntry::Group(_)));
		assert!(matches!(&group.0.children[1], GroupOrEntry::Entry(_)));
		assert!(matches!(&group.0.children[2], GroupOrEntry::Group(_)));
		assert!(matches!(&group.0.children[3], GroupOrEntry::Entry(_)));
	}
}
