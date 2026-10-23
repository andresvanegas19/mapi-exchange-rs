// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! High-level session: Connect, Logon, and search-folder helpers.

use crate::emsmdb::{
    ConnectRequest, ConnectResponse, decode_disconnect, decode_execute, encode_disconnect,
    encode_execute,
};
use crate::error::Result;
use crate::props::{PropValue, PropertyRow, SFINFO_MESSAGE_CLASS, find, tags, types};
use crate::restriction::Restriction;
use crate::rop::{
    Batch, BatchResponse, LogonResponse, PropertyName, RopRequest, RopResponse, SearchCriteria,
    folder, search_flags, table_flags,
};
use crate::transport::{Config, Transport};

const MAX_ROP_OUT: u32 = 0x0004_0000;
const LOGON_PRIVATE: u8 = 0x01;
const OPEN_HOME_LOGON: u32 = 0x0000_0004;
const OPEN_USE_PER_MDB_REPLID_MAPPING: u32 = 0x0100_0000;
const FOLDER_SEARCH: u8 = 0x02;
const SAVE_KEEP_OPEN_READ_WRITE: u8 = 0x02;

/// PS_PUBLIC_STRINGS {00020329-0000-0000-C000-000000000046}, in GUID wire order.
pub const PS_PUBLIC_STRINGS: [u8; 16] = [
    0x29, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// Additional SFInfo FAI properties. Set storage_type to the definition's storage flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SfInfoProps {
    pub template_id: i32,
    pub storage_type: u32,
    pub tag: u32,
    pub efp_flags: u32,
    /// Minutes since 1601; zero by default (no last-use timestamp supplied).
    pub last_used: u32,
    pub expiration: u32,
}

pub struct Session {
    transport: Transport,
    pub connect: ConnectResponse,
    pub logon: Option<LogonResponse>,
    store: u32,
}

#[derive(Debug, Clone)]
pub struct FolderInfo {
    pub folder_id: u64,
    pub display_name: String,
    pub criteria: Option<SearchCriteria>,
}

#[derive(Debug, Clone)]
pub struct SfInfo {
    pub message_id: u64,
    pub subject: Option<String>,
    pub template_id: Option<i32>,
    pub sf_id: Option<Vec<u8>>,
    pub definition: Option<Vec<u8>>,
}

impl Session {
    /// MAPI/HTTP Connect only.
    pub fn connect(config: Config) -> Result<Self> {
        let user_dn = config.user_dn.clone();
        let mut transport = Transport::new(config)?;
        let framed = transport.post("Connect", &ConnectRequest::new(user_dn).encode())?;
        let connect = ConnectResponse::decode(&framed.body)?;
        Ok(Self {
            transport,
            connect,
            logon: None,
            store: 0,
        })
    }

    pub fn execute(&mut self, batch: &Batch) -> Result<BatchResponse> {
        let request = encode_execute(&batch.encode()?, MAX_ROP_OUT);
        let framed = self.transport.post("Execute", &request)?;
        batch.decode_response(&decode_execute(&framed.body)?)
    }

    pub fn logon(&mut self) -> Result<&LogonResponse> {
        let mut batch = Batch::new();
        let store = batch.output();
        let index = batch.push(RopRequest::Logon {
            output: store,
            logon_flags: LOGON_PRIVATE,
            open_flags: OPEN_HOME_LOGON | OPEN_USE_PER_MDB_REPLID_MAPPING,
            essdn: self.transport.config().user_dn.clone(),
        });
        let mut response = self.execute(&batch)?;
        let RopResponse::Logon(logon) = response.take(index)? else {
            unreachable!()
        };
        self.store = response.handle(store)?;
        Ok(self.logon.insert(logon))
    }

    fn logon_info(&self) -> Result<&LogonResponse> {
        self.logon
            .as_ref()
            .ok_or_else(|| crate::Error::Config("call logon() first".into()))
    }

    pub fn special_folder(&self, index: usize) -> Result<u64> {
        Ok(self.logon_info()?.folder_ids[index])
    }

    /// Resolve or create named properties in this session's store (MS-OXCPRPT 2.2.12).
    pub fn named_prop_tags(
        &mut self,
        names: &[PropertyName],
        prop_types: &[u16],
    ) -> Result<Vec<u32>> {
        if names.len() != prop_types.len() {
            return Err(crate::Error::Config(
                "named property/type count mismatch".into(),
            ));
        }
        if names.is_empty() {
            return Ok(Vec::new());
        }
        self.logon_info()?;
        let mut batch = Batch::new();
        let store = batch.input(self.store);
        let get = batch.push(RopRequest::GetPropertyIdsFromNames {
            input: store,
            flags: 0x02,
            names: names.to_vec(),
        });
        let mut response = self.execute(&batch)?;
        let RopResponse::PropertyIds(ids) = response.take(get)? else {
            unreachable!()
        };
        named_property_tags(&ids, prop_types)
    }

    pub fn named_string_prop_tag(
        &mut self,
        guid: [u8; 16],
        name: &str,
        prop_type: u16,
    ) -> Result<u32> {
        let tags = self.named_prop_tags(
            &[PropertyName::Name {
                guid,
                name: name.into(),
            }],
            &[prop_type],
        )?;
        Ok(tags[0])
    }

    /// PidNameKeywords: a store-mapped PtypMultipleString property (MS-OXPROPS).
    pub fn keywords_tag(&mut self) -> Result<u32> {
        self.named_string_prop_tag(PS_PUBLIC_STRINGS, "Keywords", types::MULTI | types::UNICODE)
    }

    /// Search folders under Finder with their criteria.
    pub fn list_search_folders(&mut self) -> Result<Vec<FolderInfo>> {
        let finder = self.special_folder(folder::FINDER)?;
        let columns = vec![tags::PR_FOLDER_ID, tags::PR_DISPLAY_NAME_W];
        let rows = self.query_table(finder, false, columns, 500)?;
        let mut folders = Vec::new();
        for row in rows {
            let Some(folder_id) = find(&row, tags::PR_FOLDER_ID).and_then(PropValue::as_i64) else {
                continue;
            };
            let display_name = find(&row, tags::PR_DISPLAY_NAME_W)
                .and_then(PropValue::as_str)
                .unwrap_or_default()
                .to_string();
            let criteria = self.search_criteria(folder_id as u64).ok();
            folders.push(FolderInfo {
                folder_id: folder_id as u64,
                display_name,
                criteria,
            });
        }
        Ok(folders)
    }

    pub fn search_criteria(&mut self, folder_id: u64) -> Result<SearchCriteria> {
        let mut batch = Batch::new();
        let store = batch.input(self.store);
        let folder = batch.output();
        batch.push(RopRequest::OpenFolder {
            input: store,
            output: folder,
            folder_id,
            open_mode: 0,
        });
        let get = batch.push(RopRequest::GetSearchCriteria { input: folder });
        batch.push(RopRequest::Release { input: folder });
        let mut response = self.execute(&batch)?;
        match response.take(get)? {
            RopResponse::SearchCriteria(criteria) => Ok(criteria),
            _ => unreachable!(),
        }
    }

    /// Folder EntryID (MS-OXCDATA 2.2.4.1); the SFInfo definition blob stores scope as EntryIDs, not FIDs.
    /// Built locally from the logon GUIDs.
    pub fn folder_entry_id(&mut self, folder_id: u64) -> Result<Vec<u8>> {
        let logon = self.logon_info()?;
        Ok(folder_entry_id(
            &logon.mailbox_guid,
            &logon.repl_guid,
            folder_id,
        ))
    }

    /// SFInfo FAIs in Common Views, with their definition blobs.
    pub fn list_sfinfo(&mut self) -> Result<Vec<SfInfo>> {
        let common_views = self.special_folder(folder::COMMON_VIEWS)?;
        let columns = vec![tags::PR_MID, tags::PR_MESSAGE_CLASS_W, tags::PR_SUBJECT_W];
        let rows = self.query_table(common_views, true, columns, 1000)?;
        let mut items = Vec::new();
        for row in rows {
            if find(&row, tags::PR_MESSAGE_CLASS_W).and_then(PropValue::as_str)
                != Some(SFINFO_MESSAGE_CLASS)
            {
                continue;
            }
            let Some(message_id) = find(&row, tags::PR_MID).and_then(PropValue::as_i64) else {
                continue;
            };
            let props = self.message_props(
                common_views,
                message_id as u64,
                vec![
                    tags::PR_WB_SF_TEMPLATE_ID,
                    tags::PR_WB_SF_ID,
                    tags::PR_WB_SF_DEFINITION,
                ],
            )?;
            items.push(SfInfo {
                message_id: message_id as u64,
                subject: find(&row, tags::PR_SUBJECT_W)
                    .and_then(PropValue::as_str)
                    .map(str::to_string),
                template_id: find(&props, tags::PR_WB_SF_TEMPLATE_ID).and_then(PropValue::as_i32),
                sf_id: find(&props, tags::PR_WB_SF_ID)
                    .and_then(PropValue::as_bytes)
                    .map(<[u8]>::to_vec),
                definition: find(&props, tags::PR_WB_SF_DEFINITION)
                    .and_then(PropValue::as_bytes)
                    .map(<[u8]>::to_vec),
            });
        }
        Ok(items)
    }

    fn query_table(
        &mut self,
        folder_id: u64,
        associated: bool,
        columns: Vec<u32>,
        max_rows: u16,
    ) -> Result<Vec<PropertyRow>> {
        let mut batch = Batch::new();
        let store = batch.input(self.store);
        let folder = batch.output();
        batch.push(RopRequest::OpenFolder {
            input: store,
            output: folder,
            folder_id,
            open_mode: 0,
        });
        let table = batch.output();
        let flags = table_flags::USE_UNICODE
            | table_flags::NO_NOTIFICATIONS
            | if associated {
                table_flags::ASSOCIATED
            } else {
                0
            };
        let get_table = if associated {
            batch.push(RopRequest::GetContentsTable {
                input: folder,
                output: table,
                flags,
            })
        } else {
            batch.push(RopRequest::GetHierarchyTable {
                input: folder,
                output: table,
                flags,
            })
        };
        let set = batch.push(RopRequest::SetColumns {
            input: table,
            columns,
        });
        let query = batch.push(RopRequest::QueryRows {
            input: table,
            count: max_rows,
        });
        batch.push(RopRequest::Release { input: table });
        batch.push(RopRequest::Release { input: folder });
        let mut response = self.execute(&batch)?;
        response.take(get_table)?;
        response.take(set)?;
        match response.take(query)? {
            RopResponse::QueryRows { rows, .. } => Ok(rows),
            _ => unreachable!(),
        }
    }

    fn message_props(
        &mut self,
        folder_id: u64,
        message_id: u64,
        tags: Vec<u32>,
    ) -> Result<PropertyRow> {
        let mut batch = Batch::new();
        let store = batch.input(self.store);
        let message = batch.output();
        let open = batch.push(RopRequest::OpenMessage {
            input: store,
            output: message,
            folder_id,
            message_id,
            open_mode: 0,
        });
        let mut response = self.execute(&batch)?;
        response.take(open)?;
        let handle = response.handle(message)?;

        let mut batch = Batch::new();
        let message = batch.input(handle);
        let get = batch.push(RopRequest::GetPropertiesSpecific {
            input: message,
            tags,
        });
        batch.push(RopRequest::Release { input: message });
        let mut response = self.execute(&batch)?;
        match response.take(get)? {
            RopResponse::Properties(row) => Ok(row),
            _ => unreachable!(),
        }
    }

    /// Create a search folder under Finder and start the search (RopSetSearchCriteria).
    pub fn create_search_folder(
        &mut self,
        display_name: &str,
        restriction: &Restriction,
        scope: &[u64],
        recursive: bool,
    ) -> Result<u64> {
        let finder = self.special_folder(folder::FINDER)?;
        let mut batch = Batch::new();
        let store = batch.input(self.store);
        let parent = batch.output();
        batch.push(RopRequest::OpenFolder {
            input: store,
            output: parent,
            folder_id: finder,
            open_mode: 0,
        });
        let created = batch.output();
        let create = batch.push(RopRequest::CreateFolder {
            input: parent,
            output: created,
            folder_type: FOLDER_SEARCH,
            display_name: display_name.into(),
            comment: String::new(),
            open_existing: true,
        });
        let set_class = batch.push(RopRequest::SetProperties {
            input: created,
            values: vec![(
                tags::PR_CONTAINER_CLASS_W,
                PropValue::Unicode("IPF.Note".into()),
            )],
        });
        let mut flags = search_flags::RESTART_SEARCH;
        flags |= if recursive {
            search_flags::RECURSIVE_SEARCH
        } else {
            search_flags::SHALLOW_SEARCH
        };
        let set = batch.push(RopRequest::SetSearchCriteria {
            input: created,
            restriction: Some(restriction.clone()),
            folder_ids: scope.to_vec(),
            flags,
        });
        batch.push(RopRequest::Release { input: created });
        batch.push(RopRequest::Release { input: parent });
        let mut response = self.execute(&batch)?;
        let RopResponse::CreateFolder { folder_id, .. } = response.take(create)? else {
            unreachable!()
        };
        check_property_problems(response.take(set_class)?)?;
        response.take(set)?;
        Ok(folder_id)
    }

    /// Write the SFInfo FAI (MS-OXOSRCH) that lets clients re-create the folder.
    pub fn create_sfinfo(
        &mut self,
        subject: &str,
        template_id: i32,
        sf_id: &[u8],
        definition: &[u8],
    ) -> Result<u64> {
        let props = SfInfoProps {
            template_id,
            storage_type: definition_storage_type(definition)?,
            ..SfInfoProps::default()
        };
        self.create_sfinfo_with_props(subject, sf_id, definition, &props)
    }

    /// Write the complete SFInfo property set, including caller-supplied lifecycle metadata.
    pub fn create_sfinfo_with_props(
        &mut self,
        subject: &str,
        sf_id: &[u8],
        definition: &[u8],
        props: &SfInfoProps,
    ) -> Result<u64> {
        if props.storage_type != definition_storage_type(definition)? {
            return Err(crate::Error::Config(
                "SFInfo storage type does not match definition".into(),
            ));
        }
        let common_views = self.special_folder(folder::COMMON_VIEWS)?;
        let mut batch = Batch::new();
        let store = batch.input(self.store);
        let message = batch.output();
        let create = batch.push(RopRequest::CreateMessage {
            input: store,
            output: message,
            folder_id: common_views,
            associated: true,
        });
        let set = batch.push(RopRequest::SetProperties {
            input: message,
            values: sfinfo_properties(subject, sf_id, definition, props),
        });
        let save = batch.push(RopRequest::SaveChangesMessage {
            input: message,
            flags: SAVE_KEEP_OPEN_READ_WRITE,
        });
        batch.push(RopRequest::Release { input: message });
        let mut response = self.execute(&batch)?;
        response.take(create)?;
        check_property_problems(response.take(set)?)?;
        match response.take(save)? {
            RopResponse::SaveChangesMessage { message_id } => Ok(message_id),
            _ => unreachable!(),
        }
    }

    /// Hard-delete a child folder and its contents (MS-OXCROPS RopDeleteFolder).
    pub fn delete_folder(&mut self, parent_folder_id: u64, folder_id: u64) -> Result<()> {
        self.logon_info()?;
        let mut batch = Batch::new();
        let store = batch.input(self.store);
        let parent = batch.output();
        let open = batch.push(RopRequest::OpenFolder {
            input: store,
            output: parent,
            folder_id: parent_folder_id,
            open_mode: 0,
        });
        let delete = batch.push(RopRequest::DeleteFolder {
            input: parent,
            flags: 0x15, // DEL_MESSAGES | DEL_FOLDERS | DELETE_HARD_DELETE.
            folder_id,
        });
        batch.push(RopRequest::Release { input: parent });
        let mut response = self.execute(&batch)?;
        response.take(open)?;
        let RopResponse::DeleteFolder { partial_completion } = response.take(delete)? else {
            unreachable!()
        };
        check_deletion(partial_completion)
    }

    pub fn delete_search_folder(&mut self, folder_id: u64) -> Result<()> {
        let finder = self.special_folder(folder::FINDER)?;
        self.delete_folder(finder, folder_id)
    }

    /// Delete regular or associated messages by MID (MS-OXCROPS RopDeleteMessages).
    pub fn delete_messages(&mut self, folder_id: u64, message_ids: &[u64]) -> Result<()> {
        if message_ids.is_empty() {
            return Ok(());
        }
        self.logon_info()?;
        let mut batch = Batch::new();
        let store = batch.input(self.store);
        let folder = batch.output();
        let open = batch.push(RopRequest::OpenFolder {
            input: store,
            output: folder,
            folder_id,
            open_mode: 0,
        });
        let delete = batch.push(RopRequest::DeleteMessages {
            input: folder,
            message_ids: message_ids.to_vec(),
        });
        batch.push(RopRequest::Release { input: folder });
        let mut response = self.execute(&batch)?;
        response.take(open)?;
        let RopResponse::DeleteMessages { partial_completion } = response.take(delete)? else {
            unreachable!()
        };
        check_deletion(partial_completion)
    }

    pub fn delete_sfinfo(&mut self, message_id: u64) -> Result<()> {
        let common_views = self.special_folder(folder::COMMON_VIEWS)?;
        self.delete_messages(common_views, &[message_id])
    }

    pub fn disconnect(mut self) -> Result<()> {
        if self.logon.is_some() {
            let mut batch = Batch::new();
            let store = batch.input(self.store);
            batch.push(RopRequest::Release { input: store });
            let _ = self.execute(&batch);
        }
        let framed = self.transport.post("Disconnect", &encode_disconnect())?;
        decode_disconnect(&framed.body)
    }
}

fn named_property_tags(ids: &[u16], prop_types: &[u16]) -> Result<Vec<u32>> {
    if ids.len() != prop_types.len() {
        return Err(crate::Error::Malformed(
            "named property ID count mismatch".into(),
        ));
    }
    ids.iter()
        .zip(prop_types)
        .map(|(&id, &ty)| {
            if !(0x8000..=0xFFFE).contains(&id) {
                return Err(crate::Error::Malformed(format!(
                    "invalid named property ID 0x{id:04x}"
                )));
            }
            Ok((u32::from(id) << 16) | u32::from(ty))
        })
        .collect()
}

fn definition_storage_type(definition: &[u8]) -> Result<u32> {
    let bytes = definition
        .get(4..8)
        .ok_or_else(|| crate::Error::Malformed("SFInfo definition header is truncated".into()))?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn sfinfo_properties(
    subject: &str,
    sf_id: &[u8],
    definition: &[u8],
    props: &SfInfoProps,
) -> Vec<(u32, PropValue)> {
    vec![
        (
            tags::PR_MESSAGE_CLASS_W,
            PropValue::Unicode(SFINFO_MESSAGE_CLASS.into()),
        ),
        (tags::PR_SUBJECT_W, PropValue::Unicode(subject.into())),
        (tags::PR_DISPLAY_NAME_W, PropValue::Unicode(subject.into())),
        (
            tags::PR_WB_SF_TEMPLATE_ID,
            PropValue::I32(props.template_id),
        ),
        (tags::PR_WB_SF_ID, PropValue::Binary(sf_id.to_vec())),
        (
            tags::PR_WB_SF_DEFINITION,
            PropValue::Binary(definition.to_vec()),
        ),
        (
            tags::PR_WB_SF_STORAGE_TYPE,
            PropValue::I32(props.storage_type as i32),
        ),
        (tags::PR_WB_SF_TAG, PropValue::I32(props.tag as i32)),
        (
            tags::PR_WB_SF_EFP_FLAGS,
            PropValue::I32(props.efp_flags as i32),
        ),
        (
            tags::PR_WB_SF_LAST_USED,
            PropValue::I32(props.last_used as i32),
        ),
        (
            tags::PR_WB_SF_EXPIRATION,
            PropValue::I32(props.expiration as i32),
        ),
    ]
}

fn check_property_problems(response: RopResponse) -> Result<()> {
    let RopResponse::SetProperties { problems } = response else {
        unreachable!()
    };
    if let Some((_, tag, code)) = problems.first() {
        return Err(crate::Error::Malformed(format!(
            "RopSetProperties problem 0x{code:08x} ({}) on property 0x{tag:08x}",
            crate::error::error_code_name(*code)
        )));
    }
    Ok(())
}

fn check_deletion(partial_completion: bool) -> Result<()> {
    if partial_completion {
        return Err(crate::Error::Malformed(
            "deletion only partially completed".into(),
        ));
    }
    Ok(())
}

const EITLT_PRIVATE_FOLDER: u16 = 0x0001;

/// Folder EntryID for a private mailbox (MS-OXCDATA 2.2.4.1): 46 bytes.
/// `folder_id` uses the wire FID layout: ReplId (2 bytes) then GlobalCounter (6 bytes).
pub fn folder_entry_id(mailbox_guid: &[u8; 16], repl_guid: &[u8; 16], folder_id: u64) -> Vec<u8> {
    let fid = folder_id.to_le_bytes();
    let mut entry_id = Vec::with_capacity(46);
    entry_id.extend_from_slice(&[0; 4]);
    entry_id.extend_from_slice(mailbox_guid);
    entry_id.extend_from_slice(&EITLT_PRIVATE_FOLDER.to_le_bytes());
    entry_id.extend_from_slice(repl_guid);
    entry_id.extend_from_slice(&fid[2..8]);
    entry_id.extend_from_slice(&[0; 2]);
    entry_id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_property_ids_become_typed_tags() {
        assert_eq!(
            named_property_tags(&[0x8001, 0xFFFE], &[0x101F, 3]).unwrap(),
            vec![0x8001_101F, 0xFFFE_0003]
        );
        assert!(named_property_tags(&[0x8001], &[]).is_err());
        for id in [0, 0x7FFF, 0xFFFF] {
            assert!(named_property_tags(&[id], &[0x101F]).is_err());
        }
    }

    #[test]
    fn sfinfo_full_property_set_and_defaults() {
        let props = SfInfoProps {
            template_id: 7,
            storage_type: 0x48,
            ..Default::default()
        };
        let definition = [4, 0x10, 0, 0, 0x48, 0, 0, 0];
        assert_eq!(
            definition_storage_type(&definition).unwrap(),
            props.storage_type
        );
        assert!(definition_storage_type(&definition[..7]).is_err());
        let row = sfinfo_properties("Sample", &[1, 2], &definition, &props);
        assert_eq!(row.len(), 11);
        for tag in [tags::PR_SUBJECT_W, tags::PR_DISPLAY_NAME_W] {
            assert_eq!(find(&row, tag), Some(&PropValue::Unicode("Sample".into())));
        }
        assert_eq!(
            find(&row, tags::PR_MESSAGE_CLASS_W),
            Some(&PropValue::Unicode(SFINFO_MESSAGE_CLASS.into()))
        );
        assert_eq!(
            find(&row, tags::PR_WB_SF_TEMPLATE_ID),
            Some(&PropValue::I32(7))
        );
        assert_eq!(
            find(&row, tags::PR_WB_SF_STORAGE_TYPE),
            Some(&PropValue::I32(0x48))
        );
        assert_eq!(
            find(&row, tags::PR_WB_SF_ID),
            Some(&PropValue::Binary(vec![1, 2]))
        );
        assert_eq!(
            find(&row, tags::PR_WB_SF_DEFINITION),
            Some(&PropValue::Binary(definition.to_vec()))
        );
        for tag in [
            tags::PR_WB_SF_TAG,
            tags::PR_WB_SF_EFP_FLAGS,
            tags::PR_WB_SF_LAST_USED,
            tags::PR_WB_SF_EXPIRATION,
        ] {
            assert_eq!(find(&row, tag), Some(&PropValue::I32(0)));
        }
        let props = SfInfoProps {
            tag: 0xFFFF_FFFF,
            efp_flags: 2,
            last_used: 3,
            expiration: 4,
            ..props
        };
        let row = sfinfo_properties("Custom", &[], &definition, &props);
        for (tag, value) in [
            (tags::PR_WB_SF_TAG, -1),
            (tags::PR_WB_SF_EFP_FLAGS, 2),
            (tags::PR_WB_SF_LAST_USED, 3),
            (tags::PR_WB_SF_EXPIRATION, 4),
        ] {
            assert_eq!(find(&row, tag), Some(&PropValue::I32(value)));
        }
    }

    #[test]
    fn property_problems_and_partial_deletions_fail() {
        assert!(check_property_problems(RopResponse::SetProperties { problems: vec![] }).is_ok());
        let error = check_property_problems(RopResponse::SetProperties {
            problems: vec![(0, tags::PR_CONTAINER_CLASS_W, 0x8007_0005)],
        })
        .unwrap_err()
        .to_string();
        assert!(error.contains("0x3613001f"));
        assert!(check_deletion(false).is_ok());
        assert!(check_deletion(true).is_err());
    }

    #[test]
    fn private_folder_entry_id_layout() {
        let mailbox = [0x11; 16];
        let repl = [0x22; 16];
        let id = folder_entry_id(&mailbox, &repl, 0x0c01_0000_0000_0001);
        assert_eq!(id.len(), 46);
        assert_eq!(&id[..4], &[0; 4]);
        assert_eq!(&id[4..20], &mailbox);
        assert_eq!(&id[20..22], &[1, 0]);
        assert_eq!(&id[22..38], &repl);
        assert_eq!(&id[38..44], &[0, 0, 0, 0, 0x01, 0x0c]);
        assert_eq!(&id[44..], &[0, 0]);
    }
}
