// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! ROP request/response encoding (MS-OXCROPS) and RPC_HEADER_EXT framing (MS-OXCRPC 2.2.2.1).

use crate::codec::{Reader, Writer};
use crate::error::{Error, Result, error_code_name, malformed};
use crate::props::{PropValue, PropertyRow, read_property_row, write_tagged};
use crate::restriction::Restriction;

pub const HANDLE_UNUSED: u32 = 0xFFFF_FFFF;
pub const EC_WRONG_SERVER: u32 = 0x0000_0478;

pub mod folder {
    pub const ROOT: usize = 0;
    pub const DEFERRED_ACTION: usize = 1;
    pub const SPOOLER_QUEUE: usize = 2;
    pub const IPM_SUBTREE: usize = 3;
    pub const INBOX: usize = 4;
    pub const OUTBOX: usize = 5;
    pub const SENT_ITEMS: usize = 6;
    pub const DELETED_ITEMS: usize = 7;
    pub const COMMON_VIEWS: usize = 8;
    pub const SCHEDULE: usize = 9;
    pub const FINDER: usize = 10;
    pub const VIEWS: usize = 11;
    pub const SHORTCUTS: usize = 12;
}

pub mod search_flags {
    pub const STOP_SEARCH: u32 = 0x0000_0001;
    pub const RESTART_SEARCH: u32 = 0x0000_0002;
    pub const RECURSIVE_SEARCH: u32 = 0x0000_0004;
    pub const SHALLOW_SEARCH: u32 = 0x0000_0008;
    pub const CONTENT_INDEXED_SEARCH: u32 = 0x0001_0000;
    pub const NON_CONTENT_INDEXED_SEARCH: u32 = 0x0002_0000;
    pub const STATIC_SEARCH: u32 = 0x0004_0000;
}

pub mod table_flags {
    pub const ASSOCIATED: u8 = 0x02;
    pub const DEPTH: u8 = 0x04;
    pub const DEFERRED_ERRORS: u8 = 0x08;
    pub const NO_NOTIFICATIONS: u8 = 0x10;
    pub const SOFT_DELETES: u8 = 0x20;
    pub const USE_UNICODE: u8 = 0x40;
}

/// Index into the per-request server object handle table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot(pub u8);

/// Named property identifiers (MS-OXCDATA 2.6.1); GUIDs use wire byte order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyName {
    Id { guid: [u8; 16], lid: u32 },
    Name { guid: [u8; 16], name: String },
}

impl PropertyName {
    fn write(&self, w: &mut Writer) -> Result<()> {
        match self {
            Self::Id { guid, lid } => {
                w.u8(0).bytes(guid).u32(*lid);
            }
            Self::Name { guid, name } => {
                if name.contains('\0') {
                    return Err(Error::Config("named property contains a NUL".into()));
                }
                let size = u8::try_from((name.encode_utf16().count() + 1) * 2)
                    .map_err(|_| Error::Unsupported("named property exceeds 255 bytes".into()))?;
                w.u8(1).bytes(guid).u8(size).utf16z(name);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum RopRequest {
    Logon {
        output: Slot,
        logon_flags: u8,
        open_flags: u32,
        essdn: String,
    },
    Release {
        input: Slot,
    },
    OpenFolder {
        input: Slot,
        output: Slot,
        folder_id: u64,
        open_mode: u8,
    },
    OpenMessage {
        input: Slot,
        output: Slot,
        folder_id: u64,
        message_id: u64,
        open_mode: u8,
    },
    GetHierarchyTable {
        input: Slot,
        output: Slot,
        flags: u8,
    },
    GetContentsTable {
        input: Slot,
        output: Slot,
        flags: u8,
    },
    SetColumns {
        input: Slot,
        columns: Vec<u32>,
    },
    QueryRows {
        input: Slot,
        count: u16,
    },
    GetPropertiesSpecific {
        input: Slot,
        tags: Vec<u32>,
    },
    GetPropertyIdsFromNames {
        input: Slot,
        flags: u8,
        names: Vec<PropertyName>,
    },
    DeleteFolder {
        input: Slot,
        flags: u8,
        folder_id: u64,
    },
    DeleteMessages {
        input: Slot,
        message_ids: Vec<u64>,
    },
    CreateFolder {
        input: Slot,
        output: Slot,
        folder_type: u8,
        display_name: String,
        comment: String,
        open_existing: bool,
    },
    SetSearchCriteria {
        input: Slot,
        restriction: Option<Restriction>,
        folder_ids: Vec<u64>,
        flags: u32,
    },
    GetSearchCriteria {
        input: Slot,
    },
    CreateMessage {
        input: Slot,
        output: Slot,
        folder_id: u64,
        associated: bool,
    },
    SetProperties {
        input: Slot,
        values: Vec<(u32, PropValue)>,
    },
    SaveChangesMessage {
        input: Slot,
        flags: u8,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct LogonResponse {
    pub logon_flags: u8,
    pub folder_ids: [u64; 13],
    pub response_flags: u8,
    pub mailbox_guid: [u8; 16],
    pub repl_id: u16,
    pub repl_guid: [u8; 16],
}

#[derive(Debug, Clone, PartialEq)]
pub struct SearchCriteria {
    pub restriction: Option<Restriction>,
    /// Raw bytes kept for diagnostics.
    pub restriction_bytes: Vec<u8>,
    pub folder_ids: Vec<u64>,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RopResponse {
    Logon(LogonResponse),
    OpenFolder {
        has_rules: bool,
        is_ghosted: bool,
    },
    OpenMessage,
    Table {
        row_count: u32,
    },
    SetColumns,
    QueryRows {
        origin: u8,
        rows: Vec<PropertyRow>,
    },
    Properties(PropertyRow),
    PropertyIds(Vec<u16>),
    DeleteFolder {
        partial_completion: bool,
    },
    DeleteMessages {
        partial_completion: bool,
    },
    CreateFolder {
        folder_id: u64,
        existed: bool,
    },
    SetSearchCriteria,
    SearchCriteria(SearchCriteria),
    CreateMessage {
        message_id: Option<u64>,
    },
    SetProperties {
        problems: Vec<(u16, u32, u32)>,
    },
    SaveChangesMessage {
        message_id: u64,
    },
    /// ROP-level failure; the batch continues with the next response.
    Failed {
        rop: &'static str,
        code: u32,
    },
    Redirect {
        server: String,
    },
}

impl RopResponse {
    pub fn ok(self) -> Result<Self> {
        match self {
            Self::Failed { rop, code } => Err(Error::Rop {
                rop,
                code,
                name: error_code_name(code),
            }),
            Self::Redirect { server } => Err(Error::Unsupported(format!(
                "ecWrongServer: mailbox lives on {server}"
            ))),
            other => Ok(other),
        }
    }
}

const LOGON_ID: u8 = 0;

impl RopRequest {
    fn name(&self) -> &'static str {
        match self {
            Self::Logon { .. } => "RopLogon",
            Self::Release { .. } => "RopRelease",
            Self::OpenFolder { .. } => "RopOpenFolder",
            Self::OpenMessage { .. } => "RopOpenMessage",
            Self::GetHierarchyTable { .. } => "RopGetHierarchyTable",
            Self::GetContentsTable { .. } => "RopGetContentsTable",
            Self::SetColumns { .. } => "RopSetColumns",
            Self::QueryRows { .. } => "RopQueryRows",
            Self::GetPropertiesSpecific { .. } => "RopGetPropertiesSpecific",
            Self::GetPropertyIdsFromNames { .. } => "RopGetPropertyIdsFromNames",
            Self::DeleteFolder { .. } => "RopDeleteFolder",
            Self::DeleteMessages { .. } => "RopDeleteMessages",
            Self::CreateFolder { .. } => "RopCreateFolder",
            Self::SetSearchCriteria { .. } => "RopSetSearchCriteria",
            Self::GetSearchCriteria { .. } => "RopGetSearchCriteria",
            Self::CreateMessage { .. } => "RopCreateMessage",
            Self::SetProperties { .. } => "RopSetProperties",
            Self::SaveChangesMessage { .. } => "RopSaveChangesMessage",
        }
    }

    pub fn write(&self, w: &mut Writer) -> Result<()> {
        match self {
            Self::Logon {
                output,
                logon_flags,
                open_flags,
                essdn,
            } => {
                w.u8(0xFE)
                    .u8(LOGON_ID)
                    .u8(output.0)
                    .u8(*logon_flags)
                    .u32(*open_flags)
                    .u32(0);
                if essdn.is_empty() {
                    w.u16(0);
                } else {
                    w.u16((essdn.len() + 1) as u16).asciiz(essdn);
                }
            }
            Self::Release { input } => {
                w.u8(0x01).u8(LOGON_ID).u8(input.0);
            }
            Self::OpenFolder {
                input,
                output,
                folder_id,
                open_mode,
            } => {
                w.u8(0x02)
                    .u8(LOGON_ID)
                    .u8(input.0)
                    .u8(output.0)
                    .u64(*folder_id)
                    .u8(*open_mode);
            }
            Self::OpenMessage {
                input,
                output,
                folder_id,
                message_id,
                open_mode,
            } => {
                w.u8(0x03).u8(LOGON_ID).u8(input.0).u8(output.0);
                w.u16(0x0FFF)
                    .u64(*folder_id)
                    .u8(*open_mode)
                    .u64(*message_id);
            }
            Self::GetHierarchyTable {
                input,
                output,
                flags,
            } => {
                w.u8(0x04).u8(LOGON_ID).u8(input.0).u8(output.0).u8(*flags);
            }
            Self::GetContentsTable {
                input,
                output,
                flags,
            } => {
                w.u8(0x05).u8(LOGON_ID).u8(input.0).u8(output.0).u8(*flags);
            }
            Self::SetColumns { input, columns } => {
                w.u8(0x12)
                    .u8(LOGON_ID)
                    .u8(input.0)
                    .u8(0)
                    .u16(columns.len() as u16);
                columns.iter().for_each(|tag| {
                    w.u32(*tag);
                });
            }
            Self::QueryRows { input, count } => {
                // QueryRowsFlags = Advance, ForwardRead = TRUE.
                w.u8(0x15).u8(LOGON_ID).u8(input.0).u8(0).u8(1).u16(*count);
            }
            Self::GetPropertiesSpecific { input, tags } => {
                // PropertySizeLimit 0 = server default, WantUnicode = TRUE.
                w.u8(0x07)
                    .u8(LOGON_ID)
                    .u8(input.0)
                    .u16(0)
                    .u16(1)
                    .u16(tags.len() as u16);
                tags.iter().for_each(|tag| {
                    w.u32(*tag);
                });
            }
            // MS-OXCROPS 2.2.8.1: map named properties in the input store.
            Self::GetPropertyIdsFromNames {
                input,
                flags,
                names,
            } => {
                let count = u16::try_from(names.len())
                    .map_err(|_| Error::Unsupported("too many named properties".into()))?;
                w.u8(0x56).u8(LOGON_ID).u8(input.0).u8(*flags).u16(count);
                for name in names {
                    name.write(w)?;
                }
            }
            // MS-OXCROPS RopDeleteFolder: input is the parent folder.
            Self::DeleteFolder {
                input,
                flags,
                folder_id,
            } => {
                w.u8(0x1D)
                    .u8(LOGON_ID)
                    .u8(input.0)
                    .u8(*flags)
                    .u64(*folder_id);
            }
            // MS-OXCROPS RopDeleteMessages: synchronous, without non-read notifications.
            Self::DeleteMessages { input, message_ids } => {
                let count = u16::try_from(message_ids.len())
                    .map_err(|_| Error::Unsupported("too many message IDs".into()))?;
                w.u8(0x1E).u8(LOGON_ID).u8(input.0).u8(0).u8(0).u16(count);
                for id in message_ids {
                    w.u64(*id);
                }
            }
            Self::CreateFolder {
                input,
                output,
                folder_type,
                display_name,
                comment,
                open_existing,
            } => {
                w.u8(0x1C).u8(LOGON_ID).u8(input.0).u8(output.0);
                w.u8(*folder_type).u8(1).u8(u8::from(*open_existing)).u8(0);
                w.utf16z(display_name).utf16z(comment);
            }
            Self::SetSearchCriteria {
                input,
                restriction,
                folder_ids,
                flags,
            } => {
                let data = match restriction {
                    Some(restriction) => restriction.encode()?,
                    None => Vec::new(),
                };
                let size = u16::try_from(data.len())
                    .map_err(|_| Error::Unsupported("restriction larger than 64KB".into()))?;
                w.u8(0x30).u8(LOGON_ID).u8(input.0).u16(size).bytes(&data);
                w.u16(folder_ids.len() as u16);
                folder_ids.iter().for_each(|id| {
                    w.u64(*id);
                });
                w.u32(*flags);
            }
            Self::GetSearchCriteria { input } => {
                // UseUnicode, IncludeRestriction, IncludeFolders.
                w.u8(0x31).u8(LOGON_ID).u8(input.0).u8(1).u8(1).u8(1);
            }
            Self::CreateMessage {
                input,
                output,
                folder_id,
                associated,
            } => {
                w.u8(0x06).u8(LOGON_ID).u8(input.0).u8(output.0);
                w.u16(0x0FFF).u64(*folder_id).u8(u8::from(*associated));
            }
            Self::SetProperties { input, values } => {
                let mut body = Writer::new();
                for (tag, value) in values {
                    write_tagged(&mut body, *tag, value)?;
                }
                let size = u16::try_from(body.len() + 2)
                    .map_err(|_| Error::Unsupported("SetProperties larger than 64KB".into()))?;
                w.u8(0x0A)
                    .u8(LOGON_ID)
                    .u8(input.0)
                    .u16(size)
                    .u16(values.len() as u16);
                w.bytes(body.as_slice());
            }
            Self::SaveChangesMessage { input, flags } => {
                // ResponseHandleIndex shares the input slot.
                w.u8(0x0C).u8(LOGON_ID).u8(input.0).u8(input.0).u8(*flags);
            }
        }
        Ok(())
    }

    /// Parse this request's response. Returns None for ROPs without a response.
    pub fn read_response(&self, r: &mut Reader) -> Result<Option<RopResponse>> {
        if matches!(self, Self::Release { .. }) {
            return Ok(None);
        }
        let expected = self.rop_id();
        let rop_id = r.u8()?;
        if rop_id != expected {
            return Err(malformed(format!(
                "expected response for {} (0x{expected:02x}), got 0x{rop_id:02x}",
                self.name()
            )));
        }
        let _handle_index = r.u8()?;
        let code = r.u32()?;
        if code != 0 {
            // Delete ROPs include PartialCompletion even when ReturnValue is nonzero.
            if matches!(
                self,
                Self::DeleteFolder { .. } | Self::DeleteMessages { .. }
            ) {
                r.u8()?;
            }
            if let (Self::Logon { .. }, EC_WRONG_SERVER) = (self, code) {
                let _flags = r.u8()?;
                let len = r.u8()? as usize;
                let server = String::from_utf8_lossy(r.take(len)?)
                    .trim_end_matches('\0')
                    .to_string();
                return Ok(Some(RopResponse::Redirect { server }));
            }
            return Ok(Some(RopResponse::Failed {
                rop: self.name(),
                code,
            }));
        }
        Ok(Some(match self {
            Self::Logon { .. } => {
                let logon_flags = r.u8()?;
                let mut folder_ids = [0u64; 13];
                for id in &mut folder_ids {
                    *id = r.u64()?;
                }
                let response_flags = r.u8()?;
                let mailbox_guid = r.array()?;
                let repl_id = r.u16()?;
                let repl_guid = r.array()?;
                // LogonTime (8), GwartTime (8), StoreState (4).
                r.take(20)?;
                RopResponse::Logon(LogonResponse {
                    logon_flags,
                    folder_ids,
                    response_flags,
                    mailbox_guid,
                    repl_id,
                    repl_guid,
                })
            }
            Self::OpenFolder { .. } => {
                let has_rules = r.u8()? != 0;
                let is_ghosted = r.u8()? != 0;
                if is_ghosted {
                    skip_server_list(r)?;
                }
                RopResponse::OpenFolder {
                    has_rules,
                    is_ghosted,
                }
            }
            Self::OpenMessage { .. } => {
                // The rest (subject, recipients) is not needed; callers send
                // OpenMessage as the last ROP of a batch so the remainder can be skipped.
                r.take(r.remaining())?;
                RopResponse::OpenMessage
            }
            Self::GetHierarchyTable { .. } | Self::GetContentsTable { .. } => RopResponse::Table {
                row_count: r.u32()?,
            },
            Self::SetColumns { .. } => {
                let _status = r.u8()?;
                RopResponse::SetColumns
            }
            Self::QueryRows { .. } => {
                return Err(Error::Unsupported(
                    "QueryRows needs the column set; use read_query_rows".into(),
                ));
            }
            Self::GetPropertiesSpecific { tags, .. } => {
                RopResponse::Properties(read_property_row(r, tags)?)
            }
            Self::GetPropertyIdsFromNames { .. } => {
                let count = r.u16()?;
                RopResponse::PropertyIds((0..count).map(|_| r.u16()).collect::<Result<_>>()?)
            }
            Self::DeleteFolder { .. } => RopResponse::DeleteFolder {
                partial_completion: r.u8()? != 0,
            },
            Self::DeleteMessages { .. } => RopResponse::DeleteMessages {
                partial_completion: r.u8()? != 0,
            },
            Self::CreateFolder { .. } => {
                let folder_id = r.u64()?;
                let existed = r.u8()? != 0;
                if existed {
                    let _has_rules = r.u8()?;
                    if r.u8()? != 0 {
                        skip_server_list(r)?;
                    }
                }
                RopResponse::CreateFolder { folder_id, existed }
            }
            Self::SetSearchCriteria { .. } => RopResponse::SetSearchCriteria,
            Self::GetSearchCriteria { .. } => {
                let size = r.u16()? as usize;
                let restriction_bytes = r.take(size)?.to_vec();
                let restriction = if restriction_bytes.is_empty() {
                    None
                } else {
                    Some(Restriction::decode(&restriction_bytes)?)
                };
                let _logon_id = r.u8()?;
                let count = r.u16()?;
                let folder_ids = (0..count).map(|_| r.u64()).collect::<Result<_>>()?;
                let flags = r.u32()?;
                RopResponse::SearchCriteria(SearchCriteria {
                    restriction,
                    restriction_bytes,
                    folder_ids,
                    flags,
                })
            }
            Self::CreateMessage { .. } => {
                let message_id = if r.u8()? != 0 { Some(r.u64()?) } else { None };
                RopResponse::CreateMessage { message_id }
            }
            Self::SetProperties { .. } => {
                let count = r.u16()?;
                let problems = (0..count)
                    .map(|_| Ok((r.u16()?, r.u32()?, r.u32()?)))
                    .collect::<Result<_>>()?;
                RopResponse::SetProperties { problems }
            }
            Self::SaveChangesMessage { .. } => {
                let _input = r.u8()?;
                RopResponse::SaveChangesMessage {
                    message_id: r.u64()?,
                }
            }
            Self::Release { .. } => unreachable!(),
        }))
    }

    fn rop_id(&self) -> u8 {
        match self {
            Self::Logon { .. } => 0xFE,
            Self::Release { .. } => 0x01,
            Self::OpenFolder { .. } => 0x02,
            Self::OpenMessage { .. } => 0x03,
            Self::GetHierarchyTable { .. } => 0x04,
            Self::GetContentsTable { .. } => 0x05,
            Self::CreateMessage { .. } => 0x06,
            Self::GetPropertiesSpecific { .. } => 0x07,
            Self::SetProperties { .. } => 0x0A,
            Self::SaveChangesMessage { .. } => 0x0C,
            Self::SetColumns { .. } => 0x12,
            Self::QueryRows { .. } => 0x15,
            Self::GetPropertyIdsFromNames { .. } => 0x56,
            Self::DeleteFolder { .. } => 0x1D,
            Self::DeleteMessages { .. } => 0x1E,
            Self::CreateFolder { .. } => 0x1C,
            Self::SetSearchCriteria { .. } => 0x30,
            Self::GetSearchCriteria { .. } => 0x31,
        }
    }
}

fn skip_server_list(r: &mut Reader) -> Result<()> {
    let count = r.u16()?;
    let _cheap = r.u16()?;
    for _ in 0..count {
        r.asciiz()?;
    }
    Ok(())
}

/// A list of ROPs plus the handle table sent in one Execute call.
#[derive(Debug, Default, Clone)]
pub struct Batch {
    pub(crate) rops: Vec<RopRequest>,
    pub(crate) handles: Vec<u32>,
    /// Column set per QueryRows ROP index, captured from the preceding SetColumns.
    columns: Vec<Option<Vec<u32>>>,
}

impl Batch {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserve a slot pre-filled with an existing server handle.
    pub fn input(&mut self, handle: u32) -> Slot {
        self.handles.push(handle);
        Slot((self.handles.len() - 1) as u8)
    }

    /// Reserve an empty slot the server fills with a new object handle.
    pub fn output(&mut self) -> Slot {
        self.input(HANDLE_UNUSED)
    }

    pub fn push(&mut self, rop: RopRequest) -> usize {
        let columns = match &rop {
            RopRequest::QueryRows { input, .. } => self.rops.iter().rev().find_map(|r| match r {
                RopRequest::SetColumns { input: i, columns } if i == input => Some(columns.clone()),
                _ => None,
            }),
            _ => None,
        };
        self.rops.push(rop);
        self.columns.push(columns);
        self.rops.len() - 1
    }

    /// Set the column set for a QueryRows on a table whose SetColumns ran in an earlier batch.
    pub fn push_query_rows(&mut self, input: Slot, count: u16, columns: Vec<u32>) -> usize {
        self.rops.push(RopRequest::QueryRows { input, count });
        self.columns.push(Some(columns));
        self.rops.len() - 1
    }

    /// ROP buffer payload: RopSize, RopsList, ServerObjectHandleTable.
    pub fn encode_payload(&self) -> Result<Vec<u8>> {
        let mut rops = Writer::new();
        for rop in &self.rops {
            rop.write(&mut rops)?;
        }
        let mut w = Writer::new();
        let rop_size = u16::try_from(rops.len() + 2)
            .map_err(|_| Error::Unsupported("ROP list larger than 64KB".into()))?;
        w.u16(rop_size).bytes(rops.as_slice());
        self.handles.iter().for_each(|h| {
            w.u32(*h);
        });
        Ok(w.into_bytes())
    }

    /// Wrap the payload in a single uncompressed RPC_HEADER_EXT marked Last.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let payload = self.encode_payload()?;
        let size = u16::try_from(payload.len())
            .map_err(|_| Error::Unsupported("payload larger than 64KB".into()))?;
        let mut w = Writer::new();
        w.u16(0)
            .u16(header_flags::LAST)
            .u16(size)
            .u16(size)
            .bytes(&payload);
        Ok(w.into_bytes())
    }

    /// Decode the response RopBuffer for this batch.
    pub fn decode_response(&self, rop_buffer: &[u8]) -> Result<BatchResponse> {
        let payload = unwrap_rpc_header_ext(rop_buffer)?;
        let mut r = Reader::new(&payload);
        let rop_size = r.u16()? as usize;
        if rop_size < 2 {
            return Err(malformed("RopSize < 2"));
        }
        let rops_bytes = r.take(rop_size - 2)?;
        let handle_bytes = r.take(r.remaining())?;
        if handle_bytes.len() % 4 != 0 {
            return Err(malformed("handle table not a multiple of 4 bytes"));
        }
        let handles = handle_bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect();

        let mut rops = Reader::new(rops_bytes);
        let mut responses = Vec::with_capacity(self.rops.len());
        for (index, rop) in self.rops.iter().enumerate() {
            if rops.is_empty() {
                responses.push(None);
                continue;
            }
            let response = match (rop, &self.columns[index]) {
                (RopRequest::QueryRows { .. }, columns) => {
                    Some(read_query_rows(&mut rops, columns.as_deref())?)
                }
                _ => rop.read_response(&mut rops)?,
            };
            responses.push(response);
        }
        Ok(BatchResponse { responses, handles })
    }
}

fn read_query_rows(r: &mut Reader, columns: Option<&[u32]>) -> Result<RopResponse> {
    if r.u8()? != 0x15 {
        return Err(malformed("expected RopQueryRows response"));
    }
    let _index = r.u8()?;
    let code = r.u32()?;
    if code != 0 {
        return Ok(RopResponse::Failed {
            rop: "RopQueryRows",
            code,
        });
    }
    let columns = columns.ok_or_else(|| {
        Error::Config("QueryRows without a known column set (call SetColumns first)".into())
    })?;
    let origin = r.u8()?;
    let count = r.u16()?;
    let rows = (0..count)
        .map(|_| read_property_row(r, columns))
        .collect::<Result<_>>()?;
    Ok(RopResponse::QueryRows { origin, rows })
}

#[derive(Debug, Clone)]
pub struct BatchResponse {
    /// One entry per request ROP; None for ROPs without a response or unexecuted ROPs.
    pub responses: Vec<Option<RopResponse>>,
    pub handles: Vec<u32>,
}

impl BatchResponse {
    pub fn handle(&self, slot: Slot) -> Result<u32> {
        match self.handles.get(slot.0 as usize) {
            Some(&h) if h != HANDLE_UNUSED => Ok(h),
            _ => Err(malformed(format!("no server handle in slot {}", slot.0))),
        }
    }

    /// Take the response for request `index`, turning ROP failures into errors.
    pub fn take(&mut self, index: usize) -> Result<RopResponse> {
        self.responses
            .get_mut(index)
            .and_then(Option::take)
            .ok_or_else(|| malformed(format!("no response for ROP #{index}")))?
            .ok()
    }
}

pub mod header_flags {
    pub const COMPRESSED: u16 = 0x0001;
    pub const XOR_MAGIC: u16 = 0x0002;
    pub const LAST: u16 = 0x0004;
}

/// Concatenate the payloads of all RPC_HEADER_EXT segments, undoing XOR obfuscation.
pub fn unwrap_rpc_header_ext(buffer: &[u8]) -> Result<Vec<u8>> {
    let mut r = Reader::new(buffer);
    let mut out = Vec::new();
    loop {
        let version = r.u16()?;
        if version != 0 {
            return Err(malformed(format!("RPC_HEADER_EXT version {version}")));
        }
        let flags = r.u16()?;
        let size = r.u16()? as usize;
        let size_actual = r.u16()? as usize;
        let mut segment = r.take(size)?.to_vec();
        if flags & header_flags::XOR_MAGIC != 0 {
            segment.iter_mut().for_each(|b| *b ^= 0xA5);
        }
        if flags & header_flags::COMPRESSED != 0 {
            return Err(Error::Unsupported(
                "compressed RPC_HEADER_EXT (send Execute with the NoCompression flag)".into(),
            ));
        }
        if segment.len() != size_actual {
            return Err(malformed("RPC_HEADER_EXT Size != SizeActual"));
        }
        out.extend_from_slice(&segment);
        if flags & header_flags::LAST != 0 || r.is_empty() {
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::props::tags;

    #[test]
    fn named_property_request_exact_bytes() {
        let guid = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let request = RopRequest::GetPropertyIdsFromNames {
            input: Slot(3),
            flags: 0x02,
            names: vec![
                PropertyName::Id {
                    guid,
                    lid: 0x1234_5678,
                },
                PropertyName::Name {
                    guid,
                    name: "A😀".into(),
                },
            ],
        };
        let mut w = Writer::new();
        request.write(&mut w).unwrap();
        let expected = [
            &[0x56, 0, 3, 2, 2, 0, 0][..],
            &guid,
            &[0x78, 0x56, 0x34, 0x12, 1],
            &guid,
            &[8, 0x41, 0, 0x3D, 0xD8, 0, 0xDE, 0, 0],
        ]
        .concat();
        assert_eq!(w.into_bytes(), expected);
    }

    #[test]
    fn keywords_request_exact_bytes() {
        let request = RopRequest::GetPropertyIdsFromNames {
            input: Slot(0),
            flags: 2,
            names: vec![PropertyName::Name {
                guid: crate::client::PS_PUBLIC_STRINGS,
                name: "Keywords".into(),
            }],
        };
        let mut w = Writer::new();
        request.write(&mut w).unwrap();
        assert_eq!(
            w.into_bytes(),
            vec![
                0x56, 0, 0, 2, 1, 0, 1, 0x29, 0x03, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0,
                0x46, 18, b'K', 0, b'e', 0, b'y', 0, b'w', 0, b'o', 0, b'r', 0, b'd', 0, b's', 0,
                0, 0,
            ]
        );
    }

    #[test]
    fn named_property_response_exact_bytes() {
        let request = RopRequest::GetPropertyIdsFromNames {
            input: Slot(3),
            flags: 2,
            names: vec![],
        };
        let bytes = [0x56, 3, 0, 0, 0, 0, 2, 0, 1, 0x80, 0xFE, 0xFF];
        let mut r = Reader::new(&bytes);
        assert_eq!(
            request.read_response(&mut r).unwrap(),
            Some(RopResponse::PropertyIds(vec![0x8001, 0xFFFE]))
        );
        assert!(r.is_empty());
        assert!(
            request
                .read_response(&mut Reader::new(&bytes[..11]))
                .is_err()
        );
        let error = [0x56, 3, 0x0F, 1, 4, 0x80];
        let mut r = Reader::new(&error);
        assert_eq!(
            request.read_response(&mut r).unwrap(),
            Some(RopResponse::Failed {
                rop: "RopGetPropertyIdsFromNames",
                code: 0x8004_010F,
            })
        );
        assert!(r.is_empty());
    }

    #[test]
    fn named_property_names_validate_byte_lengths() {
        let valid = PropertyName::Name {
            guid: [0; 16],
            name: "x".repeat(126),
        };
        let mut w = Writer::new();
        valid.write(&mut w).unwrap();
        assert_eq!(w.as_slice()[17], 254);
        for name in ["x".repeat(127), "has\0nul".into()] {
            let invalid = PropertyName::Name {
                guid: [0; 16],
                name,
            };
            assert!(invalid.write(&mut Writer::new()).is_err());
        }
        let request = RopRequest::GetPropertyIdsFromNames {
            input: Slot(0),
            flags: 2,
            names: vec![valid; u16::MAX as usize + 1],
        };
        assert!(request.write(&mut Writer::new()).is_err());
    }

    #[test]
    fn delete_request_exact_bytes() {
        let mut w = Writer::new();
        RopRequest::DeleteFolder {
            input: Slot(1),
            flags: 0x15,
            folder_id: 0x0807_0605_0403_0201,
        }
        .write(&mut w)
        .unwrap();
        assert_eq!(w.into_bytes(), [0x1D, 0, 1, 0x15, 1, 2, 3, 4, 5, 6, 7, 8]);
        let mut w = Writer::new();
        RopRequest::DeleteMessages {
            input: Slot(2),
            message_ids: vec![0x0807_0605_0403_0201, 9],
        }
        .write(&mut w)
        .unwrap();
        assert_eq!(
            w.into_bytes(),
            [
                0x1E, 0, 2, 0, 0, 2, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0,
            ]
        );
    }

    #[test]
    fn delete_response_consumes_partial_completion() {
        let requests = [
            RopRequest::DeleteFolder {
                input: Slot(0),
                flags: 0x15,
                folder_id: 1,
            },
            RopRequest::DeleteMessages {
                input: Slot(0),
                message_ids: vec![2],
            },
        ];
        for request in requests {
            let bytes = [request.rop_id(), 0, 0, 0, 0, 0, 1];
            let mut r = Reader::new(&bytes);
            let response = request.read_response(&mut r).unwrap().unwrap();
            assert!(matches!(
                response,
                RopResponse::DeleteFolder {
                    partial_completion: true
                } | RopResponse::DeleteMessages {
                    partial_completion: true
                }
            ));
            assert!(r.is_empty());
            let bytes = [request.rop_id(), 0, 5, 0, 7, 0x80, 1];
            let mut r = Reader::new(&bytes);
            assert!(matches!(
                request.read_response(&mut r).unwrap(),
                Some(RopResponse::Failed { .. })
            ));
            assert!(r.is_empty());
        }
    }

    #[test]
    fn logon_request_bytes() {
        let mut batch = Batch::new();
        let out = batch.output();
        batch.push(RopRequest::Logon {
            output: out,
            logon_flags: 0x01,
            open_flags: 0x0100_0004,
            essdn: "/o=X".into(),
        });
        let bytes = batch.encode().unwrap();
        let expected_payload: Vec<u8> = [
            &[21u8, 0][..],
            &[0xFE, 0, 0, 0x01, 0x04, 0, 0, 0x01, 0, 0, 0, 0, 5, 0],
            b"/o=X\0",
            &[0xFF, 0xFF, 0xFF, 0xFF],
        ]
        .concat();
        let n = expected_payload.len() as u8;
        assert_eq!(&bytes[..8], &[0, 0, 4, 0, n, 0, n, 0]);
        assert_eq!(&bytes[8..], &expected_payload[..]);
    }

    fn wrap(payload: &[u8], flags: u16) -> Vec<u8> {
        let mut w = Writer::new();
        let n = payload.len() as u16;
        w.u16(0).u16(flags).u16(n).u16(n).bytes(payload);
        w.into_bytes()
    }

    #[test]
    fn decodes_logon_and_table_responses() {
        let mut batch = Batch::new();
        let store = batch.output();
        let logon = batch.push(RopRequest::Logon {
            output: store,
            logon_flags: 1,
            open_flags: 0,
            essdn: String::new(),
        });
        let finder = batch.output();
        let open = batch.push(RopRequest::OpenFolder {
            input: store,
            output: finder,
            folder_id: 1,
            open_mode: 0,
        });
        let table = batch.output();
        let hier = batch.push(RopRequest::GetHierarchyTable {
            input: finder,
            output: table,
            flags: 0,
        });
        let cols = vec![tags::PR_FOLDER_ID, tags::PR_DISPLAY_NAME_W];
        batch.push(RopRequest::SetColumns {
            input: table,
            columns: cols,
        });
        let query = batch.push(RopRequest::QueryRows {
            input: table,
            count: 10,
        });
        let release = batch.push(RopRequest::Release { input: table });

        let mut rops = Writer::new();
        rops.u8(0xFE).u8(0).u32(0).u8(1);
        (0..13u64).for_each(|i| {
            rops.u64(0x100 + i);
        });
        rops.u8(0)
            .bytes(&[7; 16])
            .u16(1)
            .bytes(&[8; 16])
            .bytes(&[0; 20]);
        rops.u8(0x02).u8(1).u32(0).u8(0).u8(0);
        rops.u8(0x04).u8(2).u32(0).u32(1);
        rops.u8(0x12).u8(2).u32(0).u8(0);
        rops.u8(0x15).u8(2).u32(0).u8(2).u16(1);
        rops.u8(0).u64(42).utf16z("Sample Folder");
        let mut payload = Writer::new();
        payload.u16(rops.len() as u16 + 2).bytes(rops.as_slice());
        payload.u32(0x11).u32(0x22).u32(0x33);

        let mut response = batch
            .decode_response(&wrap(payload.as_slice(), header_flags::LAST))
            .unwrap();
        assert_eq!(response.handle(finder).unwrap(), 0x22);
        match response.take(logon).unwrap() {
            RopResponse::Logon(l) => {
                assert_eq!(l.folder_ids[folder::FINDER], 0x10A);
                assert_eq!(l.repl_id, 1);
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            response.take(open).unwrap(),
            RopResponse::OpenFolder { .. }
        ));
        assert_eq!(
            response.take(hier).unwrap(),
            RopResponse::Table { row_count: 1 }
        );
        match response.take(query).unwrap() {
            RopResponse::QueryRows { rows, .. } => {
                assert_eq!(rows[0][1].1, PropValue::Unicode("Sample Folder".into()));
            }
            other => panic!("{other:?}"),
        }
        assert!(response.responses[release].is_none());
    }

    #[test]
    fn rop_failure_is_reported() {
        let mut batch = Batch::new();
        let folder = batch.input(5);
        let index = batch.push(RopRequest::GetSearchCriteria { input: folder });
        let mut payload = Writer::new();
        payload.u16(8).u8(0x31).u8(0).u32(0x8004_010F).u32(5);
        let mut response = batch.decode_response(&wrap(payload.as_slice(), 4)).unwrap();
        let err = response.take(index).unwrap_err().to_string();
        assert!(err.contains("MAPI_E_NOT_FOUND"), "{err}");
    }

    #[test]
    fn xor_payload_is_unmasked() {
        let masked: Vec<u8> = [1u8, 2, 3].iter().map(|b| b ^ 0xA5).collect();
        let bytes = wrap(&masked, header_flags::XOR_MAGIC | header_flags::LAST);
        assert_eq!(unwrap_rpc_header_ext(&bytes).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn search_criteria_roundtrip_shape() {
        let restriction = Restriction::Exist { tag: 0x1090_0003 };
        let mut batch = Batch::new();
        let folder = batch.input(9);
        batch.push(RopRequest::SetSearchCriteria {
            input: folder,
            restriction: Some(restriction.clone()),
            folder_ids: vec![0x0001_0000_0000_0001],
            flags: search_flags::RESTART_SEARCH | search_flags::RECURSIVE_SEARCH,
        });
        let payload = batch.encode_payload().unwrap();
        // RopSize(2) + header(3) + size(2) + restriction(5) + count(2) + id(8) + flags(4)
        assert_eq!(
            u16::from_le_bytes([payload[0], payload[1]]),
            2 + 3 + 2 + 5 + 2 + 8 + 4
        );
        assert_eq!(&payload[7..12], &restriction.encode().unwrap()[..]);
    }
}
