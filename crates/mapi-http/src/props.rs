// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Property tags, values and rows as encoded in ROP buffers (MS-OXCDATA 2.9-2.11).

use crate::codec::{Reader, Writer};
use crate::error::{Error, Result, malformed};

pub mod types {
    pub const UNSPECIFIED: u16 = 0x0000;
    pub const NULL: u16 = 0x0001;
    pub const I16: u16 = 0x0002;
    pub const I32: u16 = 0x0003;
    pub const F32: u16 = 0x0004;
    pub const F64: u16 = 0x0005;
    pub const CURRENCY: u16 = 0x0006;
    pub const APPTIME: u16 = 0x0007;
    pub const ERROR: u16 = 0x000A;
    pub const BOOLEAN: u16 = 0x000B;
    pub const OBJECT: u16 = 0x000D;
    pub const I64: u16 = 0x0014;
    pub const STRING8: u16 = 0x001E;
    pub const UNICODE: u16 = 0x001F;
    pub const SYSTIME: u16 = 0x0040;
    pub const GUID: u16 = 0x0048;
    pub const SERVERID: u16 = 0x00FB;
    pub const RESTRICTION: u16 = 0x00FD;
    pub const RULEACTION: u16 = 0x00FE;
    pub const BINARY: u16 = 0x0102;
    pub const MULTI: u16 = 0x1000;
}

/// Well-known property tags used by this client.
pub mod tags {
    pub const PR_DISPLAY_NAME_W: u32 = 0x3001_001F;
    pub const PR_FOLDER_ID: u32 = 0x6748_0014;
    pub const PR_MID: u32 = 0x674A_0014;
    pub const PR_ENTRYID: u32 = 0x0FFF_0102;
    pub const PR_MESSAGE_CLASS_W: u32 = 0x001A_001F;
    pub const PR_SUBJECT_W: u32 = 0x0037_001F;
    pub const PR_FOLDER_TYPE: u32 = 0x3601_0003;
    pub const PR_CONTENT_COUNT: u32 = 0x3602_0003;
    pub const PR_CONTAINER_CLASS_W: u32 = 0x3613_001F;
    pub const PR_LAST_MODIFICATION_TIME: u32 = 0x3008_0040;
    /// Search folder definition message properties (MS-OXOSRCH 2.2; MS-OXPROPS alternate names).
    pub const PR_WB_SF_TEMPLATE_ID: u32 = 0x6841_0003;
    pub const PR_WB_SF_ID: u32 = 0x6842_0102;
    pub const PR_WB_SF_DEFINITION: u32 = 0x6845_0102;
    pub const PR_WB_SF_RECREATE_INFO: u32 = 0x6844_0102;
    pub const PR_WB_SF_STORAGE_TYPE: u32 = 0x6846_0003;
    pub const PR_WB_SF_TAG: u32 = 0x6847_0003;
    pub const PR_WB_SF_EFP_FLAGS: u32 = 0x6848_0003;
    pub const PR_WB_SF_LAST_USED: u32 = 0x6834_0003;
    pub const PR_WB_SF_EXPIRATION: u32 = 0x683A_0003;
}

/// Search folder definition message class (MS-OXOSRCH 2.2.1).
pub const SFINFO_MESSAGE_CLASS: &str = "IPM.Microsoft.WunderBar.SFInfo";

pub fn prop_type(tag: u32) -> u16 {
    (tag & 0xFFFF) as u16
}

pub fn prop_id(tag: u32) -> u16 {
    (tag >> 16) as u16
}

#[derive(Debug, Clone, PartialEq)]
pub enum PropValue {
    Null,
    I16(i16),
    I32(i32),
    F32(f32),
    F64(f64),
    Currency(i64),
    AppTime(f64),
    Error(u32),
    Boolean(bool),
    I64(i64),
    String8(String),
    Unicode(String),
    SysTime(u64),
    Guid([u8; 16]),
    ServerId(Vec<u8>),
    Binary(Vec<u8>),
    MultiI16(Vec<i16>),
    MultiI32(Vec<i32>),
    MultiI64(Vec<i64>),
    MultiUnicode(Vec<String>),
    MultiString8(Vec<String>),
    MultiGuid(Vec<[u8; 16]>),
    MultiBinary(Vec<Vec<u8>>),
    /// Property was not returned in a flagged row.
    NotFound,
}

impl PropValue {
    pub fn as_i32(&self) -> Option<i32> {
        match self {
            Self::I32(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::I64(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Unicode(v) | Self::String8(v) => Some(v),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Binary(v) | Self::ServerId(v) => Some(v),
            _ => None,
        }
    }
}

/// Encode a value whose type is implied by `ty` (no type prefix).
pub fn write_value(writer: &mut Writer, ty: u16, value: &PropValue) -> Result<()> {
    use types::*;
    match (ty, value) {
        (I16, PropValue::I16(v)) => {
            writer.u16(*v as u16);
        }
        (I32, PropValue::I32(v)) => {
            writer.u32(*v as u32);
        }
        (F32, PropValue::F32(v)) => {
            writer.u32(v.to_bits());
        }
        (F64, PropValue::F64(v)) | (APPTIME, PropValue::AppTime(v)) => {
            writer.u64(v.to_bits());
        }
        (CURRENCY, PropValue::Currency(v)) | (I64, PropValue::I64(v)) => {
            writer.u64(*v as u64);
        }
        (ERROR, PropValue::Error(v)) => {
            writer.u32(*v);
        }
        (BOOLEAN, PropValue::Boolean(v)) => {
            writer.u8(u8::from(*v));
        }
        (STRING8, PropValue::String8(v)) => {
            writer.asciiz(v);
        }
        (UNICODE, PropValue::Unicode(v)) => {
            writer.utf16z(v);
        }
        (SYSTIME, PropValue::SysTime(v)) => {
            writer.u64(*v);
        }
        (GUID, PropValue::Guid(v)) => {
            writer.bytes(v);
        }
        (BINARY, PropValue::Binary(v)) | (SERVERID, PropValue::ServerId(v)) => {
            write_counted(writer, v)?;
        }
        (t, PropValue::MultiI16(v)) if t == MULTI | I16 => {
            writer.u32(v.len() as u32);
            v.iter().for_each(|x| {
                writer.u16(*x as u16);
            });
        }
        (t, PropValue::MultiI32(v)) if t == MULTI | I32 => {
            writer.u32(v.len() as u32);
            v.iter().for_each(|x| {
                writer.u32(*x as u32);
            });
        }
        (t, PropValue::MultiI64(v)) if t == MULTI | I64 => {
            writer.u32(v.len() as u32);
            v.iter().for_each(|x| {
                writer.u64(*x as u64);
            });
        }
        (t, PropValue::MultiUnicode(v)) if t == MULTI | UNICODE => {
            writer.u32(v.len() as u32);
            v.iter().for_each(|x| {
                writer.utf16z(x);
            });
        }
        (t, PropValue::MultiString8(v)) if t == MULTI | STRING8 => {
            writer.u32(v.len() as u32);
            v.iter().for_each(|x| {
                writer.asciiz(x);
            });
        }
        (t, PropValue::MultiGuid(v)) if t == MULTI | GUID => {
            writer.u32(v.len() as u32);
            v.iter().for_each(|x| {
                writer.bytes(x);
            });
        }
        (t, PropValue::MultiBinary(v)) if t == MULTI | BINARY => {
            writer.u32(v.len() as u32);
            for x in v {
                write_counted(writer, x)?;
            }
        }
        _ => {
            return Err(Error::Unsupported(format!(
                "value {value:?} for property type 0x{ty:04x}"
            )));
        }
    }
    Ok(())
}

fn write_counted(writer: &mut Writer, bytes: &[u8]) -> Result<()> {
    let count = u16::try_from(bytes.len())
        .map_err(|_| Error::Unsupported(format!("binary of {} bytes", bytes.len())))?;
    writer.u16(count).bytes(bytes);
    Ok(())
}

/// Decode a value whose type is implied by `ty` (no type prefix).
pub fn read_value(reader: &mut Reader, ty: u16) -> Result<PropValue> {
    use types::*;
    Ok(match ty {
        NULL => PropValue::Null,
        I16 => PropValue::I16(reader.u16()? as i16),
        I32 => PropValue::I32(reader.u32()? as i32),
        F32 => PropValue::F32(f32::from_bits(reader.u32()?)),
        F64 => PropValue::F64(f64::from_bits(reader.u64()?)),
        APPTIME => PropValue::AppTime(f64::from_bits(reader.u64()?)),
        CURRENCY => PropValue::Currency(reader.u64()? as i64),
        ERROR => PropValue::Error(reader.u32()?),
        BOOLEAN => PropValue::Boolean(reader.u8()? != 0),
        I64 => PropValue::I64(reader.u64()? as i64),
        STRING8 => PropValue::String8(reader.asciiz()?),
        UNICODE => PropValue::Unicode(reader.utf16z()?),
        SYSTIME => PropValue::SysTime(reader.u64()?),
        GUID => PropValue::Guid(reader.array()?),
        BINARY => PropValue::Binary(read_counted(reader)?),
        SERVERID => PropValue::ServerId(read_counted(reader)?),
        t if t == MULTI | I16 => {
            let n = reader.u32()?;
            PropValue::MultiI16(
                (0..n)
                    .map(|_| reader.u16().map(|v| v as i16))
                    .collect::<Result<_>>()?,
            )
        }
        t if t == MULTI | I32 => {
            let n = reader.u32()?;
            PropValue::MultiI32(
                (0..n)
                    .map(|_| reader.u32().map(|v| v as i32))
                    .collect::<Result<_>>()?,
            )
        }
        t if t == MULTI | I64 => {
            let n = reader.u32()?;
            PropValue::MultiI64(
                (0..n)
                    .map(|_| reader.u64().map(|v| v as i64))
                    .collect::<Result<_>>()?,
            )
        }
        t if t == MULTI | UNICODE => {
            let n = reader.u32()?;
            PropValue::MultiUnicode((0..n).map(|_| reader.utf16z()).collect::<Result<_>>()?)
        }
        t if t == MULTI | STRING8 => {
            let n = reader.u32()?;
            PropValue::MultiString8((0..n).map(|_| reader.asciiz()).collect::<Result<_>>()?)
        }
        t if t == MULTI | GUID => {
            let n = reader.u32()?;
            PropValue::MultiGuid((0..n).map(|_| reader.array()).collect::<Result<_>>()?)
        }
        t if t == MULTI | BINARY => {
            let n = reader.u32()?;
            PropValue::MultiBinary(
                (0..n)
                    .map(|_| read_counted(reader))
                    .collect::<Result<_>>()?,
            )
        }
        other => return Err(Error::Unsupported(format!("property type 0x{other:04x}"))),
    })
}

fn read_counted(reader: &mut Reader) -> Result<Vec<u8>> {
    let count = reader.u16()? as usize;
    Ok(reader.take(count)?.to_vec())
}

/// TypedPropertyValue: type then value.
pub fn read_typed_value(reader: &mut Reader) -> Result<(u16, PropValue)> {
    let ty = reader.u16()?;
    Ok((ty, read_value(reader, ty)?))
}

/// TaggedPropertyValue: tag then value.
pub fn write_tagged(writer: &mut Writer, tag: u32, value: &PropValue) -> Result<()> {
    writer.u32(tag);
    write_value(writer, prop_type(tag), value)
}

pub fn read_tagged(reader: &mut Reader) -> Result<(u32, PropValue)> {
    let tag = reader.u32()?;
    Ok((tag, read_value(reader, prop_type(tag))?))
}

/// One row in a table or GetPropertiesSpecific response (PropertyRow, MS-OXCDATA 2.8.1).
pub type PropertyRow = Vec<(u32, PropValue)>;

pub fn read_property_row(reader: &mut Reader, columns: &[u32]) -> Result<PropertyRow> {
    let flagged = match reader.u8()? {
        0 => false,
        1 => true,
        other => return Err(malformed(format!("PropertyRow flag {other}"))),
    };
    let mut row = Vec::with_capacity(columns.len());
    for &tag in columns {
        let ty = prop_type(tag);
        let value = if flagged {
            match reader.u8()? {
                0x00 => read_column_value(reader, ty)?,
                0x01 => PropValue::NotFound,
                0x0A => PropValue::Error(reader.u32()?),
                other => return Err(malformed(format!("PropertyValue flag {other:#x}"))),
            }
        } else {
            read_column_value(reader, ty)?
        };
        row.push((tag, value));
    }
    Ok(row)
}

fn read_column_value(reader: &mut Reader, ty: u16) -> Result<PropValue> {
    if ty == types::UNSPECIFIED {
        Ok(read_typed_value(reader)?.1)
    } else {
        read_value(reader, ty)
    }
}

/// Look up a value in a row by tag.
pub fn find(row: &PropertyRow, tag: u32) -> Option<&PropValue> {
    row.iter().find(|(t, _)| *t == tag).map(|(_, v)| v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_values_roundtrip() {
        let values = [
            (tags::PR_WB_SF_TEMPLATE_ID, PropValue::I32(6)),
            (
                tags::PR_MESSAGE_CLASS_W,
                PropValue::Unicode(SFINFO_MESSAGE_CLASS.into()),
            ),
            (
                tags::PR_WB_SF_DEFINITION,
                PropValue::Binary(vec![4, 0x10, 0, 0]),
            ),
            (
                0x6850_101F,
                PropValue::MultiUnicode(vec!["a".into(), "bc".into()]),
            ),
            (0x0E1B_000B, PropValue::Boolean(true)),
        ];
        let mut writer = Writer::new();
        for (tag, value) in &values {
            write_tagged(&mut writer, *tag, value).unwrap();
        }
        let bytes = writer.into_bytes();
        let mut reader = Reader::new(&bytes);
        for expected in &values {
            assert_eq!(&read_tagged(&mut reader).unwrap(), expected);
        }
        assert!(reader.is_empty());
    }

    #[test]
    fn binary_uses_16_bit_count() {
        let mut writer = Writer::new();
        write_value(
            &mut writer,
            types::BINARY,
            &PropValue::Binary(vec![0xAA, 0xBB]),
        )
        .unwrap();
        assert_eq!(writer.into_bytes(), vec![2, 0, 0xAA, 0xBB]);
    }

    #[test]
    fn flagged_row_reports_missing_and_errors() {
        let columns = [
            tags::PR_FOLDER_ID,
            tags::PR_DISPLAY_NAME_W,
            tags::PR_WB_SF_DEFINITION,
        ];
        let mut writer = Writer::new();
        writer.u8(1);
        writer.u8(0).u64(0x0001_0000_0000_0042);
        writer.u8(1);
        writer.u8(0x0A).u32(0x8007_000E);
        let bytes = writer.into_bytes();
        let row = read_property_row(&mut Reader::new(&bytes), &columns).unwrap();
        assert_eq!(row[0].1, PropValue::I64(0x0001_0000_0000_0042));
        assert_eq!(row[1].1, PropValue::NotFound);
        assert_eq!(row[2].1, PropValue::Error(0x8007_000E));
    }
}
