// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! SFInfo definition blob (`PR_WB_SF_DEFINITION`, version 0x1004).
//!
//! Layout of the blob on the SFInfo message (all integers little-endian):
//!
//! ```text
//! u32     version            0x1004
//! u32     storage_type       storage-type flags (see `storage`)
//! u32     number_value       numeric parameter
//! str     text_value         text parameter
//! u32     skip block         0
//! u32     deep               0 or 0xFFFFFFFF
//! str     folder names       unused here (empty)
//! ENTRYLIST                  packed size, count, then (cb, 0) pairs, then EntryID bytes
//! u32     skip block         0
//! MRES                       the restriction, every field widened to 32 bits
//! u32     skip block         0
//! ```
//!
//! `str` is a length-prefixed string: a BYTE character count (or 0xFF followed by a WORD count
//! when the count is 255 or more), then that many UTF-16 code units with no terminator.
//!
//! Unlike the ROP restriction format, this blob stores every restriction field as a 32-bit word.
//! Supported subset: And, Or, Not, Content, Property, Bitmask, Exist with Long, Boolean,
//! SysTime and Unicode literals.

use crate::error::{Error, Result, malformed};
use crate::props::PropValue;
use crate::restriction::Restriction;

const VERSION: u32 = 0x1004;

/// Storage-type flags. They say which optional parts the blob has.
pub mod storage {
    /// `number_value` carries a parameter.
    pub const NUMBER: u32 = 0x0001;
    /// `text_value` carries a parameter.
    pub const TEXT: u32 = 0x0002;
    /// A MADL (address list) follows the ENTRYLIST. Not written by this crate.
    pub const BINARY: u32 = 0x0004;
    /// An MRES restriction follows.
    pub const MRES: u32 = 0x0008;
    /// A filter stream follows. Not written by this crate.
    pub const FILTERSTREAM: u32 = 0x0010;
    pub const FOLDERNAME: u32 = 0x0020;
    /// The scope is an explicit folder list.
    pub const FOLDERLIST: u32 = 0x0040;
    /// The criteria are rebuilt every day.
    pub const REFRESH_DAILY: u32 = 0x4000;
    pub const REFRESH_WEEKLY: u32 = 0x2000;
    pub const REFRESH_MONTHLY: u32 = 0x1000;
    /// Restriction plus explicit folder list, with no parameters.
    pub const DEFAULT: u32 = MRES | FOLDERLIST;
}
const MAX_BLOB: usize = 1024 * 1024;
const MAX_DEPTH: usize = 64;
const MAX_SCOPE: usize = 10_000;

const PT_LONG: u32 = 0x0003;
const PT_BOOLEAN: u32 = 0x000B;
const PT_SYSTIME: u32 = 0x0040;
const PT_UNICODE: u32 = 0x001F;
const MV_FLAG: u32 = 0x1000;

#[derive(Debug, Clone, PartialEq)]
pub struct Definition {
    /// Storage-type flags; must include MRES and FOLDERLIST and must not include BINARY or FILTERSTREAM.
    pub storage_type: u32,
    /// Numeric parameter. Meaningful only with `storage::NUMBER`.
    pub number_value: u32,
    /// Text parameter. Meaningful only with `storage::TEXT`.
    pub text_value: String,
    pub deep: bool,
    /// Folder EntryIDs (`PR_ENTRYID`), not FIDs.
    pub scope: Vec<Vec<u8>>,
    pub restriction: Restriction,
}

impl Definition {
    /// Definition without template parameters (`storage::DEFAULT`, empty `number_value`/`text_value`).
    pub fn new(deep: bool, scope: Vec<Vec<u8>>, restriction: Restriction) -> Self {
        Self {
            storage_type: storage::DEFAULT,
            number_value: 0,
            text_value: String::new(),
            deep,
            scope,
            restriction,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.scope.is_empty() || self.scope.iter().any(Vec::is_empty) {
            return Err(Error::Unsupported("empty search scope".into()));
        }
        check_storage_type(self.storage_type)?;
        let packed_size = self
            .scope
            .iter()
            .try_fold(8usize, |size, entry| size.checked_add(8 + entry.len()))
            .filter(|size| *size <= MAX_BLOB)
            .ok_or_else(|| Error::Unsupported("search scope too large".into()))?;

        let mut bytes = Vec::new();
        word(&mut bytes, VERSION);
        word(&mut bytes, self.storage_type);
        word(&mut bytes, self.number_value);
        write_string(&mut bytes, &self.text_value)?;
        word(&mut bytes, 0); // skip block
        word(&mut bytes, if self.deep { u32::MAX } else { 0 });
        write_string(&mut bytes, "")?; // folder names
        word(&mut bytes, packed_size as u32);
        word(&mut bytes, self.scope.len() as u32);
        word(&mut bytes, 0);
        for entry in &self.scope {
            word(&mut bytes, entry.len() as u32);
            word(&mut bytes, 0);
        }
        for entry in &self.scope {
            bytes.extend_from_slice(entry);
        }
        word(&mut bytes, 0);
        write_restriction(&mut bytes, &self.restriction, 0)?;
        word(&mut bytes, 0);
        if bytes.len() > MAX_BLOB {
            return Err(Error::Unsupported("definition blob exceeds 1 MiB".into()));
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_BLOB {
            return Err(malformed("definition blob exceeds 1 MiB"));
        }
        let mut r = WordReader { bytes, pos: 0 };
        if r.word()? != VERSION {
            return Err(Error::Unsupported("definition blob header".into()));
        }
        let storage_type = r.word()?;
        check_storage_type(storage_type)?;
        let number_value = r.word()?;
        let text_value = r.string()?;
        r.zero_word()?;
        let deep = match r.word()? {
            0 => false,
            u32::MAX => true,
            other => return Err(malformed(format!("deep flag {other:#x}"))),
        };
        let _folder_names = r.string()?;
        let packed_size = r.word()? as usize;
        let start = r.pos;
        let count = r.word()? as usize;
        if count == 0 || count > MAX_SCOPE {
            return Err(malformed(format!("scope count {count}")));
        }
        r.zero_word()?;
        let mut lengths = Vec::with_capacity(count);
        for _ in 0..count {
            lengths.push(r.word()? as usize);
            r.zero_word()?;
        }
        let mut scope = Vec::with_capacity(count);
        for length in lengths {
            if length == 0 {
                return Err(malformed("empty scope EntryID"));
            }
            scope.push(r.take(length)?.to_vec());
        }
        if r.pos - start != packed_size {
            return Err(malformed("ENTRYLIST size mismatch"));
        }
        r.zero_word()?;
        let restriction = read_restriction(&mut r, 0)?;
        r.zero_word()?;
        if r.pos != bytes.len() {
            return Err(malformed("trailing bytes in definition blob"));
        }
        Ok(Self {
            storage_type,
            number_value,
            text_value,
            deep,
            scope,
            restriction,
        })
    }
}

fn check_storage_type(value: u32) -> Result<()> {
    let required = storage::MRES | storage::FOLDERLIST;
    if value & required != required || value & (storage::BINARY | storage::FILTERSTREAM) != 0 {
        return Err(Error::Unsupported(format!(
            "storage type {value:#x} (needs MRES|FOLDERLIST, no BINARY/FILTERSTREAM)"
        )));
    }
    Ok(())
}

/// Length-prefixed string: BYTE count, or 0xFF + WORD count, then UTF-16 without NUL.
fn write_string(bytes: &mut Vec<u8>, text: &str) -> Result<()> {
    let units: Vec<u16> = text.encode_utf16().collect();
    let count = u16::try_from(units.len())
        .map_err(|_| Error::Unsupported("blob string longer than 65535 chars".into()))?;
    if count < 255 {
        bytes.push(count as u8);
    } else {
        bytes.push(255);
        bytes.extend_from_slice(&count.to_le_bytes());
    }
    for unit in units {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(())
}

fn word(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn write_restriction(bytes: &mut Vec<u8>, res: &Restriction, depth: usize) -> Result<()> {
    if depth >= MAX_DEPTH {
        return Err(Error::Unsupported("restriction too deep".into()));
    }
    match res {
        Restriction::And(children) | Restriction::Or(children) => {
            word(bytes, u32::from(matches!(res, Restriction::Or(_))));
            word(bytes, children.len() as u32);
            for child in children {
                write_restriction(bytes, child, depth + 1)?;
            }
        }
        Restriction::Not(child) => {
            word(bytes, 2);
            write_restriction(bytes, child, depth + 1)?;
        }
        Restriction::Content {
            fuzzy_low,
            fuzzy_high,
            tag,
            value,
        } => {
            if !matches!(tag & 0xFFFF, PT_UNICODE | 0x101F) {
                return Err(Error::Unsupported("Content requires a Unicode tag".into()));
            }
            word(bytes, 3);
            word(
                bytes,
                u32::from(*fuzzy_low) | (u32::from(*fuzzy_high) << 16),
            );
            word(bytes, *tag);
            // A multivalue tag (e.g. Keywords) compares each element to a scalar literal.
            write_literal(bytes, tag & !MV_FLAG, value)?;
        }
        Restriction::Property { relop, tag, value } => {
            word(bytes, 4);
            word(bytes, u32::from(*relop));
            word(bytes, *tag);
            write_literal(bytes, *tag, value)?;
        }
        Restriction::Bitmask { relop, tag, mask } => {
            word(bytes, 6);
            word(bytes, u32::from(*relop));
            word(bytes, *tag);
            word(bytes, *mask);
        }
        Restriction::Exist { tag } => {
            word(bytes, 8);
            word(bytes, *tag);
        }
        other => {
            return Err(Error::Unsupported(format!(
                "restriction not supported in SFInfo blob: {other:?}"
            )));
        }
    }
    if bytes.len() > MAX_BLOB {
        return Err(Error::Unsupported("definition blob exceeds 1 MiB".into()));
    }
    Ok(())
}

fn write_literal(bytes: &mut Vec<u8>, tag: u32, value: &PropValue) -> Result<()> {
    let ty = tag & 0xFFFF;
    word(bytes, tag);
    match (ty, value) {
        (PT_LONG, PropValue::I32(v)) => bytes.extend_from_slice(&v.to_le_bytes()),
        (PT_BOOLEAN, PropValue::Boolean(v)) => {
            bytes.extend_from_slice(&u16::from(*v).to_le_bytes())
        }
        (PT_SYSTIME, PropValue::SysTime(v)) => bytes.extend_from_slice(&v.to_le_bytes()),
        (PT_UNICODE, PropValue::Unicode(text)) => {
            if text.contains('\0') {
                return Err(Error::Unsupported("text literal with embedded NUL".into()));
            }
            let units: Vec<u16> = text.encode_utf16().chain([0]).collect();
            let length = i16::try_from(units.len() * 2)
                .map_err(|_| Error::Unsupported("text literal too long".into()))?;
            bytes.extend_from_slice(&length.to_le_bytes());
            for unit in units {
                bytes.extend_from_slice(&unit.to_le_bytes());
            }
        }
        _ => {
            return Err(Error::Unsupported(format!(
                "literal {value:?} does not match tag {tag:#010x}"
            )));
        }
    }
    Ok(())
}

struct WordReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> WordReader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| malformed("definition blob truncated"))?;
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
    fn word(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn zero_word(&mut self) -> Result<()> {
        match self.word()? {
            0 => Ok(()),
            v => Err(malformed(format!("expected zero word, got {v:#x}"))),
        }
    }
    fn string(&mut self) -> Result<String> {
        let mut count = self.take(1)?[0] as usize;
        if count == 255 {
            count = self.u16()? as usize;
        }
        let raw = self.take(count * 2)?;
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&units).map_err(|_| malformed("blob string UTF-16"))
    }
}

fn read_restriction(r: &mut WordReader, depth: usize) -> Result<Restriction> {
    if depth >= MAX_DEPTH {
        return Err(malformed("restriction too deep"));
    }
    Ok(match r.word()? {
        kind @ (0 | 1) => {
            let count = r.word()? as usize;
            if count > MAX_SCOPE {
                return Err(malformed(format!("restriction child count {count}")));
            }
            let children = (0..count)
                .map(|_| read_restriction(r, depth + 1))
                .collect::<Result<Vec<_>>>()?;
            if kind == 0 {
                Restriction::And(children)
            } else {
                Restriction::Or(children)
            }
        }
        2 => Restriction::Not(Box::new(read_restriction(r, depth + 1)?)),
        3 => {
            let fuzzy = r.word()?;
            let tag = r.word()?;
            let value = read_literal(r, tag & !MV_FLAG)?;
            Restriction::Content {
                fuzzy_low: fuzzy as u16,
                fuzzy_high: (fuzzy >> 16) as u16,
                tag,
                value,
            }
        }
        4 => {
            let relop = relop_u8(r.word()?)?;
            let tag = r.word()?;
            let value = read_literal(r, tag)?;
            Restriction::Property { relop, tag, value }
        }
        6 => {
            let relop = relop_u8(r.word()?)?;
            let tag = r.word()?;
            let mask = r.word()?;
            Restriction::Bitmask { relop, tag, mask }
        }
        8 => Restriction::Exist { tag: r.word()? },
        other => {
            return Err(Error::Unsupported(format!(
                "SFInfo restriction type {other}"
            )));
        }
    })
}

fn relop_u8(value: u32) -> Result<u8> {
    u8::try_from(value).map_err(|_| malformed(format!("relop {value:#x}")))
}

fn read_literal(r: &mut WordReader, expected_tag: u32) -> Result<PropValue> {
    let tag = r.word()?;
    if tag != expected_tag {
        return Err(malformed(format!(
            "literal tag {tag:#010x} != {expected_tag:#010x}"
        )));
    }
    Ok(match tag & 0xFFFF {
        PT_LONG => PropValue::I32(r.word()? as i32),
        PT_BOOLEAN => PropValue::Boolean(r.u16()? != 0),
        PT_SYSTIME => PropValue::SysTime(r.u64()?),
        PT_UNICODE => {
            let length = r.u16()? as i16;
            if length < 2 || length % 2 != 0 {
                return Err(malformed(format!("text literal length {length}")));
            }
            let raw = r.take(length as usize)?;
            let units: Vec<u16> = raw
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            if units.last() != Some(&0) || units[..units.len() - 1].contains(&0) {
                return Err(malformed("text literal NUL terminator"));
            }
            PropValue::Unicode(
                String::from_utf16(&units[..units.len() - 1])
                    .map_err(|_| malformed("text literal UTF-16"))?,
            )
        }
        other => {
            return Err(Error::Unsupported(format!("literal type {other:#06x}")));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::restriction::{bitmap, fuzzy, relop};

    fn sample() -> Definition {
        Definition {
            storage_type: storage::DEFAULT | storage::NUMBER | storage::TEXT,
            number_value: 42,
            text_value: "alpha;beta".into(),
            deep: true,
            scope: vec![vec![0xAA; 46], vec![0xBB; 46]],
            restriction: Restriction::And(vec![
                Restriction::Or(vec![
                    Restriction::Bitmask {
                        relop: bitmap::EQZ,
                        tag: 0x0E07_0003,
                        mask: 0x1,
                    },
                    Restriction::Bitmask {
                        relop: bitmap::NEZ,
                        tag: 0x0E06_0003,
                        mask: 0x4,
                    },
                ]),
                Restriction::Not(Box::new(Restriction::Content {
                    fuzzy_low: fuzzy::PREFIX,
                    fuzzy_high: fuzzy::IGNORECASE,
                    tag: 0x001A_001F,
                    value: PropValue::Unicode("IPM.Sample".into()),
                })),
                Restriction::Property {
                    relop: relop::GT,
                    tag: 0x0E08_0003,
                    value: PropValue::I32(4_096),
                },
                Restriction::Exist { tag: 0x0003_101F },
                Restriction::Content {
                    fuzzy_low: fuzzy::FULLSTRING,
                    fuzzy_high: fuzzy::IGNORECASE,
                    tag: 0x0003_101F,
                    value: PropValue::Unicode("alpha".into()),
                },
                Restriction::Property {
                    relop: relop::LT,
                    tag: 0x0E06_0040,
                    value: PropValue::SysTime(0x01DA_0000_0000_0000),
                },
                Restriction::Property {
                    relop: relop::EQ,
                    tag: 0x0E1B_000B,
                    value: PropValue::Boolean(true),
                },
            ]),
        }
    }

    #[test]
    fn round_trip() {
        let def = sample();
        let bytes = def.encode().unwrap();
        assert_eq!(Definition::decode(&bytes).unwrap(), def);
    }

    #[test]
    fn header_and_entrylist_layout() {
        let def = Definition::new(
            false,
            vec![vec![1, 2, 3]],
            Restriction::Exist { tag: 0x0037_001F },
        );
        let bytes = def.encode().unwrap();
        let mut expected = Vec::new();
        for w in [0x1004u32, 0x48, 0] {
            expected.extend_from_slice(&w.to_le_bytes());
        }
        expected.push(0);
        expected.extend_from_slice(&0u32.to_le_bytes());
        expected.extend_from_slice(&0u32.to_le_bytes()); // shallow
        expected.push(0);
        for w in [8u32 + 8 + 3, 1, 0, 3, 0] {
            expected.extend_from_slice(&w.to_le_bytes());
        }
        expected.extend_from_slice(&[1, 2, 3]);
        for w in [0u32, 8, 0x0037_001F, 0] {
            expected.extend_from_slice(&w.to_le_bytes());
        }
        assert_eq!(bytes, expected);
    }

    #[test]
    fn rejects_unsupported() {
        let def = Definition::new(
            true,
            vec![vec![1]],
            Restriction::Size {
                relop: relop::GT,
                tag: 0x0E08_0003,
                size: 4,
            },
        );
        assert!(def.encode().is_err());
        let binary = Definition {
            storage_type: storage::DEFAULT | storage::BINARY,
            ..sample()
        };
        assert!(binary.encode().is_err());
        let empty = Definition {
            scope: vec![],
            ..sample()
        };
        assert!(empty.encode().is_err());
    }

    #[test]
    fn long_string_uses_word_count() {
        let def = Definition {
            text_value: "x".repeat(300),
            ..sample()
        };
        let bytes = def.encode().unwrap();
        // version, storage type, number_value, then 0xFF + WORD 300.
        assert_eq!(&bytes[12..15], &[0xFF, 0x2C, 0x01]);
        assert_eq!(Definition::decode(&bytes).unwrap(), def);
    }

    #[test]
    fn rejects_trailing_and_bad_header() {
        let mut bytes = sample().encode().unwrap();
        bytes.push(0);
        assert!(Definition::decode(&bytes).is_err());
        let mut bytes = sample().encode().unwrap();
        bytes[0] = 0x05;
        assert!(Definition::decode(&bytes).is_err());
    }
}
