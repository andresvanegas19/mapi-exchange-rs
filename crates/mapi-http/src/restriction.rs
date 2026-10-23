// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Restriction wire format used by RopSetSearchCriteria / RopGetSearchCriteria
//! (MS-OXCDATA 2.12, standard ROP encoding: 16-bit counts).

use crate::codec::{Reader, Writer};
use crate::error::{Result, malformed};
use crate::props::{PropValue, read_tagged, write_tagged};

pub mod relop {
    pub const LT: u8 = 0x00;
    pub const LE: u8 = 0x01;
    pub const GT: u8 = 0x02;
    pub const GE: u8 = 0x03;
    pub const EQ: u8 = 0x04;
    pub const NE: u8 = 0x05;
    pub const RE: u8 = 0x06;
    pub const MEMBER_OF_DL: u8 = 0x64;
}

pub mod fuzzy {
    pub const FULLSTRING: u16 = 0x0000;
    pub const SUBSTRING: u16 = 0x0001;
    pub const PREFIX: u16 = 0x0002;
    pub const IGNORECASE: u16 = 0x0001;
    pub const IGNORENONSPACE: u16 = 0x0002;
    pub const LOOSE: u16 = 0x0004;
}

pub mod bitmap {
    pub const EQZ: u8 = 0x00;
    pub const NEZ: u8 = 0x01;
}

#[derive(Debug, Clone, PartialEq)]
pub enum Restriction {
    And(Vec<Restriction>),
    Or(Vec<Restriction>),
    Not(Box<Restriction>),
    Content {
        fuzzy_low: u16,
        fuzzy_high: u16,
        tag: u32,
        value: PropValue,
    },
    Property {
        relop: u8,
        tag: u32,
        value: PropValue,
    },
    CompareProps {
        relop: u8,
        tag1: u32,
        tag2: u32,
    },
    Bitmask {
        relop: u8,
        tag: u32,
        mask: u32,
    },
    Size {
        relop: u8,
        tag: u32,
        size: u32,
    },
    Exist {
        tag: u32,
    },
    SubObject {
        subobject: u32,
        restriction: Box<Restriction>,
    },
    Comment {
        values: Vec<(u32, PropValue)>,
        restriction: Option<Box<Restriction>>,
    },
    Count {
        count: u32,
        restriction: Box<Restriction>,
    },
}

const AND: u8 = 0x00;
const OR: u8 = 0x01;
const NOT: u8 = 0x02;
const CONTENT: u8 = 0x03;
const PROPERTY: u8 = 0x04;
const COMPARE: u8 = 0x05;
const BITMASK: u8 = 0x06;
const SIZE: u8 = 0x07;
const EXIST: u8 = 0x08;
const SUBOBJECT: u8 = 0x09;
const COMMENT: u8 = 0x0A;
const COUNT: u8 = 0x0B;

impl Restriction {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut writer = Writer::new();
        self.write(&mut writer)?;
        Ok(writer.into_bytes())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes);
        let restriction = Self::read(&mut reader, 0)?;
        if !reader.is_empty() {
            return Err(malformed(format!(
                "{} trailing bytes after restriction",
                reader.remaining()
            )));
        }
        Ok(restriction)
    }

    pub fn write(&self, writer: &mut Writer) -> Result<()> {
        match self {
            Self::And(children) | Self::Or(children) => {
                writer.u8(if matches!(self, Self::And(_)) {
                    AND
                } else {
                    OR
                });
                let count = u16::try_from(children.len())
                    .map_err(|_| malformed("too many sub-restrictions"))?;
                writer.u16(count);
                for child in children {
                    child.write(writer)?;
                }
            }
            Self::Not(child) => {
                writer.u8(NOT);
                child.write(writer)?;
            }
            Self::Content {
                fuzzy_low,
                fuzzy_high,
                tag,
                value,
            } => {
                writer
                    .u8(CONTENT)
                    .u16(*fuzzy_low)
                    .u16(*fuzzy_high)
                    .u32(*tag);
                // On a multivalue tag (Keywords) the
                // literal is a single value, so its tag drops the MV flag.
                write_tagged(writer, *tag & !0x1000, value)?;
            }
            Self::Property { relop, tag, value } => {
                writer.u8(PROPERTY).u8(*relop).u32(*tag);
                write_tagged(writer, *tag, value)?;
            }
            Self::CompareProps { relop, tag1, tag2 } => {
                writer.u8(COMPARE).u8(*relop).u32(*tag1).u32(*tag2);
            }
            Self::Bitmask { relop, tag, mask } => {
                writer.u8(BITMASK).u8(*relop).u32(*tag).u32(*mask);
            }
            Self::Size { relop, tag, size } => {
                writer.u8(SIZE).u8(*relop).u32(*tag).u32(*size);
            }
            Self::Exist { tag } => {
                writer.u8(EXIST).u32(*tag);
            }
            Self::SubObject {
                subobject,
                restriction,
            } => {
                writer.u8(SUBOBJECT).u32(*subobject);
                restriction.write(writer)?;
            }
            Self::Comment {
                values,
                restriction,
            } => {
                let count =
                    u8::try_from(values.len()).map_err(|_| malformed("too many comment values"))?;
                writer.u8(COMMENT).u8(count);
                for (tag, value) in values {
                    write_tagged(writer, *tag, value)?;
                }
                match restriction {
                    Some(child) => {
                        writer.u8(1);
                        child.write(writer)?;
                    }
                    None => {
                        writer.u8(0);
                    }
                }
            }
            Self::Count { count, restriction } => {
                writer.u8(COUNT).u32(*count);
                restriction.write(writer)?;
            }
        }
        Ok(())
    }

    pub fn read(reader: &mut Reader, depth: usize) -> Result<Self> {
        if depth > 255 {
            return Err(malformed("restriction nested too deeply"));
        }
        let next = |reader: &mut Reader| Self::read(reader, depth + 1).map(Box::new);
        Ok(match reader.u8()? {
            kind @ (AND | OR) => {
                let count = reader.u16()?;
                let children = (0..count)
                    .map(|_| Self::read(reader, depth + 1))
                    .collect::<Result<Vec<_>>>()?;
                if kind == AND {
                    Self::And(children)
                } else {
                    Self::Or(children)
                }
            }
            NOT => Self::Not(next(reader)?),
            CONTENT => {
                let fuzzy_low = reader.u16()?;
                let fuzzy_high = reader.u16()?;
                let tag = reader.u32()?;
                let (_, value) = read_tagged(reader)?;
                Self::Content {
                    fuzzy_low,
                    fuzzy_high,
                    tag,
                    value,
                }
            }
            PROPERTY => {
                let relop = reader.u8()?;
                let tag = reader.u32()?;
                let (_, value) = read_tagged(reader)?;
                Self::Property { relop, tag, value }
            }
            COMPARE => Self::CompareProps {
                relop: reader.u8()?,
                tag1: reader.u32()?,
                tag2: reader.u32()?,
            },
            BITMASK => Self::Bitmask {
                relop: reader.u8()?,
                tag: reader.u32()?,
                mask: reader.u32()?,
            },
            SIZE => Self::Size {
                relop: reader.u8()?,
                tag: reader.u32()?,
                size: reader.u32()?,
            },
            EXIST => Self::Exist { tag: reader.u32()? },
            SUBOBJECT => Self::SubObject {
                subobject: reader.u32()?,
                restriction: next(reader)?,
            },
            COMMENT => {
                let count = reader.u8()?;
                let values = (0..count)
                    .map(|_| read_tagged(reader))
                    .collect::<Result<Vec<_>>>()?;
                let restriction = match reader.u8()? {
                    0 => None,
                    _ => Some(next(reader)?),
                };
                Self::Comment {
                    values,
                    restriction,
                }
            }
            COUNT => Self::Count {
                count: reader.u32()?,
                restriction: next(reader)?,
            },
            other => return Err(malformed(format!("restriction type 0x{other:02x}"))),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::props::tags;

    const PR_FLAG_STATUS: u32 = 0x1090_0003;
    const PR_MESSAGE_FLAGS: u32 = 0x0E07_0003;

    #[test]
    fn bitmask_bytes() {
        // Bitmask EQZ on PR_MESSAGE_FLAGS & MSGFLAG_READ.
        let restriction = Restriction::Bitmask {
            relop: bitmap::EQZ,
            tag: PR_MESSAGE_FLAGS,
            mask: 1,
        };
        assert_eq!(
            restriction.encode().unwrap(),
            vec![0x06, 0x00, 0x03, 0x00, 0x07, 0x0E, 0x01, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn nested_roundtrip() {
        let restriction = Restriction::And(vec![
            Restriction::Exist {
                tag: PR_FLAG_STATUS,
            },
            Restriction::Property {
                relop: relop::EQ,
                tag: PR_FLAG_STATUS,
                value: PropValue::I32(2),
            },
            Restriction::Content {
                fuzzy_low: fuzzy::SUBSTRING,
                fuzzy_high: fuzzy::IGNORECASE,
                tag: tags::PR_SUBJECT_W,
                value: PropValue::Unicode("invoice".into()),
            },
            Restriction::Not(Box::new(Restriction::Comment {
                values: vec![(0x6000_001F, PropValue::Unicode("tag".into()))],
                restriction: Some(Box::new(Restriction::Size {
                    relop: relop::GT,
                    tag: 0x0E08_0003,
                    size: 4,
                })),
            })),
            Restriction::SubObject {
                subobject: 0x0E13_000D,
                restriction: Box::new(Restriction::Count {
                    count: 1,
                    restriction: Box::new(Restriction::CompareProps {
                        relop: relop::NE,
                        tag1: 1,
                        tag2: 2,
                    }),
                }),
            },
        ]);
        let bytes = restriction.encode().unwrap();
        assert_eq!(Restriction::decode(&bytes).unwrap(), restriction);
    }

    #[test]
    fn trailing_bytes_rejected() {
        assert!(Restriction::decode(&[0x08, 1, 0, 0, 0, 0xFF]).is_err());
    }
}
