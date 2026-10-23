// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Little-endian byte helpers used by every wire structure.

use crate::error::{Result, malformed};

#[derive(Debug, Default, Clone)]
pub struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, value: u8) -> &mut Self {
        self.bytes.push(value);
        self
    }

    pub fn u16(&mut self, value: u16) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn u32(&mut self, value: u32) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn u64(&mut self, value: u64) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    pub fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.bytes.extend_from_slice(value);
        self
    }

    /// Null-terminated 8-bit string.
    pub fn asciiz(&mut self, value: &str) -> &mut Self {
        self.bytes.extend_from_slice(value.as_bytes());
        self.bytes.push(0);
        self
    }

    /// Null-terminated UTF-16LE string.
    pub fn utf16z(&mut self, value: &str) -> &mut Self {
        for unit in value.encode_utf16() {
            self.u16(unit);
        }
        self.u16(0)
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Overwrite a previously written u16 (used for back-patched sizes).
    pub fn patch_u16(&mut self, offset: usize, value: u16) {
        self.bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(count)
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| {
                malformed(format!(
                    "need {count} bytes at offset {}, have {}",
                    self.position,
                    self.remaining()
                ))
            })?;
        let slice = &self.bytes[self.position..end];
        self.position = end;
        Ok(slice)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }

    pub fn asciiz(&mut self) -> Result<String> {
        let rest = &self.bytes[self.position..];
        let end = rest
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| malformed("unterminated 8-bit string"))?;
        let text = String::from_utf8_lossy(&rest[..end]).into_owned();
        self.position += end + 1;
        Ok(text)
    }

    pub fn utf16z(&mut self) -> Result<String> {
        let mut units = Vec::new();
        loop {
            match self.u16()? {
                0 => break,
                unit => units.push(unit),
            }
        }
        Ok(String::from_utf16_lossy(&units))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_roundtrip() {
        let mut writer = Writer::new();
        writer.asciiz("/o=Org").utf16z("Búsqueda").u32(7);
        let bytes = writer.into_bytes();
        let mut reader = Reader::new(&bytes);
        assert_eq!(reader.asciiz().unwrap(), "/o=Org");
        assert_eq!(reader.utf16z().unwrap(), "Búsqueda");
        assert_eq!(reader.u32().unwrap(), 7);
        assert!(reader.is_empty());
    }

    #[test]
    fn truncated_read_fails() {
        let mut reader = Reader::new(&[1, 2, 3]);
        assert!(reader.u32().is_err());
    }
}
