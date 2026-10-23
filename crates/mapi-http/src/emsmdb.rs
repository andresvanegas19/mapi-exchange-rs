// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! EMSMDB request/response bodies for MAPI over HTTP (MS-OXCMAPIHTTP 2.2.4).

use crate::codec::{Reader, Writer};
use crate::error::{Error, Result, malformed, response_code_name};

pub mod execute_flags {
    pub const NO_COMPRESSION: u32 = 0x0000_0001;
    pub const NO_XOR_MAGIC: u32 = 0x0000_0002;
    pub const CHAIN: u32 = 0x0000_0004;
}

#[derive(Debug, Clone)]
pub struct ConnectRequest {
    pub user_dn: String,
    pub flags: u32,
    pub code_page: u32,
    pub lcid_sort: u32,
    pub lcid_string: u32,
}

impl ConnectRequest {
    pub fn new(user_dn: impl Into<String>) -> Self {
        Self {
            user_dn: user_dn.into(),
            flags: 0,
            code_page: 1252,
            lcid_sort: 0x0409,
            lcid_string: 0x0409,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.asciiz(&self.user_dn)
            .u32(self.flags)
            .u32(self.code_page)
            .u32(self.lcid_sort)
            .u32(self.lcid_string)
            .u32(0);
        w.into_bytes()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ConnectResponse {
    pub max_polling_interval: u32,
    pub retry_count: u32,
    pub retry_delay: u32,
    pub dn_prefix: String,
    pub display_name: String,
}

impl ConnectResponse {
    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body);
        check_status(&mut r, "Connect")?;
        Ok(Self {
            max_polling_interval: r.u32()?,
            retry_count: r.u32()?,
            retry_delay: r.u32()?,
            dn_prefix: r.asciiz()?,
            display_name: r.utf16z()?,
        })
    }
}

pub fn encode_execute(rop_buffer: &[u8], max_rop_out: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u32(execute_flags::NO_COMPRESSION | execute_flags::NO_XOR_MAGIC)
        .u32(rop_buffer.len() as u32)
        .bytes(rop_buffer)
        .u32(max_rop_out)
        .u32(0);
    w.into_bytes()
}

/// Returns the response RopBuffer.
pub fn decode_execute(body: &[u8]) -> Result<Vec<u8>> {
    let mut r = Reader::new(body);
    check_status(&mut r, "Execute")?;
    let _flags = r.u32()?;
    let size = r.u32()? as usize;
    Ok(r.take(size)?.to_vec())
}

pub fn encode_disconnect() -> Vec<u8> {
    0u32.to_le_bytes().to_vec()
}

pub fn decode_disconnect(body: &[u8]) -> Result<()> {
    check_status(&mut Reader::new(body), "Disconnect")
}

fn check_status(r: &mut Reader, request_type: &'static str) -> Result<()> {
    let status = r.u32()?;
    let error = r.u32()?;
    if status != 0 || error != 0 {
        return Err(Error::Status {
            request_type,
            status,
            error,
        });
    }
    Ok(())
}

/// Parsed MAPI/HTTP response: meta-tags, trailing headers and binary body (MS-OXCMAPIHTTP 2.2.2.2).
#[derive(Debug, Clone, PartialEq)]
pub struct Framed {
    pub meta: Vec<String>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Framed {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn response_code(&self) -> Option<u32> {
        self.header("X-ResponseCode")
            .and_then(|v| v.trim().parse().ok())
    }

    pub fn check(&self, request_type: &'static str) -> Result<()> {
        match self.response_code() {
            Some(0) | None => Ok(()),
            Some(code) => Err(Error::ResponseCode {
                request_type,
                code,
                name: response_code_name(code),
                description: self.header("X-FailureDescription").map(str::to_string),
            }),
        }
    }
}

/// Split `PROCESSING\r\n[PENDING\r\n]*DONE\r\nHeader: v\r\n...\r\n\r\n<binary>`.
pub fn parse_framed(bytes: &[u8]) -> Result<Framed> {
    let mut position = 0;
    let mut meta = Vec::new();
    let mut headers = Vec::new();
    let mut in_headers = false;
    loop {
        let rest = &bytes[position..];
        let end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| malformed("unterminated MAPI/HTTP response line"))?;
        let line = std::str::from_utf8(&rest[..end])
            .map_err(|_| malformed("non-UTF-8 MAPI/HTTP response line"))?
            .to_string();
        position += end + 2;
        if in_headers {
            if line.is_empty() {
                break;
            }
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| malformed(format!("bad trailing header {line:?}")))?;
            headers.push((name.trim().to_string(), value.trim().to_string()));
        } else {
            in_headers = line == "DONE";
            meta.push(line);
        }
    }
    Ok(Framed {
        meta,
        headers,
        body: bytes[position..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_request_bytes() {
        let bytes = ConnectRequest::new("/o=A").encode();
        assert_eq!(&bytes[..5], b"/o=A\0");
        assert_eq!(&bytes[5..9], &0u32.to_le_bytes());
        assert_eq!(&bytes[9..13], &1252u32.to_le_bytes());
        assert_eq!(bytes.len(), 5 + 20);
    }

    #[test]
    fn framed_connect_response() {
        let mut body = Writer::new();
        body.u32(0)
            .u32(0)
            .u32(60_000)
            .u32(6)
            .u32(10_000)
            .asciiz("/o=First Org")
            .utf16z("Test User")
            .u32(0);
        let mut wire =
            b"PROCESSING\r\nPENDING\r\nDONE\r\nX-ResponseCode: 0\r\nX-ElapsedTime: 5\r\n\r\n"
                .to_vec();
        wire.extend_from_slice(body.as_slice());
        let framed = parse_framed(&wire).unwrap();
        assert_eq!(framed.meta, ["PROCESSING", "PENDING", "DONE"]);
        framed.check("Connect").unwrap();
        let response = ConnectResponse::decode(&framed.body).unwrap();
        assert_eq!(response.dn_prefix, "/o=First Org");
        assert_eq!(response.display_name, "Test User");
    }

    #[test]
    fn non_zero_response_code_is_error() {
        let framed = parse_framed(b"PROCESSING\r\nDONE\r\nX-ResponseCode: 10\r\n\r\n").unwrap();
        let err = framed.check("Execute").unwrap_err().to_string();
        assert!(err.contains("Context Not Found"), "{err}");
    }

    #[test]
    fn execute_roundtrip() {
        let request = encode_execute(&[1, 2, 3], 0x1_0000);
        assert_eq!(&request[..4], &3u32.to_le_bytes());
        let mut body = Writer::new();
        body.u32(0).u32(0).u32(0).u32(2).bytes(&[9, 9]).u32(0);
        assert_eq!(decode_execute(body.as_slice()).unwrap(), vec![9, 9]);
    }
}
