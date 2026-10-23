// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

/// Errors returned by the MAPI/HTTP client.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("HTTP transport error: {0}")]
    Http(String),

    #[error("HTTP status {status} for {request_type} (X-ResponseCode: {response_code:?})")]
    HttpStatus {
        status: u16,
        request_type: &'static str,
        response_code: Option<u32>,
        authenticate: Option<String>,
    },

    #[error("{request_type} failed with X-ResponseCode {code} ({name}){}", description.as_deref().map(|d| format!(": {d}")).unwrap_or_default())]
    ResponseCode {
        request_type: &'static str,
        code: u32,
        name: &'static str,
        description: Option<String>,
    },

    #[error("{request_type} failed with StatusCode 0x{status:08x}, ErrorCode 0x{error:08x}")]
    Status {
        request_type: &'static str,
        status: u32,
        error: u32,
    },

    #[error("{rop} failed with 0x{code:08x} ({name})")]
    Rop {
        rop: &'static str,
        code: u32,
        name: &'static str,
    },

    #[error("malformed data: {0}")]
    Malformed(String),

    #[error("unsupported: {0}")]
    Unsupported(String),

    #[error("configuration: {0}")]
    Config(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn malformed(message: impl Into<String>) -> Error {
    Error::Malformed(message.into())
}

/// Names for the X-ResponseCode values defined in MS-OXCMAPIHTTP section 2.2.3.3.3.
pub fn response_code_name(code: u32) -> &'static str {
    match code {
        0 => "Success",
        1 => "Unknown Failure",
        2 => "Invalid Verb",
        3 => "Invalid Path",
        4 => "Invalid Header",
        5 => "Invalid Request Type",
        6 => "Invalid Context Cookie",
        7 => "Missing Header",
        8 => "Anonymous Not Allowed",
        9 => "Too Large",
        10 => "Context Not Found",
        11 => "No Privilege",
        12 => "Invalid Request Body",
        13 => "Missing Cookie",
        15 => "Invalid Sequence",
        16 => "Endpoint Disabled",
        17 => "Invalid Response",
        18 => "Endpoint Shutting Down",
        _ => "Unknown",
    }
}

/// Names for common MAPI error codes (MS-OXCDATA section 2.4).
pub fn error_code_name(code: u32) -> &'static str {
    match code {
        0x0000_0000 => "Success",
        0x0000_0478 => "ecWrongServer",
        0x0000_04B9 => "ecNullObject",
        0x0000_04D3 => "ecRpcFormat",
        0x0000_0505 => "ecBufferTooSmall",
        0x0000_0461 => "ecUnknownUser",
        0x0000_03EB => "ecLoginFailure",
        0x0000_0970 => "ecSearchFolderScopeViolation",
        0x0004_0380 => "MAPI_W_ERRORS_RETURNED",
        0x8000_4005 => "MAPI_E_CALL_FAILED",
        0x8004_0102 => "MAPI_E_NO_SUPPORT",
        0x8004_0106 => "MAPI_E_UNKNOWN_FLAGS",
        0x8004_010F => "MAPI_E_NOT_FOUND",
        0x8004_0111 => "MAPI_E_LOGON_FAILED",
        0x8004_0113 => "MAPI_E_USER_CANCEL",
        0x8004_0115 => "MAPI_E_NETWORK_ERROR",
        0x8004_0117 => "MAPI_E_TOO_COMPLEX",
        0x8004_011B => "MAPI_E_CORRUPT_DATA",
        0x8004_0301 => "MAPI_E_BAD_VALUE",
        0x8004_0302 => "MAPI_E_INVALID_TYPE",
        0x8004_0303 => "MAPI_E_TYPE_NO_SUPPORT",
        0x8004_0604 => "MAPI_E_COLLISION",
        0x8004_0605 => "MAPI_E_NOT_INITIALIZED",
        0x8007_0005 => "MAPI_E_NO_ACCESS",
        0x8007_000E => "MAPI_E_NOT_ENOUGH_MEMORY",
        0x8007_0057 => "MAPI_E_INVALID_PARAMETER",
        _ => "unknown",
    }
}
