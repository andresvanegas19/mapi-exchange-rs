// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! MAPI constants from `outlook-mapi-sys`, used without loading MAPI or logging on.
//!
//! The local constants in [`crate::props`], [`crate::restriction`] and [`crate::rop`] stay
//! portable. The compile-time checks below make sure they match the MAPI SDK values.

use outlook_mapi_sys::Microsoft::Office::Outlook::MAPI::Win32 as sys;

use crate::{props::tags, props::types, restriction, rop::search_flags};

macro_rules! same {
    ($($local:expr => $sys:expr),* $(,)?) => {
        $(const _: () = assert!($local as u64 == $sys as u64);)*
    };
}

same! {
    tags::PR_DISPLAY_NAME_W => sys::PR_DISPLAY_NAME_W,
    tags::PR_ENTRYID => sys::PR_ENTRYID,
    tags::PR_MESSAGE_CLASS_W => sys::PR_MESSAGE_CLASS_W,
    tags::PR_SUBJECT_W => sys::PR_SUBJECT_W,
    tags::PR_FOLDER_TYPE => sys::PR_FOLDER_TYPE,
    tags::PR_CONTENT_COUNT => sys::PR_CONTENT_COUNT,
    tags::PR_CONTAINER_CLASS_W => sys::PR_CONTAINER_CLASS_W,
    tags::PR_LAST_MODIFICATION_TIME => sys::PR_LAST_MODIFICATION_TIME,

    types::I32 => sys::PT_LONG,
    types::BOOLEAN => sys::PT_BOOLEAN,
    types::I64 => sys::PT_I8,
    types::UNICODE => sys::PT_UNICODE,
    types::SYSTIME => sys::PT_SYSTIME,
    types::BINARY => sys::PT_BINARY,
    types::MULTI => sys::MV_FLAG,

    restriction::relop::LT => sys::RELOP_LT,
    restriction::relop::EQ => sys::RELOP_EQ,
    restriction::relop::RE => sys::RELOP_RE,
    restriction::bitmap::EQZ => sys::BMR_EQZ,
    restriction::bitmap::NEZ => sys::BMR_NEZ,
    restriction::fuzzy::FULLSTRING => sys::FL_FULLSTRING,
    restriction::fuzzy::SUBSTRING => sys::FL_SUBSTRING,
    restriction::fuzzy::PREFIX => sys::FL_PREFIX,
    // The SDK keeps the fuzzy-level flags in the high word; the wire format uses the low bits.
    restriction::fuzzy::IGNORECASE => (sys::FL_IGNORECASE >> 16),
    restriction::fuzzy::IGNORENONSPACE => (sys::FL_IGNORENONSPACE >> 16),
    restriction::fuzzy::LOOSE => (sys::FL_LOOSE >> 16),

    search_flags::STOP_SEARCH => sys::STOP_SEARCH,
    search_flags::RESTART_SEARCH => sys::RESTART_SEARCH,
    search_flags::RECURSIVE_SEARCH => sys::RECURSIVE_SEARCH,
    search_flags::SHALLOW_SEARCH => sys::SHALLOW_SEARCH,
}

#[cfg(test)]
mod tests {
    use super::sys;

    #[test]
    fn public_strings_guid_matches() {
        let g = sys::PS_PUBLIC_STRINGS;
        let mut bytes = Vec::with_capacity(16);
        bytes.extend_from_slice(&g.data1.to_le_bytes());
        bytes.extend_from_slice(&g.data2.to_le_bytes());
        bytes.extend_from_slice(&g.data3.to_le_bytes());
        bytes.extend_from_slice(&g.data4);
        assert_eq!(bytes, crate::client::PS_PUBLIC_STRINGS);
    }
}
