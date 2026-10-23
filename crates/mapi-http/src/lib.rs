// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Outlook-free MAPI over HTTP client (clean-room from MS-OXCMAPIHTTP, MS-OXCROPS, MS-OXCDATA).
//!
//! Layers: [`transport`] (HTTPS + cookies) -> [`emsmdb`] (Connect/Execute/Disconnect bodies)
//! -> [`rop`] (ROP buffers) -> [`client::Session`] (folder and search folder helpers).

pub mod client;
pub mod codec;
pub mod emsmdb;
pub mod error;
pub mod props;
pub mod restriction;
pub mod rop;
pub mod sfinfo;
pub mod transport;

pub use client::{FolderInfo, Session, SfInfo};
pub use error::{Error, Result};
pub use props::PropValue;
pub use restriction::Restriction;
pub use sfinfo::Definition;
pub use transport::Config;
