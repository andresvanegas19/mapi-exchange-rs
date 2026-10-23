// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use outlook_mapi_http::{
    Config, Definition, Restriction, Result, Session, restriction::bitmap, rop::folder,
};

pub fn open() -> Result<Session> {
    let mut session = Session::connect(Config::from_env()?)?;
    println!(
        "connected: display_name={:?} dn_prefix={:?}",
        session.connect.display_name, session.connect.dn_prefix
    );
    session.logon()?;
    println!(
        "logon ok: inbox=0x{:016x} common_views=0x{:016x} finder=0x{:016x}",
        session.special_folder(folder::INBOX)?,
        session.special_folder(folder::COMMON_VIEWS)?,
        session.special_folder(folder::FINDER)?
    );
    Ok(session)
}

pub fn blob() -> Result<()> {
    // Sample restriction: PR_MESSAGE_FLAGS & MSGFLAG_READ == 0.
    let restriction = Restriction::Bitmask {
        relop: bitmap::EQZ,
        tag: 0x0E07_0003,
        mask: 0x0000_0001,
    };
    let definition = Definition::new(true, vec![vec![0u8; 46]], restriction);
    let bytes = definition.encode()?;
    println!("{} bytes\n{}", bytes.len(), hex(&bytes));
    assert_eq!(Definition::decode(&bytes)?, definition);
    println!("round-trip ok");
    Ok(())
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
