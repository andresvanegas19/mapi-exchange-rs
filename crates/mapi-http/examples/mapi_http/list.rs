// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::{common, describe};
use outlook_mapi_http::{Definition, Result, Session, SfInfo};

pub fn run() -> Result<()> {
    let mut session = common::open()?;
    let result = inspect(&mut session);
    let disconnect = session.disconnect();
    result.and(disconnect)
}

fn inspect(session: &mut Session) -> Result<()> {
    let sfinfo = session.list_sfinfo()?;
    for f in session.list_search_folders()? {
        println!("search folder 0x{:016x} {:?}", f.folder_id, f.display_name);
        // The display name is a diagnostic association, not a persistent identity link.
        let matches: Vec<_> = sfinfo
            .iter()
            .filter(|sf| {
                sf.subject
                    .as_deref()
                    .is_some_and(|subject| subject.eq_ignore_ascii_case(&f.display_name))
            })
            .collect();
        if matches.is_empty() {
            println!("  SFInfo: no subject/name match; template/storage/parameters unknown");
        }
        for sf in matches {
            metadata(sf);
        }
        if let Some(criteria) = &f.criteria {
            println!(
                "  live criteria: flags=0x{:08x} scope={:x?}",
                criteria.flags, criteria.folder_ids
            );
            if let Some(restriction) = &criteria.restriction {
                print!("{}", describe::tree(restriction, 2));
            }
        } else {
            println!("  live criteria: unavailable");
        }
    }
    for sf in sfinfo {
        println!(
            "sfinfo 0x{:016x} display_name={:?} sf_id={}",
            sf.message_id,
            sf.subject,
            sf.sf_id.as_deref().map(common::hex).unwrap_or_default()
        );
        metadata(&sf);
    }
    Ok(())
}

fn metadata(sf: &SfInfo) {
    println!("  template={}", describe::template(sf.template_id));
    if let Some(blob) = &sf.definition {
        match Definition::decode(blob) {
            Ok(def) => {
                println!(
                    "  storage={} number={} text={:?}",
                    describe::storage_flags(def.storage_type),
                    def.number_value,
                    def.text_value
                );
                println!(
                    "  definition: deep={} scope={} EntryID(s)",
                    def.deep,
                    def.scope.len()
                );
                print!("{}", describe::tree(&def.restriction, 2));
            }
            Err(error) => println!("  definition: {} bytes, not decoded: {error}", blob.len()),
        }
    } else {
        println!("  definition: missing");
    }
}
