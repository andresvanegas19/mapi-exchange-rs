// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::tags;
use outlook_mapi_http::{Restriction, sfinfo::storage};
use std::fmt::Write;

pub fn template(id: Option<i32>) -> String {
    id.map(|id| id.to_string())
        .unwrap_or_else(|| "unknown".into())
}

pub fn storage_flags(bits: u32) -> String {
    let mut remaining = bits;
    let mut names = Vec::new();
    for (mask, name) in [
        (storage::NUMBER, "NUMBER"),
        (storage::TEXT, "TEXT"),
        (storage::BINARY, "BINARY"),
        (storage::MRES, "MRES"),
        (storage::FILTERSTREAM, "FILTERSTREAM"),
        (storage::FOLDERNAME, "FOLDERNAME"),
        (storage::FOLDERLIST, "FOLDERLIST"),
        (storage::REFRESH_DAILY, "DAILY"),
        (storage::REFRESH_WEEKLY, "WEEKLY"),
        (storage::REFRESH_MONTHLY, "MONTHLY"),
    ] {
        if bits & mask != 0 {
            names.push(name.to_owned());
            remaining &= !mask;
        }
    }
    if remaining != 0 {
        names.push(format!("0x{remaining:08x}"));
    }
    format!("0x{bits:08x} ({})", names.join("|"))
}

pub fn tree(restriction: &Restriction, depth: usize) -> String {
    let mut output = String::new();
    render(restriction, depth, &mut output);
    output
}

fn render(r: &Restriction, depth: usize, out: &mut String) {
    use Restriction::*;
    let indent = "  ".repeat(depth);
    let label = match r {
        And(_) => "AND".into(),
        Or(_) => "OR".into(),
        Not(_) => "NOT".into(),
        Content {
            fuzzy_low,
            fuzzy_high,
            tag,
            value,
        } => format!(
            "CONTENT {} {} {value:?}",
            tags::name(*tag),
            fuzzy(*fuzzy_low, *fuzzy_high)
        ),
        Property {
            relop: op,
            tag,
            value,
        } => format!("PROPERTY {} {} {value:?}", tags::name(*tag), relop(*op)),
        CompareProps {
            relop: op,
            tag1,
            tag2,
        } => format!(
            "COMPARE {} {} {}",
            tags::name(*tag1),
            relop(*op),
            tags::name(*tag2)
        ),
        Bitmask { relop, tag, mask } => format!(
            "BITMASK {} {} 0x{mask:08x}",
            tags::name(*tag),
            match relop {
                0 => "EQZ".into(),
                1 => "NEZ".into(),
                other => format!("0x{other:02x}"),
            }
        ),
        Size {
            relop: op,
            tag,
            size,
        } => format!("SIZE {} {} {size}", tags::name(*tag), relop(*op)),
        Exist { tag } => format!("EXIST {}", tags::name(*tag)),
        SubObject { subobject, .. } => format!("SUBOBJECT {}", tags::name(*subobject)),
        Comment { values, .. } => format!(
            "COMMENT {}",
            values
                .iter()
                .map(|(tag, value)| format!("{}={value:?}", tags::name(*tag)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Count { count, .. } => format!("COUNT {count}"),
    };
    let _ = writeln!(out, "{indent}{label}");
    match r {
        And(children) | Or(children) => {
            for child in children {
                render(child, depth + 1, out);
            }
        }
        Not(child)
        | SubObject {
            restriction: child, ..
        }
        | Count {
            restriction: child, ..
        } => render(child, depth + 1, out),
        Comment {
            restriction: Some(child),
            ..
        } => render(child, depth + 1, out),
        _ => (),
    }
}

fn relop(value: u8) -> String {
    match value {
        0 => "LT".into(),
        1 => "LE".into(),
        2 => "GT".into(),
        3 => "GE".into(),
        4 => "EQ".into(),
        5 => "NE".into(),
        6 => "RE".into(),
        0x64 => "MEMBER_OF_DL".into(),
        _ => format!("0x{value:02x}"),
    }
}

fn fuzzy(low: u16, high: u16) -> String {
    let mut names = vec![match low {
        0 => "FULLSTRING".into(),
        1 => "SUBSTRING".into(),
        2 => "PREFIX".into(),
        _ => format!("0x{low:04x}"),
    }];
    for (mask, name) in [(1, "IGNORECASE"), (2, "IGNORENONSPACE"), (4, "LOOSE")] {
        if high & mask != 0 {
            names.push(name.into());
        }
    }
    if high & !7 != 0 {
        names.push(format!("0x{:04x}", high & !7));
    }
    names.join("|")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn describes_flags_and_named_property_tree() {
        assert_eq!(
            storage_flags(storage::DEFAULT | storage::REFRESH_DAILY),
            "0x00004048 (MRES|FOLDERLIST|DAILY)"
        );
        let output = tree(
            &Restriction::And(vec![Restriction::Exist { tag: 0x8000_101f }]),
            1,
        );
        assert_eq!(output, "  AND\n    EXIST 0x8000101f\n");
        assert_eq!(template(Some(7)), "7");
        assert!(tags::name(0x0037_001f).starts_with("PR_SUBJECT_W"));
        assert_eq!(fuzzy(1, 1), "SUBSTRING|IGNORECASE");
        assert_eq!(relop(4), "EQ");
    }
}
