// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use outlook_mapi_http::{Error, Result};

pub const USAGE: &str = "usage: mapi_http_search_folders --blob | --probe | --list
       mapi_http_search_folders --help

--blob   encode and decode a sample search folder definition (offline)
--probe  connect, log on, and disconnect
--list   list search folders and their SFInfo definitions (read-only)
Environment: MAPI_HTTP_MAPI_URL, MAPI_HTTP_USER, MAPI_HTTP_PASSWORD, MAPI_HTTP_USER_DN;
             optional MAPI_HTTP_CLIENT_APPLICATION and MAPI_HTTP_INSECURE_TLS=1 (test boxes only).";

#[derive(Debug, PartialEq)]
pub enum Command {
    Help,
    Blob,
    Probe,
    List,
}

pub fn parse(args: Vec<String>) -> Result<Command> {
    let Some(mode) = args.first().map(String::as_str) else {
        return Ok(Command::Help);
    };
    if args.len() != 1 {
        return Err(config("unexpected arguments"));
    }
    match mode {
        "--help" | "-h" => Ok(Command::Help),
        "--blob" => Ok(Command::Blob),
        "--probe" => Ok(Command::Probe),
        "--list" => Ok(Command::List),
        _ => Err(config("unknown command; use --help")),
    }
}

fn config(message: &str) -> Error {
    Error::Config(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn command(args: &[&str]) -> Result<Command> {
        parse(args.iter().map(|s| s.to_string()).collect())
    }
    #[test]
    fn parses_commands() {
        assert_eq!(command(&[]).unwrap(), Command::Help);
        assert_eq!(command(&["--list"]).unwrap(), Command::List);
        assert_eq!(command(&["--probe"]).unwrap(), Command::Probe);
    }
    #[test]
    fn rejects_invalid_options_before_connecting() {
        for args in [
            vec!["--create"],
            vec!["--probe", "--force"],
            vec!["--list", "x"],
        ] {
            assert!(command(&args).is_err());
        }
    }
}
