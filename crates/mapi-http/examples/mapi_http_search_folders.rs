// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Read-only MAPI/HTTP search folder inspector. Credentials are read only from environment variables.
//! See `mapi_http_search_folders --help` for commands; --blob is entirely offline.

#[path = "mapi_http/args.rs"]
mod args;
#[path = "mapi_http/common.rs"]
mod common;
#[path = "mapi_http/describe.rs"]
mod describe;
#[path = "mapi_http/list.rs"]
mod list;
#[path = "mapi_http/tags.rs"]
mod tags;

use outlook_mapi_http::Result;

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match args::parse(std::env::args().skip(1).collect())? {
        args::Command::Help => {
            println!("{}", args::USAGE);
            Ok(())
        }
        args::Command::Blob => common::blob(),
        args::Command::Probe => common::open()?.disconnect(),
        args::Command::List => list::run(),
    }
}
