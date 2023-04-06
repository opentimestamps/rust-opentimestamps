// Copyright (C) The OpenTimestamps developers
//
// This file is part of rust-opentimestamps.
//
// It is subject to the license terms in the LICENSE file found in the
// top-level directory of this distribution.
//
// No part of rust-opentimestamps including this file, may be copied, modified,
// propagated, or distributed except according to the terms contained in the
// LICENSE file.

//! # OpenTimestamps Viewer
//!
//! Simple application to open an OTS info file and dump its contents
//! to stdout in a human-readable format
//!

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(missing_docs)]

extern crate env_logger;
extern crate opentimestamps as ots;

use std::{env, fs, process};

fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("Usage: {} <timestamp.ots>", args[0]);
        process::exit(1);
    }

    let fh = match fs::File::open(&args[1]) {
        Ok(fh) => fh,
        Err(e) => {
            println!("Failed to open {}: {}", args[1], e);
            process::exit(1);
        }
    };

    let ots = match ots::DetachedTimestampFile::from_reader(fh) {
        Ok(ots) => ots,
        Err(e) => {
            println!("Failed to parse {}: {}", args[1], e);
            process::exit(1);
        }
    };

    println!("{}", ots);
}

