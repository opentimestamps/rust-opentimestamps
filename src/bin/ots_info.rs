// OpenTimestamps Library
// Written in 2017 by
//   Andrew Poelstra <rust-ots@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

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
extern crate ots;

use std::{env, fs, process};

fn main() {
    env_logger::init().unwrap();

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

