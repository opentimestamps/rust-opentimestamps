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

//! # OpenTimestamps
//!
//! This is a library to support Rust applications that interact with
//! [OpenTimestamps](https://petertodd.org/2016/opentimestamps-announcement)
//! timestamps and servers. It is written in pure Rust.
//!

// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![deny(missing_docs)]

extern crate crypto;
#[macro_use] extern crate log;

pub mod attestation;
pub mod error;
pub mod hex;
pub mod op;
pub mod timestamp;
pub mod ser;

pub use ser::DetachedTimestampFile;
pub use timestamp::Timestamp;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
