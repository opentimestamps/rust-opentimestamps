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

extern crate bitcoin_hashes;
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
    use super::*;

    const SMALL_TEST: &'static [u8] = b"\
\x00\x4f\x70\x65\x6e\x54\x69\x6d\x65\x73\x74\x61\x6d\x70\x73\x00\x00\x50\x72\x6f\x6f\x66\x00\xbf\x89\xe2\xe8\x84\xe8\x92\
\x94\x01\x08\xa7\x0d\xfe\x69\xc5\xa0\xd6\x28\x16\x78\x1a\xbb\x6e\x17\x77\x85\x47\x18\x62\x4a\x0d\x19\x42\x31\xad\xb1\x4c\
\x32\xee\x54\x38\xa4\xf0\x10\x7a\x46\x05\xde\x0a\x5b\x37\xcb\x21\x17\x59\xc6\x81\x2b\xfe\x2e\x08\xff\xf0\x10\x24\x4b\x79\
\xd5\x78\xaa\x38\xe3\x4f\x42\x7b\x0f\x3e\xd2\x55\xa5\x08\xf1\x04\x58\xa4\xc2\x57\xf0\x08\xa1\xa9\x2c\x61\xd5\x41\x72\x06\
\x00\x83\xdf\xe3\x0d\x2e\xf9\x0c\x8e\x2c\x2b\x68\x74\x74\x70\x73\x3a\x2f\x2f\x62\x6f\x62\x2e\x62\x74\x63\x2e\x63\x61\x6c\
\x65\x6e\x64\x61\x72\x2e\x6f\x70\x65\x6e\x74\x69\x6d\x65\x73\x74\x61\x6d\x70\x73\x2e\x6f\x72\x67\xf0\x10\xe0\x27\x85\x91\
\xe2\x88\x68\x19\xba\x7b\x3d\xdd\x63\x2e\xd3\xfe\x08\xf1\x04\x58\xa4\xc2\x56\xf0\x08\x38\xf2\xc7\xf4\xba\xf4\xbc\xd7\x00\
\x83\xdf\xe3\x0d\x2e\xf9\x0c\x8e\x2e\x2d\x68\x74\x74\x70\x73\x3a\x2f\x2f\x61\x6c\x69\x63\x65\x2e\x62\x74\x63\x2e\x63\x61\
\x6c\x65\x6e\x64\x61\x72\x2e\x6f\x70\x65\x6e\x74\x69\x6d\x65\x73\x74\x61\x6d\x70\x73\x2e\x6f\x72\x67";

    const LARGE_TEST: &'static [u8] = b"\
\x00\x4f\x70\x65\x6e\x54\x69\x6d\x65\x73\x74\x61\x6d\x70\x73\x00\x00\x50\x72\x6f\x6f\x66\x00\xbf\x89\xe2\xe8\x84\xe8\x92\
\x94\x01\x08\x6f\xd9\xc1\xc4\xf0\x96\xb7\x7e\x6d\x44\x57\xba\xc1\xc7\xf5\x10\x10\xd3\x18\xdb\x48\x3f\x28\x68\xd3\x79\x58\
\x43\xf0\x98\xd3\x78\xf0\x10\xe2\xe2\x24\x43\x9e\x7f\x0f\xdd\x8c\x1e\xea\xc7\x3e\xa7\x39\xdb\x08\xf1\x20\xa5\x74\x44\x4a\
\xa5\x00\x02\xb6\xfe\x5a\xf2\x46\x26\x70\x0a\x4b\xfc\x95\x0d\x61\xf8\x13\x7c\xc3\x9d\xa8\x2d\x53\x27\x6c\x9d\x66\x08\xf0\
\x20\x02\xf3\x1f\xd5\xa2\xf0\xff\x08\xf7\xe0\x73\x38\x4b\x4f\xf5\x2b\xc5\xa0\x26\xf6\xfe\x42\x4a\x3b\x6c\x83\x58\x0e\x76\
\x9e\x59\xd2\x08\xf0\x20\xe0\xea\x0a\x32\x87\xcc\xb1\x0f\x39\x1c\x62\xf6\x8e\xb5\xa2\xde\x1d\x13\xbc\x24\xc5\xc0\xb4\x0f\
\x6a\x03\xe3\x6b\xbb\xa7\xaa\xb0\x08\xf0\x20\xd9\xc3\xfa\x8a\x65\xbb\x0c\xcf\xb3\x38\x5c\xc2\x03\x42\x05\x94\xe2\xe5\xa9\
\x34\x41\xbf\xf8\x5c\xcc\x53\xd1\x63\x9b\x0f\x2c\x85\x08\xf0\x20\x2f\xc4\x1f\x43\xb7\xab\xb0\x51\xf2\xe9\xee\x08\x39\xb8\
\x61\x9a\xd8\xc7\xb0\xc4\x04\xcd\xfc\xcd\xd5\xd0\x90\xbb\x3b\x42\xa8\x89\x08\xf0\x20\x0b\xae\x5b\x64\x92\x16\x89\xf7\xb3\
\xee\x1f\x86\xb1\xae\x79\xea\x7e\xd3\xd8\x22\x08\x4f\x3a\x2c\xed\xb3\x75\xd1\xc2\x36\x05\x93\x08\xf1\x20\xe9\x31\xb8\x22\
\x28\xdb\x72\xb4\x9e\x9c\x33\x9c\x3f\xd8\xa2\x48\x16\x26\x48\xc3\x0e\x3c\x03\x1d\xb5\x40\x20\x76\xf4\xe1\x9d\x48\x08\xf1\
\x20\x37\xe1\x51\xfe\x09\x9e\x20\x8f\x90\xfe\x51\x11\x65\x0f\x81\x38\xdf\xd3\x2f\xa8\x5f\x21\x30\xf1\x6c\xd5\xe9\x91\xb4\
\xf9\x48\x1c\x08\xff\xf0\x10\x2c\x2b\xd1\x10\x61\x89\x89\xd9\xa4\xc6\xbf\x60\xa8\xde\xec\x50\x08\xf1\x04\x58\x83\xf1\x71\
\xf0\x08\x6d\x45\x80\xfc\x64\xdf\xa9\x79\xff\x00\x83\xdf\xe3\x0d\x2e\xf9\x0c\x8e\x2c\x2b\x68\x74\x74\x70\x73\x3a\x2f\x2f\
\x62\x6f\x62\x2e\x62\x74\x63\x2e\x63\x61\x6c\x65\x6e\x64\x61\x72\x2e\x6f\x70\x65\x6e\x74\x69\x6d\x65\x73\x74\x61\x6d\x70\
\x73\x2e\x6f\x72\x67\x08\xf1\xae\x01\x01\x00\x00\x00\x01\x7e\x85\x5c\xd0\x5c\xb2\x31\x1f\xea\x5f\xed\xde\xea\x21\xbe\x34\
\xa5\x98\x2e\xb3\xfb\xa9\xbd\xca\x1d\x9e\xf9\x8a\x80\x05\xe1\x22\x00\x00\x00\x00\x48\x47\x30\x44\x02\x20\x3d\x4d\xec\x68\
\x13\xb7\xe2\x87\x0e\xc5\x38\xb3\x88\x2c\xd0\x5e\x5d\xb5\x71\xd7\x51\x1b\x6e\x31\x98\x69\x46\x2b\x02\x9f\xf2\x5a\x02\x20\
\x3e\xeb\x26\x3b\x36\x1a\x2b\x48\x20\xe9\x9c\xed\xce\xa1\x47\x1a\xcd\x4b\xee\x47\x3a\x23\xa8\x2f\xaf\xcf\xf1\xbe\x13\x15\
\xb3\x45\x01\xfd\xff\xff\xff\x02\xe3\x14\x13\x00\x00\x00\x00\x00\x23\x21\x02\x76\x18\xa4\x61\xfd\x2d\x26\xc4\xba\x77\xf1\
\xf7\xcd\x8a\xc5\x57\x7e\xea\x66\x5f\xfb\xc9\xa8\xde\x3c\x2e\x55\x91\x1c\xf0\x9f\x73\xac\x00\x00\x00\x00\x00\x00\x00\x00\
\x22\x6a\x20\xf0\x04\x73\xdb\x06\x00\x08\x08\xf0\x20\xa3\xb9\x56\xff\xca\xc2\x63\xfb\xd6\x6b\x33\x1e\x9c\x06\xa4\xb0\x96\
\x34\x2c\xff\xa7\x5a\xc8\x09\x90\x50\xd8\xda\x1c\x14\x94\x10\x08\x08\xf1\x20\x6c\x3c\x90\x80\x96\x2b\x36\x5f\xc4\x3e\x1f\
\xc6\x10\xe6\x91\x23\x7e\x33\x3e\x59\x98\xf8\xa8\x5d\xe3\xac\xf5\x79\x3c\x7d\x7d\x96\x08\x08\xf1\x20\x13\x88\x3d\x43\x52\
\xa3\x8a\x7f\x1b\xe2\xf4\x3a\xe3\x8d\xc3\x8f\xd4\x75\x39\xe4\xf1\xb1\x43\x90\xbe\x7d\x27\x0b\xb3\xf8\x1d\x4e\x08\x08\xf1\
\x20\x86\xe1\xb5\x77\xf7\xc7\xa1\xfd\x34\x52\x92\x81\xba\xcd\xec\x29\x3d\xa4\xd8\xac\xe8\x62\x2a\x6c\x04\xd9\x99\x05\x7d\
\x8b\x8e\x62\x08\x08\xf0\x20\xbf\x6b\x64\xf8\x33\x89\x98\x5d\x0a\xf4\xf7\xb4\x75\x3b\xb6\x8e\x57\x09\xff\xf1\x00\xa3\xdb\
\x0c\xb6\x1e\x6e\x44\xff\x8c\xf6\xae\x08\x08\xf1\x20\xfa\x8b\x54\x69\x92\xb6\x1c\xe2\xf1\xa9\x2f\x82\xde\x54\x5d\xae\x0d\
\xa7\x03\xef\x93\x2b\x6e\x4b\xda\x52\x3f\x2a\xec\x61\x7e\x5f\x08\x08\xf0\x20\x25\x61\xe8\xf4\xc2\x4d\x32\xc2\x14\x1c\x74\
\x64\x6d\xb0\x67\x30\x7f\x6c\x6e\x17\x05\xa4\xf5\x05\xb8\xab\x81\xaf\x1c\x16\x54\xc2\x08\x08\xf1\x20\x51\x7a\x29\xcb\x81\
\x52\x6f\x3b\x28\x71\x6f\xff\xb2\x4d\x5c\x8b\x6d\x6c\xcc\xd4\xb9\x8e\xec\xc9\xaa\xf0\x00\x37\x08\xb4\x25\x22\x08\x08\x00\
\x05\x88\x96\x0d\x73\xd7\x19\x01\x03\xf7\xb6\x1b\xf0\x10\x75\x85\xd6\x34\x8e\x2c\x8a\x1c\x7e\xd0\xa6\x97\x7a\xe4\xd2\xad\
\x08\xf1\x04\x58\x83\xf1\x71\xf0\x08\x5d\xeb\x89\x67\x36\x2e\x06\xb6\xff\x00\x83\xdf\xe3\x0d\x2e\xf9\x0c\x8e\x2e\x2d\x68\
\x74\x74\x70\x73\x3a\x2f\x2f\x61\x6c\x69\x63\x65\x2e\x62\x74\x63\x2e\x63\x61\x6c\x65\x6e\x64\x61\x72\x2e\x6f\x70\x65\x6e\
\x74\x69\x6d\x65\x73\x74\x61\x6d\x70\x73\x2e\x6f\x72\x67\x08\xf0\x20\x41\x41\x13\x62\xbc\xe1\x8d\x16\xff\x66\x0b\x43\x1a\
\x64\x4b\xb6\xc4\xa1\xf0\x65\x55\x62\x7a\xe0\x07\x8c\x7b\xb7\x21\x48\x0e\x4b\x08\xf0\x20\xd8\x68\x49\x86\xc4\x82\x11\x22\
\xca\x9f\x66\x6c\x55\x07\xb8\x9d\x89\x6b\x81\x2b\xbe\xc9\xc1\x84\x72\x09\x96\x4d\x0c\x4f\x2e\xc3\x08\xf1\x20\xb1\x07\xd6\
\x20\x2e\x7f\x79\xca\x83\x99\x17\xda\xdb\xeb\x20\x5b\x76\x16\x83\xb4\x9d\x16\x9d\xe2\x30\x25\x45\x2b\xf5\x79\x6a\xe2\x08\
\xf0\x20\x74\xc4\x8c\x02\x9d\x2f\x8f\x5f\xd7\x40\x9e\x8f\xcf\x68\x4e\x42\xbe\xb7\x2e\xbd\x99\xfe\x6c\xef\xff\x09\xe4\x47\
\x29\x49\x06\xa7\x08\xf0\x20\x62\x9e\xe2\x17\x44\x93\x5b\x51\x8c\x36\x14\x8a\xd3\x0f\xc7\xfc\x08\x87\x89\xc2\xb0\x00\xb4\
\x69\xcb\xb5\x0a\xe6\x1a\x34\xf3\x01\x08\xf1\xae\x01\x01\x00\x00\x00\x01\xa2\xc7\x0a\xd9\x76\x8b\x47\x6e\xb8\x2e\x07\x04\
\x75\x60\x3c\xdc\xb3\x01\x41\x4f\x62\xd5\x58\x10\x06\x13\x72\x41\x2d\x91\xe1\xbf\x00\x00\x00\x00\x48\x47\x30\x44\x02\x20\
\x52\x52\xd2\x89\x09\x05\x5e\xff\x8f\xb3\xab\x68\xf9\xcc\x11\x15\x03\x2b\x75\xe6\xcc\xfb\xf3\x84\x4b\xd9\x16\x14\xdd\x73\
\x7c\xd6\x02\x20\x21\xad\xd2\xd0\xab\x18\x8f\x4d\xb5\x55\x06\x6b\x0c\x38\x22\xd4\xba\xb0\x13\x43\x91\x98\x57\xdb\xaa\x11\
\x11\x5d\xc1\x4a\xd2\x21\x01\xfd\xff\xff\xff\x02\xb4\x4d\x44\x00\x00\x00\x00\x00\x23\x21\x03\x00\x9a\x9a\x91\x2d\x43\x76\
\x26\x8e\xc1\x37\x7c\x12\xd3\xd9\x9b\xd5\x1d\xa4\xf1\xed\xd8\x2c\x22\x74\xfd\x45\xde\xe1\xe3\xac\xd1\xac\x00\x00\x00\x00\
\x00\x00\x00\x00\x22\x6a\x20\xf0\x04\x74\xdb\x06\x00\x08\x08\xf1\x20\x5a\xbb\xb3\xdc\xd1\x24\x9e\xeb\x6d\x9b\xa9\x97\x2a\
\x94\x6e\xef\x2c\xdc\x3f\x32\x50\x38\xc1\x9d\x25\x3f\x5c\xa6\xd6\x93\x83\x7b\x08\x08\xf1\x20\xe9\x89\x14\x1b\xe1\x09\xac\
\xba\x19\x78\x20\xe1\x8a\xd9\xc2\x50\x64\x5c\xc0\x9d\xa5\x32\x89\x5e\xd9\x8d\x19\x1f\xf6\xf4\x24\xd6\x08\x08\xf0\x20\x48\
\xdc\xfc\x2f\xe8\x9e\x46\x4e\xd5\x28\x31\x90\x16\x56\xa1\x3b\x9f\x8d\x78\x37\xd6\xba\xe3\xfc\xa1\x8f\x14\x4a\xe0\x03\x73\
\x50\x08\x08\xf1\x20\xb2\x42\x65\xa8\x06\x99\xfd\x93\x01\xd5\x94\xfd\x90\x25\x9b\xd0\xed\x3b\x86\x8a\xf1\xcd\x36\x42\x08\
\x84\x7e\x64\x80\xb8\xab\x57\x08\x08\xf1\x20\xd0\xa7\x95\x39\xe4\x40\xf9\x9e\xe6\x0d\xba\xdd\x27\xa0\x71\x62\x25\x52\x37\
\x14\x0e\x91\x1b\xd0\x1d\xfc\x5c\xde\xc6\xdc\xaf\xec\x08\x08\xf1\x20\xd5\x6d\xf3\x0e\x00\xef\x52\xc8\xd4\xc2\x7e\x95\xe7\
\x7e\x28\xe4\x2e\x8d\xb9\xdb\xf4\x93\x3b\xd3\xc1\xfa\x80\x3c\x79\x2c\x68\xfa\x08\x08\xf1\x20\x91\xe3\x57\x66\xb6\xcf\x6d\
\x60\xd4\xeb\x6f\xa7\x28\xc6\x87\x6e\xca\xbf\x99\x92\x81\xc8\x2e\xd2\x00\xb0\x5a\xb1\x18\x78\xab\x49\x08\x08\xf0\x20\xad\
\x0c\xbb\x07\xe6\xa6\xa3\x59\xf8\x0f\x69\xa8\x7d\xcb\xc9\xbc\x78\x04\x79\xea\x73\xd2\xbe\xb6\xf7\x3c\xd3\xb9\x25\xa2\x89\
\x41\x08\x08\xf1\x20\x4b\x38\x70\x93\xad\xcd\xe0\xb6\x91\x58\xcf\x5d\x08\xdf\xf0\xf6\x2a\xa9\x4c\x77\x41\x52\xad\xa3\x9f\
\xed\x89\x57\x63\xf6\xad\xb3\x08\x08\xf1\x20\xe1\xc1\xae\xc4\x3e\x4c\xba\x0c\xc7\x6a\xed\xf0\x74\x33\xc2\x45\xaf\x3f\x8a\
\xe2\xc0\x56\x45\xa1\x9c\x09\x09\x36\x4c\x3f\x30\x6e\x08\x08\x00\x05\x88\x96\x0d\x73\xd7\x19\x01\x03\xf5\xb6\x1b";

    #[test]
    fn round_trip() {
        let mut rt1 = vec![];
        let mut rt2 = vec![];

        let otsr = DetachedTimestampFile::from_reader(SMALL_TEST);
        assert!(otsr.is_ok());
        let ots = otsr.unwrap();
        assert!(ots.to_writer(&mut rt1).is_ok());
        assert_eq!(rt1, SMALL_TEST);

        let otsr = DetachedTimestampFile::from_reader(LARGE_TEST);
        otsr.as_ref().unwrap();
        assert!(otsr.is_ok());
        let ots = otsr.unwrap();
        assert!(ots.to_writer(&mut rt2).is_ok());
        assert_eq!(rt2, LARGE_TEST);
    }
}

