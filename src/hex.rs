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

//! # Hex
//!
//! Quick and dirty bytes-to-hex implementation
//!

use std::fmt::{self, Write};

/// Wrapper around a byteslice that allows formatting as hex
pub struct Hexed<'a>(pub &'a [u8]);

static CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
];

impl<'a> fmt::Debug for Hexed<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.0 {
            f.write_char(CHARS[(*byte as usize) >> 4])?;
            f.write_char(CHARS[(*byte as usize) & 0x0f])?;
        }
        Ok(())
    }
}

impl<'a> fmt::Display for Hexed<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl<'a> fmt::LowerHex for Hexed<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

