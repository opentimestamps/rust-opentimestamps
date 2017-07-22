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

