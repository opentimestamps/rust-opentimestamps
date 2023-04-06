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

//! # Errors
//!
//! Library-wide error type and associated boilerplate
//!

use std::error;
use std::{fmt, io};
use std::string::FromUtf8Error;

/// Library-wide error structure
#[allow(missing_docs)]
#[derive(Debug)]
pub enum Error {
    /// Recursed too deeply
    StackOverflow,
    /// A URI had a character we don't like
    InvalidUriChar(char),
    /// A digest type tag was not recognized
    BadDigestTag(u8),
    /// Decoded an op tag that we don't recognize
    BadOpTag(u8),
    /// OTS file began with invalid magic bytes
    BadMagic(Vec<u8>),
    /// OTS file has version we don't understand
    BadVersion(usize),
    /// A byte vector had an invalid length
    BadLength { min: usize, max: usize, val: usize },
    /// Expected EOF but didn't get it
    TrailingBytes,
    /// UTF8
    Utf8(FromUtf8Error),
    /// I/O error
    Io(io::Error)
}

impl From<FromUtf8Error> for Error {
    fn from(e: FromUtf8Error) -> Error {
        Error::Utf8(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Error {
        Error::Io(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::StackOverflow => f.write_str("recursion limit reached"),
            Error::InvalidUriChar(c) => write!(f, "invalid character `{}` in URI", c),
            Error::BadDigestTag(t) => write!(f, "invalid digest tag 0x{:02x}", t),
            Error::BadOpTag(t) => write!(f, "invalid op tag 0x{:02x}", t),
            Error::BadMagic(ref x) => write!(f, "bad magic bytes `{:?}`, is this a timestamp file?", x),
            Error::BadVersion(v) => write!(f, "version {} timestamps not understood", v),
            Error::BadLength { min, max, val } => write!(f, "length {} should be between {} and {} inclusive", val, min, max),
            Error::TrailingBytes => f.write_str("expected eof not"), // lol
            Error::Utf8(ref e) => fmt::Display::fmt(e, f),
            Error::Io(ref e) => fmt::Display::fmt(e, f)
        }
    }
}

impl error::Error for Error {

    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::Utf8(ref e) => Some(e),
            Error::Io(ref e) => Some(e),
            _ => None
        }
    }
}

