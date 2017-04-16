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
    fn description(&self) -> &str {
        match *self {
            Error::StackOverflow => "recursion limit reached",
            Error::InvalidUriChar(_) => "invalid character in URI",
            Error::BadDigestTag(_) => "invalid digest tag",
            Error::BadOpTag(_) => "invalid op tag",
            Error::BadMagic(_) => "bad magic bytes, is this a timestamp file?",
            Error::BadVersion(_) => "timestamp version not understood",
            Error::BadLength { .. } => "length out of bounds",
            Error::TrailingBytes => "expected eof not",
            Error::Utf8(ref e) => error::Error::description(e),
            Error::Io(ref e) => error::Error::description(e)
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Utf8(ref e) => Some(e),
            Error::Io(ref e) => Some(e),
            _ => None
        }
    }
}

