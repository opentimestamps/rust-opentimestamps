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

//! # Serialization
//!
//! Supports deserialization and serialization of OTS info files
//!

use std::fmt;
use std::io::{Read, Write};

use error::Error;
use hex::Hexed;
use timestamp::Timestamp;

/// Magic bytes that every proof must start with
const MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";

/// Major version of timestamp files we understand
const VERSION: usize = 1;

/// Structure representing an info file
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DetachedTimestampFile {
    /// The claimed hash function used to produce the document digest
    pub digest_type: DigestType,

    /// The initial timestamp digest input
    pub digest: Vec<u8>,

    /// The actual timestamp data
    pub timestamp: Timestamp
}

impl DetachedTimestampFile {
    /// Deserialize a info file from a reader
    pub fn from_reader<R: Read>(reader: R) -> Result<DetachedTimestampFile, Error> {
        trace!("Start deserializing timestampfile from reader.");
        let mut deser = Deserializer::new(reader);

        deser.read_magic()?;
        trace!("Magic ok.");
        deser.read_version()?;
        trace!("Version ok.");
        let digest_type = DigestType::from_tag(deser.read_byte()?)?;
        trace!("Digest type: {}", digest_type);
        let digest = deser.read_fixed_bytes(digest_type.digest_len())?;
        trace!("Digest: {}", Hexed(&digest));
        let timestamp = Timestamp::deserialize(&mut deser)?;

        deser.check_eof()?;

        Ok(DetachedTimestampFile {
            digest_type,
            digest,
            timestamp,
        })
    }

    /// Serialize the file into a reader
    pub fn to_writer<W: Write>(&self, writer: W) -> Result<(), Error> {
        let mut ser = Serializer::new(writer);
        ser.write_magic()?;
        ser.write_version()?;
        ser.write_byte(self.digest_type.to_tag())?;
        ser.write_fixed_bytes(&self.digest)?;
        self.timestamp.serialize(&mut ser)
    }
}

impl fmt::Display for DetachedTimestampFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "{} digest of some data.", self.digest_type)?;
        writeln!(f, "{}", self.timestamp)
    }
}

/// Type of hash used to produce the document digest
#[allow(missing_docs)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DigestType {
    Sha1,
    Sha256,
    Ripemd160
}

impl DigestType {
    /// Intepret a one-byte tag as a digest type
    pub fn from_tag(tag: u8) -> Result<DigestType, Error> {
        match tag {
            0x02 => Ok(DigestType::Sha1),
            0x03 => Ok(DigestType::Ripemd160),
            0x08 => Ok(DigestType::Sha256),
            x => Err(Error::BadDigestTag(x))
        }
    }

    /// Serialize a digest type by its tag
    pub fn to_tag(self) -> u8 {
        match self {
            DigestType::Sha1 => 0x02,
            DigestType::Sha256 => 0x08,
            DigestType::Ripemd160 => 0x03
        }
    }

    /// The length, in bytes, that a digest with this hash function will be
    pub fn digest_len(self) -> usize {
        match self {
            DigestType::Sha1 => 20,
            DigestType::Sha256 => 32,
            DigestType::Ripemd160 => 20
        }
    }
}

impl fmt::Display for DigestType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DigestType::Sha1 => f.write_str("SHA1"),
            DigestType::Sha256 => f.write_str("SHA256"),
            DigestType::Ripemd160 => f.write_str("RIPEMD160"),
        }
    }
}


// ** I/O stuff **

/// Standard deserializer for OTS info files
pub struct Deserializer<R: Read> {
    reader: R
}

impl<R: Read> Deserializer<R> {
    /// Constructs a new deserializer from a reader
    pub fn new(reader: R) -> Deserializer<R> {
        Deserializer {
            reader,
        }
    }

    /// Extracts the underlying reader from the deserializer
    pub fn into_inner(self) -> R {
        self.reader
    }

    /// Reads the magic bytes and checks that they are what we expect
    pub fn read_magic(&mut self) -> Result<(), Error> {
        let recv_magic = self.read_fixed_bytes(MAGIC.len())?;
        if recv_magic == MAGIC {
            Ok(())
        } else {
            Err(Error::BadMagic(recv_magic))
        }
    }

    /// Reads the version and checks that it is what we expect
    pub fn read_version(&mut self) -> Result<(), Error> {
        let recv_version = self.read_uint()?;
        if recv_version == VERSION {
            Ok(())
        } else {
            Err(Error::BadVersion(recv_version))
        }
    }


    /// Reads a single byte from the reader
    pub fn read_byte(&mut self) -> Result<u8, Error> {
        let mut byte = [0];
        self.reader.read_exact(&mut byte)?;
        Ok(byte[0])
    }

    // PT's implementation has a `read_bool` method but it is
    // never actually used

    /// Deserializes an unsigned integer
    pub fn read_uint(&mut self) -> Result<usize, Error> {
        let mut ret = 0;
        let mut shift = 0;

        loop {
            // Bottom 7 bits are value bits
            let byte = self.read_byte()?;
            ret |= ((byte & 0x7f) as usize) << shift;
            // Top bit is a continue bit
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }

        Ok(ret)
    }

    /// Deserializes a fixed number of bytes
    pub fn read_fixed_bytes(&mut self, n: usize) -> Result<Vec<u8>, Error> {
        let mut ret = vec![0; n];
        self.reader.read_exact(&mut ret)?;
        Ok(ret)
    }

    /// Deserializes a variable number of bytes
    pub fn read_bytes(&mut self, min: usize, max: usize) -> Result<Vec<u8>, Error> {
        let n = self.read_uint()?;
        if n < min || n > max {
            return Err(Error::BadLength { min, max, val: n });
        }
        self.read_fixed_bytes(n)
    }

    /// Check that there is no trailing data
    pub fn check_eof(&mut self) -> Result<(), Error> {
        if self.reader.by_ref().bytes().next().is_none() {
            Ok(())
        } else {
            Err(Error::TrailingBytes)
        }
    }
}


/// Standard serializer for OTS info files
pub struct Serializer<W: Write> {
    writer: W
}

impl<W: Write> Serializer<W> {
    /// Constructs a new deserializer from a reader
    pub fn new(writer: W) -> Serializer<W> {
        Serializer {
            writer,
        }
    }

    /// Extracts the underlying writer from the serializer
    pub fn into_inner(self) -> W {
        self.writer
    }

    /// Writes the magic bytes
    pub fn write_magic(&mut self) -> Result<(), Error> {
        self.write_fixed_bytes(MAGIC)
    }

    /// Writes the major version
    pub fn write_version(&mut self) -> Result<(), Error> {
        self.write_uint(VERSION)
    }

    /// Writes a single byte to the writer
    pub fn write_byte(&mut self, byte: u8) -> Result<(), Error> {
        self.writer.write_all(&[byte]).map_err(Error::Io)
    }

    /// Write an unsigned integer
    pub fn write_uint(&mut self, mut n: usize) -> Result<(), Error> {
        if n == 0 {
            self.write_byte(0x00)
        } else {
            while n > 0 {
                if n > 0x7f {
                    self.write_byte((n as u8) | 0x80)?;
                } else {
                    self.write_byte(n as u8)?;
                }
                n >>= 7;
            }
            Ok(())
        }
    }

    /// Write a fixed number of bytes
    pub fn write_fixed_bytes(&mut self, data: &[u8]) -> Result<(), Error> {
        self.writer.write_all(data).map_err(Error::Io)
    }

    /// Write a variable number of bytes
    pub fn write_bytes(&mut self, data: &[u8]) -> Result<(), Error> {
        self.write_uint(data.len())?;
        self.write_fixed_bytes(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_type_rt() {
        macro_rules! check_digest_type {
            ($($tag: ident),*) => {
                // Empty match to trigger exhaustiveness checking
                match DigestType {
                    $(DigestType::$tag => {}),*
                }
                // RTT each in turn
                $({
                    let tag = DigestType::$tag.to_tag();
                    assert!(DigestType::from_tag(tag).is_ok());
                    let from = DigestType::from_tag(tag).unwrap();
                    assert_eq!(DigestType::$tag, from);
                })*
            }
        };
    }

    #[test]
    fn digest_len() {
        assert_eq!(DigestType::Sha1.digest_len(), 20);
        assert_eq!(DigestType::Sha256.digest_len(), 32);
        assert_eq!(DigestType::Ripemd160.digest_len(), 20);
    }
}

