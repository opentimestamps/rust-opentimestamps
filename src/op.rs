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

//! # Operations
//!
//! Various operations that can be done when producing a timestamp. These
//! include prepending data, appending data, and hashing. Importantly, every
//! operation, when giving a commitment as input, yields a commitment as
//! output. Without this property it would be possible to create fake
//! timestamps.
//!

use std::fmt;
use std::io::{Read, Write};

use bitcoin_hashes::{Hash, ripemd160, sha1, sha256};
use error::Error;
use hex::Hexed;
use ser;

/// Maximum length of an op result
const MAX_OP_LENGTH: usize = 4096;

/// All the types of operations supported
#[derive(Clone, PartialEq, Eq, Debug)]
#[allow(missing_docs)]
pub enum Op {
    // crypto (unary) ops
    Sha1,
    Sha256,
    Ripemd160,
    // unary ops
    Hexlify,
    Reverse,
    // binary ops
    Append(Vec<u8>),
    Prepend(Vec<u8>)
}

impl Op {
    /// Returns the 8-bit tag identifying the op
    pub fn tag(&self) -> u8 {
        match *self {
            Op::Sha1 => 0x02,
            Op::Sha256 => 0x08,
            Op::Ripemd160 => 0x03,
            Op::Hexlify => 0xf3,
            Op::Reverse => 0xf2,
            Op::Append(_) => 0xf0,
            Op::Prepend(_) => 0xf1
        }
    }

    /// Deserialize an arbitrary op
    pub fn deserialize<R: Read>(deser: &mut ser::Deserializer<R>) -> Result<Op, Error> {
        let tag = deser.read_byte()?;
        Op::deserialize_with_tag(deser, tag)
    }

    /// Deserialize an op with the designated tag
    pub fn deserialize_with_tag<R: Read>(deser: &mut ser::Deserializer<R>, tag: u8) -> Result<Op, Error> {
        match tag {
            // unary ops are trivial
            0x02 => Ok(Op::Sha1),
            0x08 => Ok(Op::Sha256),
            0x03 => Ok(Op::Ripemd160),
            0xf3 => Ok(Op::Hexlify),
            0xf2 => Ok(Op::Reverse),
            // binary ops are almost trivial
            0xf0 => Ok(Op::Append(deser.read_bytes(1, MAX_OP_LENGTH)?)),
            0xf1 => Ok(Op::Prepend(deser.read_bytes(1, MAX_OP_LENGTH)?)),
            x => Err(Error::BadOpTag(x))
        }
    }

    /// Serialize the op into a serializer
    pub fn serialize<W: Write>(&self, ser: &mut ser::Serializer<W>) -> Result<(), Error> {
        ser.write_byte(self.tag())?;
        if let Op::Append(ref data) = *self {
            ser.write_bytes(data)?;
        }
        if let Op::Prepend(ref data) = *self {
            ser.write_bytes(data)?;
        }
        Ok(())
    }

    /// Execute an op on the given data
    pub fn execute(&self, input: &[u8]) -> Vec<u8> {
        match *self {
            Op::Sha1 => {
                sha1::Hash::hash(&input).to_byte_array().to_vec()
            }
            Op::Sha256 => {
                sha256::Hash::hash(&input).to_byte_array().to_vec()
            }
            Op::Ripemd160 => {
                ripemd160::Hash::hash(&input).to_byte_array().to_vec()
            }
            Op::Hexlify => {
                format!("{}", Hexed(input)).into_bytes()
            }
            Op::Reverse => {
                input.iter().cloned().rev().collect()
            }
            Op::Append(ref data) => {
                let mut vec = input.to_vec();
                vec.extend(data);
                vec
            }
            Op::Prepend(ref data) => {
                let mut vec = data.to_vec();
                vec.extend(input);
                vec
            }
        }
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Op::Sha1 => f.write_str("SHA1()"),
            Op::Sha256 => f.write_str("SHA256()"),
            Op::Ripemd160 => f.write_str("RIPEMD16()"),
            Op::Hexlify => f.write_str("Hexlify()"),
            Op::Reverse => f.write_str("Reverse()"),
            Op::Append(ref data) => write!(f, "Append({})", Hexed(data)),
            Op::Prepend(ref data) => write!(f, "Prepend({})", Hexed(data))
        }
    }
}


