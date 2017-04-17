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

//! # Operations
//!
//! Various operations that can be done when producing a timestamp. These
//! include prepending data, appending data, and hashing. Importantly, every
//! operation, when giving a commitment as input, yields a commitment as
//! output. Without this property it would be possible to create fake
//! timestamps.
//!

use crypto::digest::Digest;
use crypto::sha1::Sha1;
use crypto::sha2::Sha256;
use crypto::ripemd160::Ripemd160;
use std::fmt;
use std::io::{Read, Write};

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
                let mut ret = vec![0; 20];
                let mut hasher = Sha1::new();
                hasher.input(input);
                hasher.result(&mut ret);
                ret
            }
            Op::Sha256 => {
                let mut ret = vec![0; 32];
                let mut hasher = Sha256::new();
                hasher.input(input);
                hasher.result(&mut ret);
                ret
            }
            Op::Ripemd160 => {
                let mut ret = vec![0; 20];
                let mut hasher = Ripemd160::new();
                hasher.input(input);
                hasher.result(&mut ret);
                ret
            }
            Op::Hexlify => {
                format!("{}", Hexed(input)).into_bytes()
            }
            Op::Reverse => {
                input.iter().map(|x| *x).rev().collect()
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


