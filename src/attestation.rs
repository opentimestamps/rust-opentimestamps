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

//! # Attestations
//!
//! An attestation is a claim that some data existed at some time. It
//! comes from some server or from a blockchain.
//!

use std::fmt;
use std::io::{Read, Write};

use error::Error;
use hex::Hexed;
use ser;

/// Size in bytes of the tag identifying the attestation type
const TAG_SIZE: usize = 8;
/// Maximum length of a URI in a "pending" attestation
const MAX_URI_LEN: usize = 1000;

/// Tag indicating a Bitcoin attestation
const BITCOIN_TAG: &[u8] = b"\x05\x88\x96\x0d\x73\xd7\x19\x01";
/// Tag indicating a pending attestation
const PENDING_TAG: &[u8] = b"\x83\xdf\xe3\x0d\x2e\xf9\x0c\x8e";

/// An attestation that some data existed at some time
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Attestation {
    /// An attestation from a Bitcoin blockheader. This consists of a blockheight
    /// and nothing more, it is expected that the current hash is equal to the
    /// Merkle root of the block at this height.
    Bitcoin {
        height: usize
    },
    /// An attestation from some server. It is commented at length in Peter Todd's
    /// `python-opentimestamps` that the server should be expected to keep anything
    /// it attests to, forever, and therefore the only thing we store locally is a
    /// single simple URI with a very restricted charset. (The restricted charset
    /// seems mainly to be to avoid the software being used for nefarious purposes,
    /// as it will fetch this URI under some circumstances.)
    Pending {
        uri: String
    },
    /// An unknown attestation that we just store straight
    Unknown {
        tag: Vec<u8>,
        data: Vec<u8>
    }
}

impl Attestation {
    /// Deserialize an arbitrary attestation
    pub fn deserialize<R: Read>(deser: &mut ser::Deserializer<R>) -> Result<Attestation, Error> {
        let tag = deser.read_fixed_bytes(TAG_SIZE)?;
        let len = deser.read_uint()?;

        if tag == BITCOIN_TAG {
            let height = deser.read_uint()?;
            Ok(Attestation::Bitcoin {
                height
            })
        } else if tag == PENDING_TAG {
            // This validation logic copied from python-opentimestamps. Peter comments
            // that he is deliberately avoiding ?, &, @, etc., to "keep us out of trouble"
            let uri_bytes = deser.read_bytes(0, MAX_URI_LEN)?;
            let uri_string = String::from_utf8(uri_bytes)?;
            for ch in uri_string.chars() {
                match ch {
                    'a'..='z' => {}
                    'A'..='Z' => {}
                    '0'..='9' => {}
                    '.' | '-' | '_' | '/' | ':' => {},
                    x => return Err(Error::InvalidUriChar(x))
                }
            }
            Ok(Attestation::Pending {
                uri: uri_string
            })
        } else {
            Ok(Attestation::Unknown {
                tag,
                data: deser.read_fixed_bytes(len)?
            })
        }
    }

    /// Serialize an attestation
    pub fn serialize<W: Write>(&self, ser: &mut ser::Serializer<W>) -> Result<(), Error> {
        let mut byte_ser = ser::Serializer::new(vec![]);
        match *self {
            Attestation::Bitcoin { height } => {
                ser.write_fixed_bytes(BITCOIN_TAG)?;
                byte_ser.write_uint(height)?;
                ser.write_bytes(&byte_ser.into_inner())
            }
            Attestation::Pending { ref uri } => {
                ser.write_fixed_bytes(PENDING_TAG)?;
                byte_ser.write_bytes(uri.as_bytes())?;
                ser.write_bytes(&byte_ser.into_inner())
            }
            Attestation::Unknown { ref tag, ref data } => {
                ser.write_fixed_bytes(tag)?;
                ser.write_bytes(data)
            }
        }
    }
}

impl fmt::Display for Attestation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Attestation::Bitcoin { height } => write!(f, "Bitcoin block {}", height),
            Attestation::Pending { ref uri } => write!(f, "Pending: update URI {}", uri),
            Attestation::Unknown { ref tag, ref data } => write!(f, "unknown attestation type {}: {}", Hexed(tag), Hexed(data)),
        }
    }
}

