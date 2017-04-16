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

//! # Attestations
//!
//! An attestation is a claim that some data existed at some time. It
//! comes from some server or from a blockchain.
//!

use std::fmt;
use std::io::Read;

use error::Error;
use hex::Hexed;
use ser;

/// Size in bytes of the tag identifying the attestation type
const TAG_SIZE: usize = 8;
/// Maximum length of a URI in a "pending" attestation
const MAX_URI_LEN: usize = 1000;

/// Tag indicating a Bitcoin attestation
const BITCOIN_TAG: &'static [u8] = b"\x05\x88\x96\x0d\x73\xd7\x19\x01";
/// Tag indicating a pending attestation
const PENDING_TAG: &'static [u8] = b"\x83\xdf\xe3\x0d\x2e\xf9\x0c\x8e";

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
                height: height
            })
        } else if tag == PENDING_TAG {
            // This validation logic copied from python-opentimestamps. Peter comments
            // that he is deliberately avoiding ?, &, @, etc., to "keep us out of trouble"
            let uri_bytes = deser.read_bytes(0, MAX_URI_LEN)?;
            let uri_string = String::from_utf8(uri_bytes)?;
            for ch in uri_string.chars() {
                match ch {
                    'a'...'z' => {}
                    'A'...'Z' => {}
                    '0'...'9' => {}
                    '.' | '-' | '_' | '/' | ':' => {},
                    x => return Err(Error::InvalidUriChar(x))
                }
            }
            Ok(Attestation::Pending {
                uri: uri_string
            })
        } else {
            Ok(Attestation::Unknown {
                tag: tag,
                data: deser.read_fixed_bytes(len)?
            })
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

