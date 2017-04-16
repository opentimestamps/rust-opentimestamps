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

//! # Timestamp
//!

use std::fmt;
use std::io::Read;

use attestation::Attestation;
use error::Error;
use hex::Hexed;
use op::Op;
use ser;

/// Anti-DoS
const RECURSION_LIMIT: usize = 256;

/// The actual contents of the execution step
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum StepData {
    /// This step splits execution into multiple paths
    Fork,
    /// This step executes some concrete operation
    Op(Op),
    /// This step asserts an attestation of the current state by some timestamp service
    Attestation(Attestation)
}

/// An execution step in a timestamp verification
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Step {
    /// The contents of the step
    pub data: StepData,
    /// The output after execution
    pub output: Vec<u8>,
    /// A list of steps to execute after this one
    pub next: Vec<Step>
}

/// Main structure representing a timestamp
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Timestamp {
    /// The starting document digest
    pub start_digest: Vec<u8>,
    /// The first execution step in verifying it
    pub first_step: Step
}

impl Timestamp {
    /// Deserialize one step in a timestamp. 
    fn deserialize_step_recurse<R: Read>(deser: &mut ser::Deserializer<R>, input_digest: Vec<u8>, tag: Option<u8>, recursion_limit: usize) -> Result<Step, Error> {

        if recursion_limit == 0 {
            return Err(Error::StackOverflow);
        }

        // Read next tag if we weren't given one
        let tag = match tag {
            Some(tag) => tag,
            None => deser.read_byte()?
        };

        // A tag typically indicates an op to execute, but the two special values
        // 0xff (fork) and 0x00 (read attestation and terminate path) are used to
        // provide multiple attestations
        match tag {
            // Attestation
            0x00 => {
                let attest = Attestation::deserialize(deser)?;
                trace!("[{:3}] Attestation: {}", recursion_limit, attest);
                Ok(Step {
                    data: StepData::Attestation(attest),
                    output: input_digest,
                    next: vec![]
                })
            }
            // Fork
            0xff => {
                let mut forks = vec![];
                let mut next_tag = 0xff;
                while next_tag == 0xff {
                    trace!("[{:3}] Forking..", recursion_limit);
                    forks.push(Timestamp::deserialize_step_recurse(deser, input_digest.clone(), None, recursion_limit - 1)?);
                    next_tag = deser.read_byte()?;
                }
                forks.push(Timestamp::deserialize_step_recurse(deser, input_digest.clone(), Some(next_tag), recursion_limit - 1)?);
                Ok(Step {
                    data: StepData::Fork,
                    output: input_digest,
                    next: forks
                })
            }
            // An actual tag
            tag => {
                // parse tag
                let op = Op::deserialize_with_tag(deser, tag)?;
                let output_digest = op.execute(&input_digest);
                trace!("[{:3}] Tag {} maps {} to {}.", recursion_limit, op, Hexed(&input_digest), Hexed(&output_digest));
                // recurse
                let next = vec![Timestamp::deserialize_step_recurse(deser, output_digest.clone(), None, recursion_limit - 1)?];
                Ok(Step {
                    data: StepData::Op(op),
                    output: output_digest,
                    next: next
                })
            }
        }
    }

    /// Deserialize a timestamp
    pub fn deserialize<R: Read>(deser: &mut ser::Deserializer<R>, digest: Vec<u8>) -> Result<Timestamp, Error> {
        let first_step = Timestamp::deserialize_step_recurse(deser, digest.clone(), None, RECURSION_LIMIT)?;

        Ok(Timestamp {
            start_digest: digest,
            first_step: first_step
        })
    }
}

fn fmt_recurse(step: &Step, f: &mut fmt::Formatter, depth: usize, first_line: bool) -> fmt::Result {
    fn indent(f: &mut fmt::Formatter, depth: usize, first_line: bool) -> fmt::Result {
        if depth == 0 {
            return Ok(());
        }

        for _ in 0..depth-1 {
            f.write_str("    ")?;
        }
        if first_line {
            f.write_str("--->")?;
        } else {
            f.write_str("    ")?;
        }
        Ok(())
    }

    match step.data {
        StepData::Fork => {
            indent(f, depth, first_line)?;
            writeln!(f, "(fork {} ways)", step.next.len())?;
            for fork in &step.next {
                fmt_recurse(fork, f, depth + 1, true)?;
            }
            Ok(())
        }
        StepData::Op(ref op) => {
            indent(f, depth, first_line)?;
            writeln!(f, "execute {}", op)?;
            indent(f, depth, false)?;
            writeln!(f, " result {}", Hexed(&step.output))?;
            fmt_recurse(&step.next[0], f, depth, false)
        }
        StepData::Attestation(ref attest) => {
            indent(f, depth, first_line)?;
            writeln!(f, "result attested by {}", attest)
        }
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Starting digest: {}", Hexed(&self.start_digest))?;
        fmt_recurse(&self.first_step, f, 0, false)
    }
}

