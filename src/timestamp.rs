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

//! # Timestamp
//!

use std::fmt;
use std::io::{Read, Write};

use attestation::Attestation;
use error::Error;
use op::Op;
use ser;

/// Anti-DoS
const RECURSION_LIMIT: usize = 256;

/// The actual contents of the execution step
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Step {
    /// This step splits execution into multiple paths
    Fork(Vec<Step>),
    /// This step executes some concrete operation
    Op(Op),
    /// This step asserts an attestation of the current state by some timestamp service
    Attestation(Attestation)
}

/// Main structure representing a timestamp
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Timestamp {
    /// A list of all the steps in the Timestamp
    pub steps: Vec<Step>
}

impl Timestamp {
    /// Deserialize one step in a timestamp. 
    fn deserialize_step_recurse<R: Read>(deser: &mut ser::Deserializer<R>,
                                         steps: &mut Vec<Step>,
                                         tag: Option<u8>,
                                         recursion_limit: usize) -> Result<(), Error> {
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
                steps.push(Step::Attestation(attest));
                Ok(())
            }
            // Fork
            0xff => {
                let mut fork = vec![];

                let mut next_tag = 0xff;
                while next_tag == 0xff {
                    trace!("[{:3}] Forking..", recursion_limit);


                    Timestamp::deserialize_step_recurse(deser,
                                                        &mut fork,
                                                        None,
                                                        recursion_limit - 1)?;

                    next_tag = deser.read_byte()?;
                }

                let fork_step = Step::Fork(fork);
                steps.push(fork_step);

                Timestamp::deserialize_step_recurse(deser,
                                                    steps,
                                                    Some(next_tag),
                                                    recursion_limit - 1)?;

                Ok(())
            }
            // An actual tag
            tag => {
                // parse tag
                let op = Op::deserialize_with_tag(deser, tag)?;
                // trace!("[{:3}] Tag {} maps {} to {}.", recursion_limit, op, Hexed(&input_digest), Hexed(&output_digest));
                steps.push(Step::Op(op));
                Timestamp::deserialize_step_recurse(deser, steps, None,
                                                    recursion_limit - 1)
            }
        }
    }

    /// Deserialize a timestamp
    pub fn deserialize<R: Read>(deser: &mut ser::Deserializer<R>) -> Result<Timestamp, Error> {
        let mut steps = vec![];

        Timestamp::deserialize_step_recurse(deser, &mut steps, None, RECURSION_LIMIT)?;

        Ok(Timestamp { steps })
    }

    fn serialize_step<W: Write>(ser: &mut ser::Serializer<W>, step: &Step) -> Result<(), Error> {
        match step {
            Step::Fork(ref ss) => {
                ser.write_byte(0xff)?;
                for s in ss {
                    Timestamp::serialize_step(ser, &s)?;
                }
                Ok(())
            }
            Step::Op(ref op) => { op.serialize(ser) }
            Step::Attestation(ref attest) => {
                ser.write_byte(0x00)?;
                attest.serialize(ser)
            }
        }
    }

    /// Serialize a timestamp
    pub fn serialize<W: Write>(&self, ser: &mut ser::Serializer<W>) -> Result<(), Error> {
        for step in &self.steps {
            Timestamp::serialize_step(ser, &step)?;
        }
        Ok(())
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
        }
        else {
            f.write_str("    ")?;
        }
        Ok(())
    }

    match step {
        Step::Fork(ref steps) => {
            indent(f, depth + 1, first_line)?;
            for (i, step) in steps.iter().enumerate() {
                fmt_recurse(step, f, depth + 1, i == 0)?;
            }
            Ok(())
        }
        Step::Op(ref op) => {
            indent(f, depth, first_line)?;
            writeln!(f, "execute {}", op)?;
            indent(f, depth, false)?;
            Ok(())
        }
        Step::Attestation(ref attest) => {
            indent(f, depth, first_line)?;
            writeln!(f, "result attested by {}", attest)
        }
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for step in &self.steps {
            fmt_recurse(&step, f, 0, false)?;
        }
        Ok(())
    }
}

