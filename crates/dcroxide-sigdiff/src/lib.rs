// SPDX-License-Identifier: ISC
//! The signature differential soak: named classes of inputs to dcroxide's
//! signature code (`dcroxide-dcrec`), each answered by that code and by
//! dcrd's own through `tools/oracle`, compared case by case at recorded
//! volume, with every case reproducible from a printed seed.  It has no dcrd
//! counterpart and is never published or shipped.
//!
//! # Shape
//!
//! A case is a pure function of a master seed, its class's name and its
//! index ([`class::generate`]): a list of oracle requests, each a command
//! and the exact bytes the oracle receives ([`cmd::Request`]), with the
//! answer each request was built to get ([`class::Intent`]).  dcroxide's
//! answer is computed by decoding those same bytes with the oracle's own
//! layout ([`ours`]), so both sides always see identical inputs and a case
//! needs nothing but its request bytes to be replayed.  [`pipe::OraclePipe`]
//! keeps many requests in flight to one oracle process, [`run::run`] spreads
//! the classes over workers, [`compare::compare`] holds the two answers
//! side by side, and [`digest`] reduces each class to a digest that depends
//! on the inputs, dcrd's answers and whether the two agreed, never on
//! dcroxide's own answer.  The `sigsoak` binary drives it all and writes the
//! record of a run ([`record`], [`manifest`]).  The canaries ([`canary`])
//! stand deliberately broken models in for dcroxide, to show that the
//! classes fail where an implementation gets dcrd's branches wrong, and
//! [`witness`] picks the witness vectors `dcroxide-dcrec` keeps: cases of
//! the constructed classes, with dcrd's answers, that its own Go-free test
//! answers and re-derives.
//!
//! # Independence
//!
//! Generators, models, the class registry and their arithmetic build every
//! input with this crate's own `k256` and `curve25519-dalek` arithmetic,
//! never with the code under test, so a change to that code cannot change
//! what it is tested on.  Only `src/ours.rs` names the code under test, and
//! only `src/run.rs` (and the canaries, which stand in for it) call into
//! `ours`; `tests/independence.rs` holds every file under `src/` to that.
//!
//! # The freeze
//!
//! Between the baseline soak and the gate soak, the files
//! [`fingerprint::FROZEN`] lists do not change: everything that decides a
//! case's inputs, dcrd's normalized answer, the comparison, the status and
//! the digest, and the canaries.  [`fingerprint::fingerprint`] is a digest
//! of exactly those files as they were compiled into the binary, so two
//! runs whose fingerprints differ are refused as a comparison.  The adapter
//! (`src/ours.rs`) and the plumbing ([`fingerprint::PLUMBING`]) may change,
//! since none of them can change an input, an answer as compared, a status
//! or a digest.

pub mod answer;
pub mod arith;
pub mod canary;
pub mod class;
pub mod cmd;
pub mod compare;
pub mod digest;
pub mod entropy;
pub mod fingerprint;
// `gen` is reserved in the 2024 edition, so the generators' module is
// declared, and named in paths, as a raw identifier.
pub mod r#gen;
pub mod manifest;
pub mod model;
pub mod ours;
pub mod pipe;
pub mod record;
pub mod reply;
pub mod run;
pub mod witness;
