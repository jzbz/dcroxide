// SPDX-License-Identifier: ISC
//! Per-class digests: an order-independent sum of per-case BLAKE-256
//! leaves.
//!
//! A leaf covers a case's request bytes, dcrd's canonical answer to each
//! and the case's status, never dcroxide's own answer, so two runs on the
//! same seeds and counts (the libsecp baseline and a k256 leg, say) give
//! equal digests exactly when both agree with dcrd everywhere.  The class
//! digest at count n hashes the sum mod 2^256 of the leaves of cases
//! `0..n`; the sum commutes, so workers merge in any order, and the index
//! inside each leaf keeps two cases at one index from cancelling.  Digests
//! are kept at every power of ten from 10^3 to 10^7 below the final count
//! too, so a short replay run can be held against a long one.
//!
//! Recorded digests stay comparable only while this construction stays as
//! it is; known-answer tests pin it.

use dcroxide_crypto::blake256::Blake256;

use crate::answer::{Answer, canon};
use crate::arith::add_be;
use crate::cmd::Request;
use crate::compare::Status;

/// The counts digests are kept at besides the final one.
pub const CHECKPOINTS: [u64; 5] = [1_000, 10_000, 100_000, 1_000_000, 10_000_000];

/// The leaf of case `index` of class `class`:
/// `BLAKE-256("sigdiff-leaf-1" ‖ u16be(len class) ‖ class ‖ u64be(index) ‖
/// u8(requests) ‖ for each request: u8(len cmd) ‖ cmd ‖ u32be(len data) ‖
/// data ‖ canon(theirs) ‖ u8(status))`, `canon` being
/// [`crate::answer::canon`].
pub fn leaf(
    class: &str,
    index: u64,
    requests: &[Request],
    theirs: &[Option<Answer>],
    status: Status,
) -> [u8; 32] {
    assert_eq!(requests.len(), theirs.len(), "one answer per request");
    let mut h = Blake256::new();
    h.update(b"sigdiff-leaf-1");
    h.update(
        &u16::try_from(class.len())
            .expect("a class name under 64 KiB")
            .to_be_bytes(),
    );
    h.update(class.as_bytes());
    h.update(&index.to_be_bytes());
    h.update(&[u8::try_from(requests.len()).expect("at most 255 requests")]);
    let mut answer = Vec::new();
    for (request, theirs) in requests.iter().zip(theirs) {
        let name = request.cmd.name();
        h.update(&[u8::try_from(name.len()).expect("a short command name")]);
        h.update(name.as_bytes());
        h.update(
            &u32::try_from(request.data.len())
                .expect("data under 4 GiB")
                .to_be_bytes(),
        );
        h.update(&request.data);
        answer.clear();
        canon(request.cmd, theirs.as_ref(), &mut answer);
        h.update(&answer);
    }
    h.update(&[status.code()]);
    h.finalize()
}

/// The digest of class `class` at count `n`, whose leaves sum to `sum`:
/// `BLAKE-256("sigdiff-class-1" ‖ u16be(len class) ‖ class ‖ u64be(n) ‖
/// sum)`.
pub fn class_digest(class: &str, n: u64, sum: &[u8; 32]) -> [u8; 32] {
    let mut h = Blake256::new();
    h.update(b"sigdiff-class-1");
    h.update(
        &u16::try_from(class.len())
            .expect("a class name under 64 KiB")
            .to_be_bytes(),
    );
    h.update(class.as_bytes());
    h.update(&n.to_be_bytes());
    h.update(sum);
    h.finalize()
}

/// One row of `digests.tsv`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestRow {
    /// The count the digest is at.
    pub n: u64,
    /// The class digest at that count.
    pub digest: [u8; 32],
    /// Whether this is the final count rather than a checkpoint.
    pub is_final: bool,
}

/// A class's leaves, summed per checkpoint bucket: bucket k holds the
/// leaves of the indices from checkpoint k − 1 (or 0) up to checkpoint k,
/// and the last bucket every index from 10^7 on.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClassDigest {
    buckets: [[u8; 32]; 6],
}

impl ClassDigest {
    /// No leaves.
    pub fn new() -> ClassDigest {
        ClassDigest::default()
    }

    /// Adds the leaf of case `index`.
    pub fn add(&mut self, index: u64, leaf: &[u8; 32]) {
        let bucket = CHECKPOINTS.iter().take_while(|&&c| c <= index).count();
        self.buckets[bucket] = add_be(&self.buckets[bucket], leaf).0;
    }

    /// Adds every leaf of `other`.
    pub fn merge(&mut self, other: &ClassDigest) {
        for (mine, theirs) in self.buckets.iter_mut().zip(&other.buckets) {
            *mine = add_be(mine, theirs).0;
        }
    }

    /// The sum of the first `buckets` buckets.
    fn sum_of(&self, buckets: usize) -> [u8; 32] {
        self.buckets
            .iter()
            .take(buckets)
            .fold([0u8; 32], |acc, b| add_be(&acc, b).0)
    }

    /// The sum of every leaf added.
    pub fn total(&self) -> [u8; 32] {
        self.sum_of(self.buckets.len())
    }

    /// The rows of `digests.tsv` for a class that completed cases `0..n`:
    /// every checkpoint below `n`, then `n` itself.  Each checkpoint's sum
    /// covers exactly the indices below it, which all completed.
    pub fn rows(&self, class: &str, n: u64) -> Vec<DigestRow> {
        let mut rows: Vec<DigestRow> = CHECKPOINTS
            .iter()
            .enumerate()
            .take_while(|&(_, &c)| c < n)
            .map(|(k, &c)| DigestRow {
                n: c,
                digest: class_digest(class, c, &self.sum_of(k.saturating_add(1))),
                is_final: false,
            })
            .collect();
        rows.push(DigestRow {
            n,
            digest: class_digest(class, n, &self.total()),
            is_final: true,
        });
        rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::answer::Kind;
    use crate::cmd;
    use dcroxide_testutil::{SplitMix64, hex};

    /// The construction, pinned: each preimage was laid out by hand from
    /// the documented layout and hashed by dcrd's own BLAKE-256 (the
    /// oracle's `blake256` command), apart from this code.
    #[test]
    fn known_answers() {
        let requests = [
            cmd::ecdsa_parse_der(&[0x30, 0x01]),
            cmd::pubkey_parse(&[0x05]),
        ];
        let theirs = [
            Some(Answer::Reject {
                kind: Kind::Dcrd("ErrSigTooShort".into()),
                text: Some("not hashed".into()),
            }),
            Some(Answer::Reject {
                kind: Kind::Dcrd("ErrPubKeyInvalidLen".into()),
                text: Some("malformed public key: invalid length: 1".into()),
            }),
        ];
        assert_eq!(
            hex(&leaf("K-test", 7, &requests, &theirs, Status::Agree)),
            "3bf1a4c16dbf9d592e07795bab1c4ac06e7df8bd5ff481e202d035e2be747277"
        );
        let verdicts = [cmd::ecdsa_verify_raw(&[], &[0; 32], &[1; 32], &[2; 32])];
        assert_eq!(
            hex(&leaf(
                "EV-xGEN-true",
                123,
                &verdicts,
                &[Some(Answer::Verdict(true))],
                Status::Disagree
            )),
            "c12e08e38fe5a12cb775a4619bb605f0d64dd74d85c94f536c5eb77b5437a945"
        );
        assert_eq!(
            hex(&leaf(
                "EV-xGEN-true",
                0,
                &verdicts,
                &[None],
                Status::OracleFailure
            )),
            "60262e69f272aeffd7255746f8507c960dae52e708b97ed357aedd7329ee88f6"
        );
        let value = [cmd::ecdsa_recover_compact(&[0; 32], &[])];
        assert_eq!(
            hex(&leaf(
                "ER",
                u64::MAX,
                &value,
                &[Some(Answer::Value {
                    bytes: vec![2, 3],
                    flag: Some(false)
                })],
                Status::OursPanicked
            )),
            "27394083e1f3e8c62d69d354dcdf0b4b8aed353649cace11133f73d1af345005"
        );
        let mut sum = [0u8; 32];
        sum[31] = 1;
        assert_eq!(
            hex(&class_digest("K-test", 1000, &sum)),
            "be06bd1bc64d6c5c014cd81fa03f1e755c79df8b5059b557c038336f84eaa635"
        );
        assert_eq!(
            hex(&class_digest("", 0, &[0; 32])),
            "7c38d1f4e42418bf03c70268bdb44e293f61e60bc4671eb7702fdfa8144b6775"
        );
    }

    /// Each checkpoint's sum is the sum over exactly the indices below it,
    /// whatever order the leaves arrive in and however they are split
    /// between partial digests.
    #[test]
    fn checkpoints_are_prefix_sums_in_any_order() {
        let mut rng = SplitMix64(0x00d1_6e57);
        let n = 12_345u64;
        let leaves: Vec<[u8; 32]> = (0..n)
            .map(|_| {
                let mut leaf = [0u8; 32];
                rng.fill(&mut leaf);
                leaf
            })
            .collect();
        let mut order: Vec<u64> = (0..n).collect();
        for i in (1..order.len()).rev() {
            let j =
                usize::try_from(rng.below(u64::try_from(i).expect("small") + 1)).expect("small");
            order.swap(i, j);
        }
        let mut parts = [ClassDigest::new(), ClassDigest::new(), ClassDigest::new()];
        for (k, &i) in order.iter().enumerate() {
            parts[k % 3].add(i, &leaves[usize::try_from(i).expect("small")]);
        }
        let mut merged = ClassDigest::new();
        for part in &parts {
            merged.merge(part);
        }
        let prefix = |m: u64| {
            leaves[..usize::try_from(m).expect("small")]
                .iter()
                .fold([0u8; 32], |acc, l| add_be(&acc, l).0)
        };
        let rows = merged.rows("K-test", n);
        assert_eq!(
            rows.iter().map(|r| (r.n, r.is_final)).collect::<Vec<_>>(),
            [(1_000, false), (10_000, false), (n, true)]
        );
        for row in &rows {
            assert_eq!(
                row.digest,
                class_digest("K-test", row.n, &prefix(row.n)),
                "{}",
                row.n
            );
        }
        assert_eq!(merged.total(), prefix(n));
        // At a checkpoint exactly, the checkpoint is the final row only.
        let mut exact = ClassDigest::new();
        for i in 0..1_000u64 {
            exact.add(i, &leaves[usize::try_from(i).expect("small")]);
        }
        let rows = exact.rows("c", 1_000);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].is_final);
        assert_eq!(
            ClassDigest::new().rows("c", 0)[0].digest,
            class_digest("c", 0, &[0; 32])
        );
    }
}
