// SPDX-License-Identifier: ISC
//! The constant-time check ADR-0015 asks for (T10), on the paths where a
//! secret meets this crate's code: ECDSA and Ed25519 signing, the four key
//! exchanges, the three AEADs, AES-GCM's keying and HMAC.  It is dudect's
//! test (Reparaz, Balasch and Verbauwhede, "Dude, is my code constant
//! time?", 2017), written here so that it needs no crate and nothing
//! installed: an operation is timed with `std::time::Instant` on inputs of
//! fixed classes and of a random class, interleaved, and Welch's t-test
//! asks whether a fixed class's mean time differs from the random class's.
//!
//! * **Fixed classes at extremes.**  A fixed secret drawn at random has
//!   about the random class's average count of whatever a leak would key
//!   on (zero windows, set bits, leading zero limbs), so its mean time
//!   matches the random class's even where the code leaks.  Each target
//!   has several fixed classes instead, each a corner case of its secret
//!   (the scalar 1, n - 1, the top bit alone, a clamped scalar's least and
//!   greatest values), and each sample is of the random class with
//!   probability 1/2, else of one of the fixed classes chosen uniformly,
//!   the choice drawn from [`SplitMix64`].  Each fixed class is compared
//!   with the random class on its own.
//! * **Inputs built ahead, every class's the same way.**  A chunk of
//!   samples' inputs is built before any of them is timed, each from a
//!   buffer the random class's draw fills, over which a fixed class's bytes
//!   are written: a key, an exchange or a cipher made from the buffer,
//!   which is then freed.  So what building allocates and frees, and the
//!   heap the inputs lie in, does not depend on the class.  The timed
//!   region runs the operations, each on an input it borrows, and keeps
//!   their results; the inputs and the results are dropped outside it.
//!   Only an exchange's `complete` consumes its input, as it does in the
//!   provider, so that drop is timed.  A chunk's inputs fit in a core's
//!   cache ([`CHUNK_BYTES`]), so that an operation finds its input there,
//!   as the provider finds the cipher or the key it keeps.  An operation
//!   quicker than about two microseconds runs in a batch on inputs of the
//!   sample's class, sized from single operations timed with the clock's
//!   own cost included, so that a sample takes about two microseconds, of
//!   which the clock's cost and resolution are a small part.
//! * **dudect's crops.**  The first samples warm up and set the crops'
//!   thresholds, and are thrown away: crop i keeps the samples quicker than
//!   the warm-up's quantile 1 - 0.5^(10(i + 1)/100), for i from 0 to 99.
//!   Every later sample counts in the uncropped test and in each crop it is
//!   quicker than, and each fixed class is compared with the random class
//!   in every one of them that has [`MIN_SAMPLES`] samples on each side.
//! * **The verdict.**  A class fails the target when a comparison's |t| is
//!   above 10, dudect's threshold for a clear leak, and the largest
//!   difference between the class's mean time and the random class's
//!   among those comparisons is [`MIN_FAIL_NANOS`], 1 ns an operation, or
//!   more.  The largest difference, and not that of the largest |t|: a
//!   crop that cuts into the slower class's times lowers its mean, and
//!   often its spread more, so the comparison of the largest |t| can show
//!   less of the difference than the class has.  Above 10 on smaller
//!   differences alone a class is reported as under the floor, and above
//!   4.5 it is reported; both pass.  |t| grows with the root of the
//!   samples, so at the millions of samples a quick operation's run takes,
//!   a difference far below an instruction's cost crosses 10, where a
//!   secret-dependent path costs a few cycles an operation at least.  A
//!   class's result is the comparison that decides it: for a class that
//!   fails, the one of the largest difference among those above 10, and
//!   otherwise its largest |t|.  The target's row gives the class that
//!   decides the target: of the classes that fail, the one whose result
//!   has the largest |t|, or else the largest |t| of all.  Each result
//!   also gives its effect size, the difference of the means in standard
//!   deviations, and the difference in nanoseconds an operation, which say
//!   how large a difference is and, for a pass, how small a one the run
//!   could see.  The positive control, an early-exit comparison of 64
//!   bytes, must fail by the same rule, or the run fails: it shows that the
//!   clock and the measurement see a leak at all.  Its leak is far larger
//!   than any a target looks for, so finding it says nothing of a run's
//!   power.
//!
//! The targets are `#[ignore]` tests: they time code, so they run only when
//! asked, one at a time and in release mode, each for `DCROXIDE_CT_SECONDS`
//! seconds of wall time (10 when it is unset).
//!
//! ```text
//! cargo test -p dcroxide-tlscrypto --release --lib ct_check -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! `.github/workflows/constant-time.yml` runs them so, with the processor's
//! backends and with the portable ones, on x86_64 and arm64.  Each prints
//! one row, marked `ct_check row |`, which the workflow takes from the log
//! wherever on its line the test runner's own output leaves it and puts in
//! the job's summary.  The harness's own tests run in every `cargo test`
//! and time nothing: they drive it with a simulated clock.
//!
//! It is statistical.  It sees a difference large enough to show on the
//! machine that runs it, fails only on one of a nanosecond an operation or
//! more, and a pass is not a proof.  What is timed is the operation as the
//! provider runs it, so public work inside it is timed too: an ECDSA
//! signature's DER encoding branches on the signature's leading bytes,
//! which a fixed class repeats and the random class varies, and a reported
//! ECDSA target is read with that in mind.  A seal's cipher is built
//! ahead, as the provider makes one for each traffic key and seals every
//! record with it, so AES's key schedule and GHASH's key are timed by the
//! keying targets alone (ChaCha20-Poly1305 keys itself in each seal).  The
//! Ed25519 nonce target's nonce is a scalar built ahead too, where the
//! provider reduces SHA-512's output to one inside the signing that the
//! key target times.  The Ed25519 key reduces its expanded scalar mod L,
//! as RFC 8032's signing does, so what its arithmetic sees of 2^254 or
//! 2^255 - 8 is the residue; two of its classes are expanded scalars
//! within the clamp whose residues are extremes themselves, 2 and L - 1.
#![allow(
    clippy::arithmetic_side_effects,
    reason = "test-harness arithmetic over counts, lengths, bit positions and nanoseconds, \
              each far below its type's limit"
)]

use std::env;
use std::hint::black_box;
use std::time::Instant;

use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use curve25519_dalek::scalar::{Scalar, clamp_integer};
use dcroxide_testutil::{SplitMix64, unhex};
use rustls::crypto::hmac::Hmac;
use rustls::{NamedGroup, SignatureScheme};

use crate::aead::{self, RecordAead};
use crate::hmac::{HMAC_SHA256, HMAC_SHA384};
use crate::kx::exchange_with;
use crate::sign::timing;

/// |t| above which a fixed class fails its target, on a difference of
/// [`MIN_FAIL_NANOS`] an operation or more: dudect's threshold for a clear
/// leak.
const T_FAIL: f64 = 10.0;

/// |t| above which a fixed class is reported, though it passes.
const T_REPORT: f64 = 4.5;

/// The difference between a fixed class's mean time and the random
/// class's, in nanoseconds an operation, that fails the class: its
/// comparisons above [`T_FAIL`] fail it when the largest difference among
/// them is this or more, and are reported, as under the floor, when it is
/// less.  The largest difference, since a crop that cuts into the slower
/// class's times shows less of the difference than the class has, often
/// in the comparison of the largest |t|, whose spread it cut more.  |t|
/// grows with the root of the samples, so at the millions of samples a
/// quick operation's run takes, a difference far below an instruction's
/// cost crosses 10: AES-256-GCM's seal on the portable backends, 586 ns an
/// operation, failed one of two 60 s runs on one x86_64 processor at |t|
/// 13.28, on a difference of 0.07 ns that every fixed class showed alike.
/// A secret-dependent instruction path costs a few cycles an operation at
/// least, about a nanosecond at 3 to 5 GHz, which is the floor: more than
/// ten times that difference, and a third or less of what an early-exit
/// tag comparison planted in AES-128-GCM's open showed in failing at |t|
/// 2,720 and 2,819, 5.31 and 3.20 ns an operation in two runs' comparisons
/// of the largest |t|.  A smaller leak, about 4.8 ns a call planted in
/// ECDSA P-256 signing by the key, was not found at 10 or 60 seconds:
/// signing's spread, about 3.6 microseconds, puts |t| 10 at a difference
/// of a few hundred nanoseconds, a limit of the statistics and not of the
/// floor.
const MIN_FAIL_NANOS: f64 = 1.0;

/// dudect's crops, in addition to the uncropped test.
const CROPS: usize = 100;

/// The fewest samples each side of a comparison needs, in the uncropped
/// test or a crop, for its t to count.
const MIN_SAMPLES: u64 = 100;

/// The samples that warm up and set the crops, unless a tenth of the
/// budget passes first.
const WARM_UP_SAMPLES: usize = 1_000;

/// About what a sample takes: an operation quicker than this runs in a
/// batch, sized by [`batch_for`] from single operations timed with the
/// clock's own cost included, so that the clock's cost and resolution,
/// tens of nanoseconds, are a small part of each sample.
const MIN_SAMPLE_NANOS: u64 = 2_000;

/// The largest batch.
const MAX_BATCH: u64 = 1_000;

/// The operations timed one by one, on the random class, whose median
/// sizes the batch.
const CALIBRATION_OPS: usize = 33;

/// The most inputs built ahead at once, which bounds a chunk's memory.
const CHUNK_OPS: u64 = 4_096;

/// The most bytes of inputs built ahead at once, as the inputs' values
/// hold them (not the heap they point to): well within a core's
/// second-level cache, so that an operation finds its input in cache, as
/// the provider finds the cipher it seals every record with.  A chunk of
/// AES-GCM ciphers, about a kilobyte each, read from beyond the cache made
/// the fixed classes, whose ciphers are alike, slightly quicker than the
/// random class on one x86_64 processor; within this bound it did not.
const CHUNK_BYTES: u64 = 256 * 1024;

/// The timed nanoseconds a chunk aims at, which bounds the building that
/// the end of the budget wastes for a slow operation.
const CHUNK_NANOS: u64 = 100_000_000;

/// The variable that sets each target's budget, in whole seconds.
const BUDGET_VAR: &str = "DCROXIDE_CT_SECONDS";

/// Each target's budget when [`BUDGET_VAR`] is unset: the push and pull
/// request screen's.
const DEFAULT_SECONDS: u64 = 10;

/// One class's times in one test: their count, mean and sum of squared
/// deviations from the mean, kept by Welford's update as dudect keeps
/// them.
#[derive(Clone, Copy, Debug, Default)]
struct Moments {
    n: u64,
    mean: f64,
    m2: f64,
}

impl Moments {
    /// Counts the time `x`.
    fn push(&mut self, x: f64) {
        self.n += 1;
        let delta = x - self.mean;
        self.mean += delta / self.n as f64;
        self.m2 += delta * (x - self.mean);
    }

    /// The sample variance, of two times or more.
    fn variance(&self) -> f64 {
        self.m2 / (self.n - 1) as f64
    }
}

/// Welch's t of `a` against `b`, two times or more each: the difference of
/// their means over its standard error, positive when `a` is slower.
/// Infinite when the means differ and neither varies, and zero when nothing
/// differs.
fn welch_t(a: &Moments, b: &Moments) -> f64 {
    let difference = a.mean - b.mean;
    let error = (a.variance() / a.n as f64 + b.variance() / b.n as f64).sqrt();
    if error > 0.0 {
        difference / error
    } else if difference == 0.0 {
        0.0
    } else {
        f64::INFINITY.copysign(difference)
    }
}

/// The fraction of the warm-up's times under crop `i`'s threshold,
/// dudect's 1 - 0.5^(10(i + 1)/100): from about 6.7% for crop 0 to about
/// 99.9% for crop 99.
fn crop_fraction(i: usize) -> f64 {
    1.0 - 0.5f64.powf(10.0 * (i + 1) as f64 / CROPS as f64)
}

/// The crops' thresholds from the warm-up's times, sorted and not empty:
/// crop i's is the time at the index [`crop_fraction`] of their count
/// gives, rounded down.
fn crop_thresholds(sorted: &[u64]) -> Vec<u64> {
    (0..CROPS)
        .map(|i| sorted[(sorted.len() as f64 * crop_fraction(i)) as usize])
        .collect()
}

/// The comparisons of one target: for the uncropped samples and for each
/// crop, every class's [`Moments`].
struct Stats {
    /// Each crop's threshold in nanoseconds: a sample counts in crop i
    /// when it took less.
    thresholds: Vec<u64>,
    /// `tests[0]` counts every sample, and `tests[1 + i]` crop i's.  Each
    /// has a slot per class: the random class's is slot 0, and fixed class
    /// j's slot 1 + j.
    tests: Vec<Vec<Moments>>,
}

impl Stats {
    /// No samples yet of the random class and `fixed` fixed classes, with
    /// the crops the warm-up's times set.
    fn new(warm_up: &mut [u64], fixed: usize) -> Stats {
        warm_up.sort_unstable();
        Stats {
            thresholds: crop_thresholds(warm_up),
            tests: vec![vec![Moments::default(); 1 + fixed]; 1 + CROPS],
        }
    }

    /// Counts a sample of `nanos` of the class in `slot`.
    fn push(&mut self, slot: usize, nanos: u64) {
        let x = nanos as f64;
        self.tests[0][slot].push(x);
        for (crop, &threshold) in self.tests[1..].iter_mut().zip(&self.thresholds) {
            if nanos < threshold {
                crop[slot].push(x);
            }
        }
    }

    /// Each fixed class's comparisons with the random class, one in each
    /// test with [`MIN_SAMPLES`] on each side, in the tests' order: none
    /// where no test has them.
    fn by_class(&self) -> Vec<Vec<Comparison>> {
        (1..self.tests[0].len())
            .map(|slot| {
                self.tests
                    .iter()
                    .enumerate()
                    .filter(|(_, test)| test[0].n >= MIN_SAMPLES && test[slot].n >= MIN_SAMPLES)
                    .map(|(index, test)| Comparison {
                        t: welch_t(&test[slot], &test[0]),
                        test: index,
                        fixed: test[slot].n,
                        random: test[0].n,
                        fixed_mean: test[slot].mean,
                        random_mean: test[0].mean,
                    })
                    .collect()
            })
            .collect()
    }
}

/// A fixed class's comparison with the random class in one test.
#[derive(Clone, Copy, Debug, PartialEq)]
struct Comparison {
    /// Welch's t, positive when the fixed class is slower.
    t: f64,
    /// The test: 0 for every sample, 1 + i for crop i.
    test: usize,
    /// The fixed class's samples in the test.
    fixed: u64,
    /// The random class's samples in the test.
    random: u64,
    /// The fixed class's mean time a sample in the test, in nanoseconds.
    fixed_mean: f64,
    /// The random class's.
    random_mean: f64,
}

impl Comparison {
    /// The effect size: the difference of the means in standard deviations
    /// of the samples, t times the root of 1/fixed + 1/random, which with
    /// equal variances is Cohen's d.  Unlike t, it does not grow with the
    /// samples.
    fn effect(&self) -> f64 {
        self.t * (1.0 / self.fixed as f64 + 1.0 / self.random as f64).sqrt()
    }
}

/// A sample's class: the random class, `None`, with probability 1/2, and
/// otherwise one of the `fixed` fixed classes, chosen uniformly.
fn draw_class(rng: &mut SplitMix64, fixed: usize) -> Option<usize> {
    if rng.next_u64() & 1 == 0 {
        None
    } else {
        Some(rng.below(fixed as u64) as usize)
    }
}

/// The [`Stats`] slot of `class`.
fn slot(class: Option<usize>) -> usize {
    class.map_or(0, |fixed| 1 + fixed)
}

/// A monotonic clock in nanoseconds: the wall clock for the targets, and
/// a simulated one for the harness's own tests, which time nothing.
trait Clock {
    /// The nanoseconds since the clock's origin.
    fn now(&self) -> u64;
}

/// The wall clock, from an `Instant` read when it is made.
struct WallClock(Instant);

impl Clock for WallClock {
    fn now(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
}

/// The operations a sample runs, for an operation that took `op_nanos`:
/// enough for [`MIN_SAMPLE_NANOS`], one at least and [`MAX_BATCH`] at most.
fn batch_for(op_nanos: u64) -> u64 {
    MIN_SAMPLE_NANOS
        .div_ceil(op_nanos.max(1))
        .clamp(1, MAX_BATCH)
}

/// The samples a chunk builds ahead, of `batch` operations that took
/// `op_nanos` each on inputs of `input_bytes`: as many as [`CHUNK_NANOS`]
/// holds, one at least, and at most as many as [`CHUNK_OPS`] inputs, or
/// [`CHUNK_BYTES`] of them, make.
fn chunk_for(op_nanos: u64, batch: u64, input_bytes: u64) -> u64 {
    let sample = op_nanos.max(1).saturating_mul(batch);
    let inputs = CHUNK_OPS.min(CHUNK_BYTES / input_bytes.max(1));
    (CHUNK_NANOS / sample).clamp(1, (inputs / batch).max(1))
}

/// What [`measure`] found, and how.
struct Measured {
    stats: Stats,
    /// The operations each sample ran.
    batch: u64,
    /// The samples counted, after the warm-up.
    samples: u64,
    /// The samples the warm-up took and threw away.
    warm_up: usize,
    /// The nanoseconds the whole run took, its building included.
    nanos: u64,
}

/// Times `op` on inputs `build` makes, for `budget` nanoseconds of `clock`.
///
/// First [`CALIBRATION_OPS`] operations on inputs of the random class are
/// timed one by one, and their median sizes the batch ([`batch_for`]) and,
/// with the inputs' size, the chunk ([`chunk_for`]).  Then, chunk after
/// chunk, each sample's class
/// is drawn ([`draw_class`]) and its batch's inputs built, the whole
/// chunk's before any of it is timed, and each sample is timed as its
/// batch of operations, each one's input and result passed through
/// `black_box`.  An operation borrows its input, and its result is kept in
/// a vector with room for the batch, so that neither is dropped until the
/// clock has been read: the results after each sample, the inputs after
/// their chunk.  The first samples warm up and set the crops; the run ends
/// with the first sample to end past the budget.  `build` takes the class,
/// `None` for the random class, and the generator, from which the random
/// class's input is drawn.
fn measure<I, R>(
    clock: &impl Clock,
    rng: &mut SplitMix64,
    budget: u64,
    fixed: usize,
    mut build: impl FnMut(Option<usize>, &mut SplitMix64) -> I,
    mut op: impl FnMut(&mut I) -> R,
) -> Measured {
    let start = clock.now();
    let deadline = start.saturating_add(budget);
    let warm_up_end = start.saturating_add(budget / 10);

    let mut inputs: Vec<I> = (0..CALIBRATION_OPS).map(|_| build(None, rng)).collect();
    let mut results = Vec::with_capacity(1);
    let mut single = Vec::with_capacity(CALIBRATION_OPS);
    for input in &mut inputs {
        let began = clock.now();
        results.push(black_box(op(black_box(input))));
        single.push(clock.now().saturating_sub(began));
        results.clear();
    }
    drop(inputs);
    single.sort_unstable();
    let op_nanos = single[single.len() / 2];
    let batch = batch_for(op_nanos);
    let chunk = chunk_for(op_nanos, batch, size_of::<I>() as u64);
    results.reserve(batch as usize);

    let mut warm_up = Vec::new();
    let mut stats: Option<Stats> = None;
    let mut samples = 0;
    loop {
        let classes: Vec<Option<usize>> = (0..chunk).map(|_| draw_class(rng, fixed)).collect();
        let mut inputs = Vec::with_capacity((chunk * batch) as usize);
        for &class in &classes {
            for _ in 0..batch {
                inputs.push(build(class, rng));
            }
        }
        for (class, batch_inputs) in classes.into_iter().zip(inputs.chunks_mut(batch as usize)) {
            let began = clock.now();
            for input in batch_inputs {
                results.push(black_box(op(black_box(input))));
            }
            let ended = clock.now();
            results.clear();
            let nanos = ended.saturating_sub(began);
            if let Some(stats) = stats.as_mut() {
                stats.push(slot(class), nanos);
                samples += 1;
            } else {
                warm_up.push(nanos);
                if warm_up.len() >= WARM_UP_SAMPLES || ended >= warm_up_end {
                    stats = Some(Stats::new(&mut warm_up, fixed));
                }
            }
            if ended >= deadline {
                return Measured {
                    stats: stats.unwrap_or_else(|| Stats::new(&mut warm_up, fixed)),
                    batch,
                    samples,
                    warm_up: warm_up.len(),
                    nanos: ended.saturating_sub(start),
                };
            }
        }
    }
}

/// A fixed class's verdict on its comparisons, or a target's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    /// Every |t| at most [`T_REPORT`].
    Pass,
    /// A |t| above [`T_REPORT`], none above [`T_FAIL`]: reported, and a
    /// pass.
    Reported,
    /// A |t| above [`T_FAIL`], on differences under [`MIN_FAIL_NANOS`] an
    /// operation wherever |t| is above it: reported, and a pass.
    UnderFloor,
    /// A |t| above [`T_FAIL`] on a difference of [`MIN_FAIL_NANOS`] an
    /// operation or more.
    Leak,
    /// No comparison had [`MIN_SAMPLES`] on each side.
    TooFew,
}

impl Verdict {
    /// The verdict as the row gives it.
    fn word(self) -> String {
        match self {
            Verdict::Pass => "pass".to_owned(),
            Verdict::Reported => "reported".to_owned(),
            Verdict::UnderFloor => format!("reported (under the {MIN_FAIL_NANOS} ns floor)"),
            Verdict::Leak => "LEAK".to_owned(),
            Verdict::TooFew => "TOO FEW SAMPLES".to_owned(),
        }
    }
}

/// The verdict on a comparison of `t` whose fixed class's mean time
/// differs from the random class's by `difference` nanoseconds an
/// operation, which on the comparison that decides a class
/// ([`Report::deciding_in`]) is the class's.  A t or a difference that is
/// not a number, which no comparison gives, fails.
fn verdict(t: f64, difference: f64) -> Verdict {
    let (t, difference) = (t.abs(), difference.abs());
    if t.is_nan() || difference.is_nan() || (t > T_FAIL && difference >= MIN_FAIL_NANOS) {
        Verdict::Leak
    } else if t > T_FAIL {
        Verdict::UnderFloor
    } else if t > T_REPORT {
        Verdict::Reported
    } else {
        Verdict::Pass
    }
}

/// A target's result: each fixed class's comparisons, and the run.
struct Report {
    target: String,
    /// The fixed classes' names.
    names: Vec<&'static str>,
    /// Each fixed class's comparisons, one in each test with
    /// [`MIN_SAMPLES`] on each side.
    by_class: Vec<Vec<Comparison>>,
    batch: u64,
    samples: u64,
    warm_up: usize,
    seconds: f64,
}

impl Report {
    /// The report of the target `target`, whose fixed classes are `names`,
    /// on what [`measure`] found.
    fn new(target: &str, names: Vec<&'static str>, measured: &Measured) -> Report {
        Report {
            target: target.to_owned(),
            names,
            by_class: measured.stats.by_class(),
            batch: measured.batch,
            samples: measured.samples,
            warm_up: measured.warm_up,
            seconds: measured.nanos as f64 / 1e9,
        }
    }

    /// The comparison that decides the verdict of the fixed class whose
    /// comparisons are `comparisons`, and that its detail prints: of those
    /// with |t| above [`T_FAIL`], the one of the largest difference an
    /// operation, when it is [`MIN_FAIL_NANOS`] or more, and else the one
    /// of the largest |t|.  The largest difference, since a crop that cuts
    /// into the slower class's times shows less of the difference than the
    /// class has, often in the comparison of the largest |t|, whose spread
    /// it cut more; `None` when there is no comparison.
    fn deciding_in(&self, comparisons: &[Comparison]) -> Option<Comparison> {
        let difference = |c: &Comparison| self.per_op(c).1.abs();
        comparisons
            .iter()
            .filter(|c| c.t.abs() > T_FAIL)
            .max_by(|a, b| difference(a).total_cmp(&difference(b)))
            .filter(|c| self.verdict_of(c) == Verdict::Leak)
            .or_else(|| {
                comparisons
                    .iter()
                    .max_by(|a, b| a.t.abs().total_cmp(&b.t.abs()))
            })
            .copied()
    }

    /// The fixed class that decides the target's verdict, and the
    /// comparison that decides the class's ([`Report::deciding_in`]): of
    /// the classes that fail, the one whose comparison has the largest
    /// |t|, or else the largest |t| of all.
    fn deciding(&self) -> Option<(usize, Comparison)> {
        let fails = |c: &Comparison| self.verdict_of(c) == Verdict::Leak;
        self.by_class
            .iter()
            .enumerate()
            .filter_map(|(class, comparisons)| self.deciding_in(comparisons).map(|c| (class, c)))
            .max_by(|a, b| {
                fails(&a.1)
                    .cmp(&fails(&b.1))
                    .then(a.1.t.abs().total_cmp(&b.1.t.abs()))
            })
    }

    fn verdict(&self) -> Verdict {
        self.deciding()
            .map_or(Verdict::TooFew, |(_, c)| self.verdict_of(&c))
    }

    /// The verdict on `c`, its t and its difference an operation.
    fn verdict_of(&self, c: &Comparison) -> Verdict {
        verdict(c.t, self.per_op(c).1)
    }

    /// The random class's mean time an operation in `c`'s test, and the
    /// fixed class's difference from it, in nanoseconds.
    fn per_op(&self, c: &Comparison) -> (f64, f64) {
        let batch = self.batch as f64;
        (
            c.random_mean / batch,
            (c.fixed_mean - c.random_mean) / batch,
        )
    }

    /// The line the workflow's summary takes: the target, the deciding
    /// class's t, its effect size, the random class's nanoseconds an
    /// operation and the fixed class's difference from them, its class and
    /// test, the samples on each side of it, the samples counted and the
    /// batch, and `verdict`.
    fn row(&self, verdict: &str) -> String {
        let deciding = match self.deciding() {
            Some((class, c)) => {
                let (random, difference) = self.per_op(&c);
                format!(
                    "{:+.2} | {:+.3} | {random:.1} | {difference:+.2} | {} | {} | {} | {}",
                    c.t,
                    c.effect(),
                    self.names[class],
                    test_name(c.test),
                    c.fixed,
                    c.random
                )
            }
            None => "- | - | - | - | - | - | - | -".to_owned(),
        };
        format!(
            "ct_check row | {} | {deciding} | {} | {} | {verdict} |",
            self.target, self.samples, self.batch
        )
    }

    /// Every fixed class's deciding comparison and its verdict, a line
    /// each, and the run.
    fn detail(&self) -> String {
        let mut out = format!(
            "{} samples of {} operations after {} to warm up, in {:.1} s\n",
            self.samples, self.batch, self.warm_up, self.seconds
        );
        for (name, comparisons) in self.names.iter().zip(&self.by_class) {
            out += &match self.deciding_in(comparisons) {
                Some(c) => {
                    let (random, difference) = self.per_op(&c);
                    format!(
                        "  {name}: t {:+.2}, effect {:+.3}, {difference:+.2} ns an operation \
                         against {random:.1}, in {}, {} samples against {}, {}\n",
                        c.t,
                        c.effect(),
                        test_name(c.test),
                        c.fixed,
                        c.random,
                        self.verdict_of(&c).word()
                    )
                }
                None => format!("  {name}: no test with {MIN_SAMPLES} samples on each side\n"),
            };
        }
        out
    }

    /// Prints the row, and fails when a fixed class has a comparison of
    /// |t| above [`T_FAIL`] on a difference of [`MIN_FAIL_NANOS`] an
    /// operation or more, or no comparison had the samples to count.
    fn assert_constant_time(&self) {
        let verdict = self.verdict();
        println!("{}", self.row(&verdict.word()));
        match verdict {
            Verdict::Pass | Verdict::Reported | Verdict::UnderFloor => {}
            Verdict::Leak => panic!(
                "{}: a fixed class's time differs from the random class's, |t| above {T_FAIL} \
                 and by {MIN_FAIL_NANOS} ns an operation or more\n{}",
                self.target,
                self.detail()
            ),
            Verdict::TooFew => panic!(
                "{}: no comparison had {MIN_SAMPLES} samples on each side; \
                 raise {BUDGET_VAR}\n{}",
                self.target,
                self.detail()
            ),
        }
    }

    /// The positive control's check: prints the row, and fails unless the
    /// control fails by the targets' rule, a comparison of |t| above
    /// [`T_FAIL`] on a difference of [`MIN_FAIL_NANOS`] an operation or
    /// more, since a run that does not see the control's leak, far larger
    /// than any a target looks for, sees none: its clock or its
    /// measurement is broken.
    fn assert_leak_found(&self) {
        let found = self.verdict() == Verdict::Leak;
        println!(
            "{}",
            self.row(if found {
                "control found"
            } else {
                "CONTROL NOT FOUND"
            })
        );
        assert!(
            found,
            "{}: the control's leak was not found, no comparison of |t| above {T_FAIL} on \
             {MIN_FAIL_NANOS} ns an operation or more: this run's clock or measurement does not \
             see a leak\n{}",
            self.target,
            self.detail()
        );
    }
}

/// The name of test `test`: every sample, or a crop by the fraction of the
/// warm-up's times it keeps.
fn test_name(test: usize) -> String {
    match test.checked_sub(1) {
        None => "all samples".to_owned(),
        Some(crop) => format!("crop {crop} ({:.1}%)", 100.0 * crop_fraction(crop)),
    }
}

/// The budget [`BUDGET_VAR`]'s value gives each target, in seconds: a
/// whole number above zero, or [`DEFAULT_SECONDS`] when it is unset.
fn budget_seconds(value: Option<&str>) -> Result<u64, String> {
    let Some(value) = value else {
        return Ok(DEFAULT_SECONDS);
    };
    match value.parse::<u64>() {
        Ok(seconds) if seconds > 0 => Ok(seconds),
        _ => Err(format!(
            "{BUDGET_VAR}={value:?} is not a whole number of seconds above zero"
        )),
    }
}

/// The inputs of a target whose fixed classes are `classes`, by the
/// sample's class, every class's the same way: `draw` fills a buffer, a
/// fixed class's bytes are written over it, of the same length, and
/// `build` makes the input from it before it is freed.  So what building
/// allocates and frees, and the heap the inputs lie in, does not depend on
/// the class.
fn by_class<I>(
    classes: &[(&'static str, Vec<u8>)],
    mut draw: impl FnMut(&mut SplitMix64) -> Vec<u8>,
    mut build: impl FnMut(&[u8]) -> I,
) -> impl FnMut(Option<usize>, &mut SplitMix64) -> I {
    move |class, rng| {
        let mut bytes = draw(rng);
        if let Some(fixed) = class {
            bytes.copy_from_slice(&classes[fixed].1);
        }
        build(&bytes)
    }
}

/// Times `op` as the target `target`, for the budget [`BUDGET_VAR`] gives,
/// on inputs made from byte strings by [`by_class`]: each fixed class's
/// own, and for the random class one that `draw` makes.
fn time_target<I, R>(
    target: &str,
    classes: &[(&'static str, Vec<u8>)],
    draw: impl FnMut(&mut SplitMix64) -> Vec<u8>,
    build: impl FnMut(&[u8]) -> I,
    op: impl FnMut(&mut I) -> R,
) -> Report {
    let value = env::var_os(BUDGET_VAR);
    let value = value.as_deref().map(|value| value.to_string_lossy());
    let seconds = budget_seconds(value.as_deref()).unwrap_or_else(|e| panic!("{e}"));
    let mut rng = SplitMix64::from_entropy(target);
    let measured = measure(
        &WallClock(Instant::now()),
        &mut rng,
        seconds * 1_000_000_000,
        classes.len(),
        by_class(classes, draw, build),
        op,
    );
    let names = classes.iter().map(|(name, _)| *name).collect();
    Report::new(target, names, &measured)
}

/// `value` plus `delta`, big-endian at its own length.
fn plus(value: &[u8], delta: i16) -> Vec<u8> {
    let mut out = value.to_vec();
    let mut carry = i32::from(delta);
    for byte in out.iter_mut().rev() {
        let sum = i32::from(*byte) + carry;
        *byte = sum.rem_euclid(256) as u8;
        carry = sum.div_euclid(256);
    }
    assert_eq!(carry, 0, "{value:02x?} plus {delta} leaves its length");
    out
}

/// `value` times `factor`, big-endian at its own length.
fn times(value: &[u8], factor: u8) -> Vec<u8> {
    let mut out = value.to_vec();
    let mut carry = 0u16;
    for byte in out.iter_mut().rev() {
        let product = u16::from(*byte) * u16::from(factor) + carry;
        *byte = product as u8;
        carry = product >> 8;
    }
    assert_eq!(carry, 0, "{value:02x?} times {factor} leaves its length");
    out
}

/// Bit `at` of the big-endian `value`, bit 0 the least significant.
fn bit(value: &[u8], at: usize) -> bool {
    value[value.len() - 1 - at / 8] >> (at % 8) & 1 == 1
}

/// Sets bit `at` of the big-endian `value` to `on`.
fn set_bit(value: &mut [u8], at: usize, on: bool) {
    let index = value.len() - 1 - at / 8;
    let mask = 1 << (at % 8);
    if on {
        value[index] |= mask;
    } else {
        value[index] &= !mask;
    }
}

/// The big-endian `value` with eight of its set bits cleared, spread over
/// them evenly from the lowest.
fn clear_eight(value: &[u8]) -> Vec<u8> {
    let set: Vec<usize> = (0..8 * value.len()).filter(|&at| bit(value, at)).collect();
    let mut out = value.to_vec();
    for i in 0..8 {
        set_bit(&mut out, set[i * set.len() / 8], false);
    }
    out
}

/// The classes in `candidates` but those whose value an earlier one has.
fn distinct(candidates: Vec<(&'static str, Vec<u8>)>) -> Vec<(&'static str, Vec<u8>)> {
    let mut out: Vec<(&'static str, Vec<u8>)> = Vec::new();
    for (name, value) in candidates {
        if out.iter().all(|(_, earlier)| *earlier != value) {
            out.push((name, value));
        }
    }
    out
}

/// A NIST curve as the targets take it.
struct Nist {
    /// The ECDSA scheme its keys sign with.
    scheme: SignatureScheme,
    /// Its key exchange group.
    group: NamedGroup,
    /// Its order, big-endian at the field's length.
    order: &'static str,
}

const P256: Nist = Nist {
    scheme: SignatureScheme::ECDSA_NISTP256_SHA256,
    group: NamedGroup::secp256r1,
    order: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
};

const P384: Nist = Nist {
    scheme: SignatureScheme::ECDSA_NISTP384_SHA384,
    group: NamedGroup::secp384r1,
    order: "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
            581a0db248b0a77aecec196accc52973",
};

const P521: Nist = Nist {
    scheme: SignatureScheme::ECDSA_NISTP521_SHA512,
    group: NamedGroup::secp521r1,
    order: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
            fffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
};

/// The fixed classes of a NIST curve's scalars, for the curve of order
/// `order`, big-endian at the field's length: 1, 2, 0xff, 2^64 - 1 (every
/// limb but the lowest zero), the top bit alone (the largest power of two
/// below n), n - 1 and n - 2; n - 1 with its bottom half zero, and with its
/// top half zero; eight set bits, spread, and n - 1 with eight of its set
/// bits cleared, spread; and n - 1 with every 4-bit window but the top one
/// zero.  A class whose value an earlier one has is left out: on P-521 the
/// top window holds the order's one top bit, so it is the top bit alone.
fn nist_classes(order: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let len = order.len();
    let bits = 8 * len - order[0].leading_zeros() as usize;
    let zero = vec![0; len];
    let n_minus_1 = plus(order, -1);
    let mut ones_64 = zero.clone();
    ones_64[len - 8..].fill(0xff);
    let mut top_bit = zero.clone();
    set_bit(&mut top_bit, bits - 1, true);
    let mut bottom_zero = n_minus_1.clone();
    bottom_zero[len - len / 2..].fill(0);
    let mut top_zero = n_minus_1.clone();
    top_zero[..len - len / 2].fill(0);
    let mut low_weight = zero.clone();
    for i in 0..8 {
        set_bit(&mut low_weight, i * ((bits - 1) / 8), true);
    }
    let mut windows = n_minus_1.clone();
    for at in 0..4 * ((bits - 1) / 4) {
        set_bit(&mut windows, at, false);
    }
    distinct(vec![
        ("1", plus(&zero, 1)),
        ("2", plus(&zero, 2)),
        ("0xff", plus(&zero, 0xff)),
        ("2^64 - 1", ones_64),
        ("top bit alone", top_bit),
        ("n - 1", n_minus_1.clone()),
        ("n - 2", plus(order, -2)),
        ("bottom half zero", bottom_zero),
        ("top half zero", top_zero),
        ("low weight", low_weight),
        ("high weight", clear_eight(&n_minus_1)),
        ("top window alone", windows),
    ])
}

/// A random scalar of the curve of order `order`: the field's length in
/// bytes, the first masked to the order's bit length, drawn until it is in
/// `[1, n)`.
fn random_scalar(order: &[u8], rng: &mut SplitMix64) -> Vec<u8> {
    let mut scalar = vec![0; order.len()];
    loop {
        rng.fill(&mut scalar);
        scalar[0] &= u8::MAX >> order[0].leading_zeros();
        if scalar.iter().any(|&byte| byte != 0) && scalar.as_slice() < order {
            return scalar;
        }
    }
}

/// The scalar the targets fix where the scalar is not what they vary: 0x5a
/// repeated, masked as [`random_scalar`] masks a draw.
fn fixed_scalar(order: &[u8]) -> Vec<u8> {
    let mut scalar = vec![0x5a; order.len()];
    scalar[0] &= u8::MAX >> order[0].leading_zeros();
    scalar
}

/// A 32-byte little-endian value from its big-endian bytes.
fn little_endian(big_endian: &[u8]) -> Vec<u8> {
    big_endian.iter().rev().copied().collect()
}

/// L, the order of Curve25519's prime subgroup, big-endian.
fn curve25519_order() -> Vec<u8> {
    plus(&little_endian(&(-Scalar::ONE).to_bytes()), 1)
}

/// The clamped scalars of low and high weight, big-endian: eight bits
/// set, 2^254 and seven more spread over bits 3 to 253, and 2^255 - 8
/// with eight bits cleared, spread over the same bits.
fn clamped_weights() -> [Vec<u8>; 2] {
    let mut low = vec![0; 32];
    set_bit(&mut low, 254, true);
    for i in 0..7 {
        set_bit(&mut low, 3 + 36 * i, true);
    }
    let mut high = vec![0; 32];
    for at in 3..255 {
        set_bit(&mut high, at, true);
    }
    for i in 0..8 {
        set_bit(&mut high, 3 + 31 * i, false);
    }
    [low, high]
}

/// The fixed classes of an Ed25519 expanded scalar, little-endian, each
/// within the clamp (bits 0 to 2 clear, bit 254 set, bit 255 clear): the
/// least, 2^254, the next, 2^254 + 8, and the greatest, 2^255 - 8; low
/// and high weight (eight bits set, eight cleared); and 6L + 2 and 5L - 1,
/// whose residues mod L, what the key's arithmetic sees, are 2 and L - 1.
fn ed25519_scalar_classes() -> Vec<(&'static str, Vec<u8>)> {
    let mut least = vec![0; 32];
    set_bit(&mut least, 254, true);
    let mut next = least.clone();
    set_bit(&mut next, 3, true);
    let mut greatest = vec![0; 32];
    for at in 3..255 {
        set_bit(&mut greatest, at, true);
    }
    let [low, high] = clamped_weights();
    let order = curve25519_order();
    [
        ("2^254", least),
        ("2^254 + 8", next),
        ("2^255 - 8", greatest),
        ("low weight", low),
        ("high weight", high),
        ("6L + 2, residue 2", plus(&times(&order, 6), 2)),
        ("5L - 1, residue L - 1", plus(&times(&order, 5), -1)),
    ]
    .into_iter()
    .map(|(name, value)| (name, little_endian(&value)))
    .collect()
}

/// The fixed classes of an Ed25519 nonce, little-endian and below L: 0, 1
/// and L - 1, eight set bits spread below 2^252, and L - 1 with eight of
/// its set bits cleared.
fn ed25519_nonce_classes() -> Vec<(&'static str, Vec<u8>)> {
    let zero = vec![0; 32];
    let l_minus_1 = plus(&curve25519_order(), -1);
    let mut low = zero.clone();
    for i in 0..8 {
        set_bit(&mut low, 31 * i, true);
    }
    [
        ("0", zero.clone()),
        ("1", plus(&zero, 1)),
        ("L - 1", l_minus_1.clone()),
        ("low weight", low),
        ("high weight", clear_eight(&l_minus_1)),
    ]
    .into_iter()
    .map(|(name, value)| (name, little_endian(&value)))
    .collect()
}

/// The fixed classes of an X25519 secret, as drawn: all zeros and all
/// ones, which clamp to 2^254 and 2^255 - 8, and the clamped scalars of
/// low and high weight (eight bits set, eight cleared).
fn x25519_classes() -> Vec<(&'static str, Vec<u8>)> {
    let [low, high] = clamped_weights();
    vec![
        ("all zeros", vec![0; 32]),
        ("all ones", vec![0xff; 32]),
        ("low weight", little_endian(&low)),
        ("high weight", little_endian(&high)),
    ]
}

/// The fixed classes of an AEAD key of `len` bytes: all zeros, all ones,
/// and 0x55 and 0xaa in turn.
fn aead_key_classes(len: usize) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("all zeros", vec![0; len]),
        ("all ones", vec![0xff; len]),
        ("0x55 and 0xaa", [0x55, 0xaa].repeat(len / 2)),
    ]
}

/// The fixed classes of an HMAC key of `len` bytes: all zeros, all ones,
/// and one bit set, the first.
fn hmac_key_classes(len: usize) -> Vec<(&'static str, Vec<u8>)> {
    let mut one_bit = vec![0; len];
    one_bit[0] = 0x80;
    vec![
        ("all zeros", vec![0; len]),
        ("all ones", vec![0xff; len]),
        ("one bit set", one_bit),
    ]
}

/// The fixed classes of a bad tag for the right one, `tag`: wrong in its
/// first byte, and wrong in its last.
fn bad_tag_classes(tag: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let mut first = tag.to_vec();
    first[0] ^= 1;
    let mut last = tag.to_vec();
    last[tag.len() - 1] ^= 1;
    vec![("wrong first byte", first), ("wrong last byte", last)]
}

/// `len` random bytes.
fn random_bytes(rng: &mut SplitMix64, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    rng.fill(&mut bytes);
    bytes
}

/// A random Ed25519 expanded scalar: 32 random bytes, clamped, as a seed's
/// hash is.
fn random_clamped(rng: &mut SplitMix64) -> Vec<u8> {
    let mut scalar = [0; 32];
    rng.fill(&mut scalar);
    clamp_integer(scalar).to_vec()
}

/// A random Ed25519 nonce: 64 random bytes reduced mod L, as RFC 8032
/// reduces SHA-512's.
fn random_nonce(rng: &mut SplitMix64) -> Vec<u8> {
    let mut wide = [0; 64];
    rng.fill(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide).to_bytes().to_vec()
}

/// The Ed25519 nonce whose canonical encoding is `r`, which is below L.
fn nonce_scalar(r: [u8; 32]) -> Scalar {
    Option::from(Scalar::from_canonical_bytes(r)).expect("a nonce below L")
}

/// A random tag other than `tag`.
fn wrong_tag(tag: &[u8], rng: &mut SplitMix64) -> Vec<u8> {
    loop {
        let wrong = random_bytes(rng, tag.len());
        if wrong != tag {
            return wrong;
        }
    }
}

/// The positive control's random class: 64 random bytes whose first
/// differs from [`REFERENCE`]'s.
fn control_input(rng: &mut SplitMix64) -> Vec<u8> {
    let mut bytes = random_bytes(rng, REFERENCE.len());
    bytes[0] = !REFERENCE[0];
    bytes
}

/// The message the signing targets sign.
const MESSAGE: &[u8] = b"a TLS 1.3 CertificateVerify's content";

/// The Ed25519 prefix the targets fix.
const PREFIX: [u8; 32] = [0x3c; 32];

/// The record the AEAD targets seal: 64 bytes of content.
const RECORD: [u8; 64] = [0x17; 64];

/// The record's nonce.
const NONCE: [u8; 12] = [0x24; 12];

/// The record's additional data: a TLS 1.3 record's header, for the
/// content and the tag, 80 bytes.
const AAD: [u8; 5] = [0x17, 0x03, 0x03, 0x00, 0x50];

/// The data the HMAC targets authenticate.
const HMAC_MESSAGE: &[u8] = b"tls13 derived";

/// What the positive control compares with.
const REFERENCE: [u8; 64] = [0x5a; 64];

/// ECDSA signing on `curve` by the key's extremes, with the message and the
/// hedge fixed, so that RFC 6979's nonce follows the key as it does in the
/// handshake signer.
fn ecdsa_signing_by_key(target: &str, curve: &Nist) {
    let order = unhex(curve.order);
    let hedge = vec![0xa5; order.len()];
    time_target(
        target,
        &nist_classes(&order),
        |rng| random_scalar(&order, rng),
        |scalar| timing::Ecdsa::new(curve.scheme, scalar).expect("a scalar in [1, n)"),
        |key| key.sign_hedged(MESSAGE, &hedge),
    )
    .assert_constant_time();
}

/// ECDSA signing on `curve` by the nonce's extremes, with the key fixed:
/// the nonce reaches `k.invert()` and `mul_by_generator`
/// (`ecdsa-0.17.0/src/hazmat.rs:64-67`), and RFC 6979's nonce never lands
/// on an extreme of its own.
fn ecdsa_signing_by_nonce(target: &str, curve: &Nist) {
    let order = unhex(curve.order);
    let key = timing::Ecdsa::new(curve.scheme, &fixed_scalar(&order)).expect("the fixed key");
    time_target(
        target,
        &nist_classes(&order),
        |rng| random_scalar(&order, rng),
        <[u8]>::to_vec,
        |nonce| key.sign_with_nonce(nonce, MESSAGE),
    )
    .assert_constant_time();
}

/// The exchange on `group` completed by its secret's extremes, `classes`,
/// with the peer's share fixed; `draw` draws the random class's secret.
/// `complete` consumes its exchange, as it does in the provider, so the
/// input holds it in an `Option` for the operation to take.
fn exchange_complete(
    target: &str,
    group: NamedGroup,
    classes: &[(&'static str, Vec<u8>)],
    peer_secret: &[u8],
    draw: impl FnMut(&mut SplitMix64) -> Vec<u8>,
) {
    let peer = exchange_with(group, peer_secret)
        .expect("the peer's secret")
        .pub_key()
        .to_vec();
    time_target(
        target,
        classes,
        draw,
        |secret| Some(exchange_with(group, secret).expect("a secret the group takes")),
        |exchange| {
            exchange
                .take()
                .expect("each exchange completed once")
                .complete(&peer)
        },
    )
    .assert_constant_time();
}

/// The step `start` runs on `group` once its secret is drawn: the exchange
/// made from the secret, whose public key that computes, by the secret's
/// extremes, `classes`; `draw` draws the random class's.
fn exchange_public(
    target: &str,
    group: NamedGroup,
    classes: &[(&'static str, Vec<u8>)],
    draw: impl FnMut(&mut SplitMix64) -> Vec<u8>,
) {
    time_target(target, classes, draw, <[u8]>::to_vec, |secret| {
        exchange_with(group, secret)
    })
    .assert_constant_time();
}

/// Sealing a record with the AEAD `A` by the key's extremes, with a cipher
/// built ahead, as the provider seals every record with the one it keyed
/// for the traffic key.
fn aead_seal<A: RecordAead>(target: &str) {
    let len = A::key_size();
    time_target(
        target,
        &aead_key_classes(len),
        |rng| random_bytes(rng, len),
        |key| A::new_from_slice(key).expect("a key of the AEAD's length"),
        |aead| {
            let mut record = RECORD;
            let tag = aead::seal(aead, NONCE, &AAD, &mut record);
            (record, tag)
        },
    )
    .assert_constant_time();
}

/// Keying the AEAD `A` by the key's extremes, as the provider keys one for
/// each traffic key: for AES-GCM, AES's key schedule and GHASH's key, the
/// encryption of zeros, which the seal targets make ahead.
fn aead_key<A: RecordAead>(target: &str) {
    let len = A::key_size();
    time_target(
        target,
        &aead_key_classes(len),
        |rng| random_bytes(rng, len),
        <[u8]>::to_vec,
        |key| A::new_from_slice(key),
    )
    .assert_constant_time();
}

/// Opening a record with the AEAD `A` by where its tag is wrong: in its
/// first byte or its last, against wrong at random.
fn aead_open_bad_tag<A: RecordAead>(target: &str) {
    let aead = A::new_from_slice(&vec![0x5a; A::key_size()]).expect("a key of the AEAD's length");
    let mut record = RECORD;
    let tag = aead::seal(&aead, NONCE, &AAD, &mut record).expect("sealed");
    time_target(
        target,
        &bad_tag_classes(&tag),
        |rng| wrong_tag(&tag, rng),
        |wrong| [&record[..], wrong].concat(),
        |sealed| aead::open(&aead, NONCE, &AAD, sealed),
    )
    .assert_constant_time();
}

/// Keying `hmac` and making a tag, by the key's extremes, keys of the
/// hash's length.
fn hmac_key(target: &str, hmac: &dyn Hmac) {
    let len = hmac.hash_output_len();
    time_target(
        target,
        &hmac_key_classes(len),
        |rng| random_bytes(rng, len),
        <[u8]>::to_vec,
        |key| hmac.with_key(key).sign(&[HMAC_MESSAGE]),
    )
    .assert_constant_time();
}

/// The positive control's comparison, which returns at the first byte that
/// differs and so leaks where that is.  `black_box` keeps it a byte at a
/// time, as written, where the compiler could make it a wider comparison
/// whose leak is too small to be a control.
fn leaky_eq(a: &[u8; 64], b: &[u8; 64]) -> bool {
    for (x, y) in a.iter().zip(b) {
        if black_box(*x) != black_box(*y) {
            return false;
        }
    }
    true
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdsa_p256_signing_by_key() {
    ecdsa_signing_by_key("ecdsa_p256_signing_by_key", &P256);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdsa_p384_signing_by_key() {
    ecdsa_signing_by_key("ecdsa_p384_signing_by_key", &P384);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdsa_p521_signing_by_key() {
    ecdsa_signing_by_key("ecdsa_p521_signing_by_key", &P521);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdsa_p256_signing_by_nonce() {
    ecdsa_signing_by_nonce("ecdsa_p256_signing_by_nonce", &P256);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdsa_p384_signing_by_nonce() {
    ecdsa_signing_by_nonce("ecdsa_p384_signing_by_nonce", &P384);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdsa_p521_signing_by_nonce() {
    ecdsa_signing_by_nonce("ecdsa_p521_signing_by_nonce", &P521);
}

/// [`exchange_complete`] on `curve`, by the scalar's extremes.
fn nist_complete(target: &str, curve: &Nist) {
    let order = unhex(curve.order);
    exchange_complete(
        target,
        curve.group,
        &nist_classes(&order),
        &fixed_scalar(&order),
        |rng| random_scalar(&order, rng),
    );
}

/// [`exchange_public`] on `curve`, by the scalar's extremes.
fn nist_public(target: &str, curve: &Nist) {
    let order = unhex(curve.order);
    exchange_public(target, curve.group, &nist_classes(&order), |rng| {
        random_scalar(&order, rng)
    });
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdh_p256_complete() {
    nist_complete("ecdh_p256_complete", &P256);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdh_p384_complete() {
    nist_complete("ecdh_p384_complete", &P384);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdh_p521_complete() {
    nist_complete("ecdh_p521_complete", &P521);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdh_p256_public_key() {
    nist_public("ecdh_p256_public_key", &P256);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdh_p384_public_key() {
    nist_public("ecdh_p384_public_key", &P384);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ecdh_p521_public_key() {
    nist_public("ecdh_p521_public_key", &P521);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn x25519_complete() {
    exchange_complete(
        "x25519_complete",
        NamedGroup::X25519,
        &x25519_classes(),
        &[0x5a; 32],
        |rng| random_bytes(rng, 32),
    );
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn x25519_public_key() {
    exchange_public(
        "x25519_public_key",
        NamedGroup::X25519,
        &x25519_classes(),
        |rng| random_bytes(rng, 32),
    );
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ed25519_signing_by_key() {
    time_target(
        "ed25519_signing_by_key",
        &ed25519_scalar_classes(),
        random_clamped,
        |scalar| timing::Ed25519::new(scalar.try_into().expect("32 bytes"), PREFIX),
        |key| key.sign(MESSAGE),
    )
    .assert_constant_time();
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn ed25519_signing_by_nonce() {
    let key = timing::Ed25519::new(clamp_integer([0x5a; 32]), PREFIX);
    time_target(
        "ed25519_signing_by_nonce",
        &ed25519_nonce_classes(),
        random_nonce,
        |r| nonce_scalar(r.try_into().expect("32 bytes")),
        |r| key.sign_with_nonce(r, MESSAGE),
    )
    .assert_constant_time();
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn aes_128_gcm_seal() {
    aead_seal::<Aes128Gcm>("aes_128_gcm_seal");
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn aes_256_gcm_seal() {
    aead_seal::<Aes256Gcm>("aes_256_gcm_seal");
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn chacha20_poly1305_seal() {
    aead_seal::<ChaCha20Poly1305>("chacha20_poly1305_seal");
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn aes_128_gcm_key() {
    aead_key::<Aes128Gcm>("aes_128_gcm_key");
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn aes_256_gcm_key() {
    aead_key::<Aes256Gcm>("aes_256_gcm_key");
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn aes_128_gcm_open_bad_tag() {
    aead_open_bad_tag::<Aes128Gcm>("aes_128_gcm_open_bad_tag");
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn aes_256_gcm_open_bad_tag() {
    aead_open_bad_tag::<Aes256Gcm>("aes_256_gcm_open_bad_tag");
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn chacha20_poly1305_open_bad_tag() {
    aead_open_bad_tag::<ChaCha20Poly1305>("chacha20_poly1305_open_bad_tag");
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn hmac_sha256_key() {
    hmac_key("hmac_sha256_key", &HMAC_SHA256);
}

#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn hmac_sha384_key() {
    hmac_key("hmac_sha384_key", &HMAC_SHA384);
}

/// The positive control: the early-exit comparison with all 64 bytes
/// equal, against inputs that differ in their first byte.
#[test]
#[ignore = "times code: run by .github/workflows/constant-time.yml"]
fn positive_control() {
    time_target(
        "positive_control",
        &[("equal", REFERENCE.to_vec())],
        control_input,
        |bytes| <[u8; 64]>::try_from(bytes).expect("64 bytes"),
        |bytes| leaky_eq(bytes, &REFERENCE),
    )
    .assert_leak_found();
}

mod tests {
    use std::cell::{Cell, RefCell};

    use ::hmac::{KeyInit, Mac};
    use curve25519_dalek::edwards::EdwardsPoint;
    use curve25519_dalek::montgomery::MontgomeryPoint;
    use ecdsa::signature::Verifier;
    use rustls::Error;
    use sha2::{Digest, Sha256, Sha384, Sha512};

    use super::*;
    use crate::verify;

    /// A clock the harness's tests move by hand: each simulated operation
    /// advances it, and nothing is timed.
    struct Simulated(Cell<u64>);

    impl Clock for Simulated {
        fn now(&self) -> u64 {
            self.0.get()
        }
    }

    impl Simulated {
        fn advance(&self, nanos: u64) {
            self.0.set(self.0.get() + nanos);
        }
    }

    /// The fixed classes of the simulated target.
    const SIMULATED: [&str; 4] = ["a", "b", "c", "d"];

    /// [`measure`] on a simulated target of four fixed classes for `budget`
    /// simulated nanoseconds: each operation advances the clock by what
    /// `nanos` gives for its class and a number its input drew below
    /// `draw`.  Every operation's class and duration, in the order run.
    fn simulate_with(
        budget: u64,
        draw: u64,
        nanos: impl Fn(Option<usize>, u64) -> u64,
    ) -> (Measured, Vec<(Option<usize>, u64)>) {
        let clock = Simulated(Cell::new(0));
        let ran = RefCell::new(Vec::new());
        let mut rng = SplitMix64(0x7369_6d75_6c61_7465);
        let measured = measure(
            &clock,
            &mut rng,
            budget,
            SIMULATED.len(),
            |class, rng| (class, rng.below(draw)),
            |&mut (class, drawn): &mut (Option<usize>, u64)| {
                let nanos = nanos(class, drawn);
                clock.advance(nanos);
                ran.borrow_mut().push((class, nanos));
            },
        );
        (measured, ran.into_inner())
    }

    /// [`simulate_with`] where each operation takes 500 ns, its input's
    /// noise, drawn up to 1,000 ns, and `leak` more for fixed class 2.
    fn simulate(budget: u64, leak: u64) -> (Measured, Vec<(Option<usize>, u64)>) {
        simulate_with(budget, 1_000, |class, noise| {
            500 + noise + if class == Some(2) { leak } else { 0 }
        })
    }

    /// The report on [`simulate`]'s run.
    fn simulated_report(budget: u64, leak: u64) -> Report {
        Report::new("simulated", SIMULATED.to_vec(), &simulate(budget, leak).0)
    }

    /// The report on a simulated run of operations quick enough to batch,
    /// 10 to 13 ns, in which fixed class 2 takes `extra` ns more in half of
    /// its operations, drawn: a difference of half of `extra` an operation,
    /// which whole nanoseconds of the clock show through the batch, with
    /// so little noise that |t| is far above [`T_FAIL`].
    fn floor_report(extra: u64) -> Report {
        let (measured, _) = simulate_with(40_000_000, 8, |class, drawn| {
            10 + drawn % 4
                + if class == Some(2) && drawn >= 4 {
                    extra
                } else {
                    0
                }
        });
        Report::new("simulated", SIMULATED.to_vec(), &measured)
    }

    fn moments(xs: &[f64]) -> Moments {
        let mut m = Moments::default();
        for &x in xs {
            m.push(x);
        }
        m
    }

    /// Welford's update gives the two-pass mean and sample variance.
    #[test]
    fn moments_match_a_two_pass_computation() {
        let xs: Vec<f64> = (0..1_000u32)
            .map(|i| f64::from(i * 7_919 % 1_013) + 0.25)
            .collect();
        let m = moments(&xs);
        let mean = xs.iter().sum::<f64>() / 1_000.0;
        let variance = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / 999.0;
        assert_eq!(m.n, 1_000);
        assert!((m.mean - mean).abs() < 1e-9 * mean, "{} {mean}", m.mean);
        assert!(
            (m.variance() - variance).abs() < 1e-9 * variance,
            "{} {variance}",
            m.variance()
        );
    }

    /// Welch's t against a hand computation, 1 to 5 against 2, 4, 6, 8 and
    /// 10: means 3 and 6 and variances 2.5 and 10 make t -3 over the root
    /// of 2.5/5 + 10/5, -3/√2.5; and when nothing varies.
    #[test]
    fn welch_t_answers_a_hand_computation() {
        let a = moments(&[1.0, 2.0, 3.0, 4.0, 5.0]);
        let b = moments(&[2.0, 4.0, 6.0, 8.0, 10.0]);
        let want = -3.0 / 2.5f64.sqrt();
        assert!(
            (welch_t(&a, &b) - want).abs() < 1e-12,
            "{}",
            welch_t(&a, &b)
        );
        assert!(
            (welch_t(&b, &a) + want).abs() < 1e-12,
            "{}",
            welch_t(&b, &a)
        );
        assert_eq!(welch_t(&a, &a), 0.0);
        let flat = moments(&[7.0; 4]);
        let higher = moments(&[8.0; 4]);
        assert_eq!(welch_t(&higher, &flat), f64::INFINITY);
        assert_eq!(welch_t(&flat, &higher), f64::NEG_INFINITY);
        assert_eq!(welch_t(&flat, &flat), 0.0);
    }

    /// The effect size against a hand computation, on the samples above:
    /// the means differ by -3 and the variances average 6.25, so with five
    /// samples a side it is -3/2.5, -1.2.  The same samples a hundred times
    /// over make t more than ten times larger, and the effect is still the
    /// means' difference over the root of the variances' mean.  The row and
    /// the detail give it, and the means an operation: here 6 and 3 over a
    /// batch of 2, so the random class's 3.0 ns and a difference of -1.5.
    #[test]
    fn the_effect_size_answers_a_hand_computation() {
        let comparison = |a: &[f64], b: &[f64]| {
            let (a, b) = (moments(a), moments(b));
            let d = (a.mean - b.mean) / ((a.variance() + b.variance()) / 2.0).sqrt();
            let comparison = Comparison {
                t: welch_t(&a, &b),
                test: 0,
                fixed: a.n,
                random: b.n,
                fixed_mean: a.mean,
                random_mean: b.mean,
            };
            assert!((comparison.effect() - d).abs() < 1e-9, "{comparison:?}");
            comparison
        };
        let few = comparison(&[1.0, 2.0, 3.0, 4.0, 5.0], &[2.0, 4.0, 6.0, 8.0, 10.0]);
        assert!((few.effect() + 1.2).abs() < 1e-12, "{few:?}");
        let many = comparison(
            &[1.0, 2.0, 3.0, 4.0, 5.0].repeat(100),
            &[2.0, 4.0, 6.0, 8.0, 10.0].repeat(100),
        );
        assert!(many.t / few.t > 10.0, "{many:?}");
        let report = Report {
            target: "hand".to_owned(),
            names: vec!["x"],
            by_class: vec![vec![few]],
            batch: 2,
            samples: 10,
            warm_up: 0,
            seconds: 0.0,
        };
        assert_eq!(
            report.row("pass"),
            "ct_check row | hand | -1.90 | -1.200 | 3.0 | -1.50 | x | all samples | 5 | 5 | 10 \
             | 2 | pass |"
        );
        assert!(
            report
                .detail()
                .contains("x: t -1.90, effect -1.200, -1.50 ns an operation against 3.0,"),
            "{}",
            report.detail()
        );
    }

    /// The crops' thresholds over warm-up times 1 to 999: the times at
    /// indices 66, 129 and 187 (999 × 0.067, × 0.130 and × 0.188, rounded
    /// down) for the first three crops, the median for crop 9 (0.5) and the
    /// 999th for the last (0.999); never falling.  A sample counts in a
    /// crop only when it is quicker than the crop's threshold.
    #[test]
    fn the_crops_are_dudects_percentiles() {
        let mut warm_up: Vec<u64> = (1..=999).rev().collect();
        let mut stats = Stats::new(&mut warm_up, 1);
        let t = stats.thresholds.clone();
        assert_eq!(t.len(), CROPS);
        assert_eq!((t[0], t[1], t[2], t[9], t[99]), (67, 130, 188, 500, 999));
        assert!(t.windows(2).all(|pair| pair[0] <= pair[1]), "{t:?}");
        stats.push(1, 67);
        stats.push(0, 66);
        stats.push(1, 999);
        let count = |slot: usize, test: usize| stats.tests[test][slot].n;
        assert_eq!((count(0, 0), count(1, 0)), (1, 2));
        assert_eq!(
            (count(0, 1), count(1, 1)),
            (1, 0),
            "crop 0's threshold is 67"
        );
        assert_eq!(
            (count(0, CROPS), count(1, CROPS)),
            (1, 1),
            "the last crop's is 999"
        );
        let quicker = t.iter().filter(|&&threshold| 67 < threshold).count() as u64;
        assert_eq!((1..=CROPS).map(|test| count(1, test)).sum::<u64>(), quicker);
        assert_eq!(test_name(0), "all samples");
        assert_eq!(test_name(1), "crop 0 (6.7%)");
        assert_eq!(test_name(CROPS), "crop 99 (99.9%)");
    }

    /// Each fixed class is compared with the random class in every test
    /// with enough samples on each side, in the tests' order, each
    /// comparison that test's moments: a class 10 ns slower in every sample
    /// has positive t, large somewhere, and too few samples in the quickest
    /// crops, a class like the random one small t in every test, and a
    /// class with one sample too few no comparison, however slow.
    #[test]
    fn each_class_is_compared_in_every_test_with_enough_samples() {
        let mut warm_up: Vec<u64> = (0..1_000).map(|i| 1_000 + i % 100).collect();
        let mut stats = Stats::new(&mut warm_up, 3);
        let mut rng = SplitMix64(0x6374_5f63_6865_636b);
        for i in 0..4_000 {
            stats.push(0, 1_000 + rng.below(100));
            stats.push(1, 1_010 + rng.below(100));
            stats.push(2, 1_000 + rng.below(100));
            if i < MIN_SAMPLES - 1 {
                stats.push(3, 5_000);
            }
        }
        let by_class = stats.by_class();
        assert_eq!(by_class.len(), 3);
        for (slot, comparisons) in (1..).zip(&by_class[..2]) {
            let enough: Vec<usize> = (0..=CROPS)
                .filter(|&test| {
                    stats.tests[test][0].n >= MIN_SAMPLES
                        && stats.tests[test][slot].n >= MIN_SAMPLES
                })
                .collect();
            assert_eq!(enough[0], 0, "slot {slot}");
            let tests: Vec<usize> = comparisons.iter().map(|c| c.test).collect();
            assert_eq!(tests, enough, "slot {slot}");
            for c in comparisons {
                let (fixed, random) = (&stats.tests[c.test][slot], &stats.tests[c.test][0]);
                assert_eq!(
                    (c.t, c.fixed, c.random, c.fixed_mean, c.random_mean),
                    (
                        welch_t(fixed, random),
                        fixed.n,
                        random.n,
                        fixed.mean,
                        random.mean
                    ),
                    "slot {slot}"
                );
            }
        }
        assert!(
            by_class[0].len() < CROPS && by_class[1].len() == 1 + CROPS,
            "{by_class:?}"
        );
        assert!(by_class[0].iter().all(|c| c.t > 0.0), "{:?}", by_class[0]);
        assert!(
            by_class[0].iter().any(|c| c.t > T_FAIL),
            "{:?}",
            by_class[0]
        );
        assert!(
            by_class[1].iter().all(|c| c.t.abs() <= T_REPORT),
            "{:?}",
            by_class[1]
        );
        assert_eq!(by_class[2], []);
    }

    /// A sample is of the random class half the time, and of each of the
    /// fixed classes an equal share of the rest.
    #[test]
    fn a_class_is_random_half_the_time_and_else_uniform() {
        let mut rng = SplitMix64(0x636c_6173_7365_7321);
        let mut counts = [0u32; 6];
        for _ in 0..120_000 {
            counts[slot(draw_class(&mut rng, 5))] += 1;
        }
        assert!((59_000..61_000).contains(&counts[0]), "{counts:?}");
        for fixed in &counts[1..] {
            assert!((11_500..12_500).contains(fixed), "{counts:?}");
        }
        assert_eq!(slot(None), 0);
        assert_eq!(slot(Some(4)), 5);
    }

    /// The verdict's thresholds and its floor, in either direction: above
    /// 4.5 reported, above 10 a leak on a difference of 1 ns an operation
    /// or more and reported as under the floor on a smaller one, however
    /// large |t| is.
    #[test]
    fn the_verdict_follows_the_thresholds_and_the_floor() {
        for (t, difference, want) in [
            (0.0, 0.0, Verdict::Pass),
            (4.5, 50.0, Verdict::Pass),
            (-4.5, -50.0, Verdict::Pass),
            (4.51, 0.01, Verdict::Reported),
            (10.0, 50.0, Verdict::Reported),
            (-10.0, -50.0, Verdict::Reported),
            (10.01, 1.0, Verdict::Leak),
            (-10.01, -1.0, Verdict::Leak),
            (-37.0, -50.0, Verdict::Leak),
            (10.01, 0.999, Verdict::UnderFloor),
            (-37.0, -0.999, Verdict::UnderFloor),
            (13.28, 0.07, Verdict::UnderFloor),
            (f64::INFINITY, 1.0, Verdict::Leak),
            (f64::INFINITY, 0.0, Verdict::UnderFloor),
            (f64::NAN, 0.0, Verdict::Leak),
            (0.0, f64::NAN, Verdict::Leak),
        ] {
            assert_eq!(verdict(t, difference), want, "{t} {difference}");
        }
        assert_eq!(
            Verdict::UnderFloor.word(),
            "reported (under the 1 ns floor)"
        );
    }

    /// The class that decides a target: of the classes that fail, the one
    /// of the largest |t|, though another's is larger under the floor; with
    /// none failing, the largest |t|; with no comparison, too few.  The
    /// floor is on the difference an operation, the batch divided out: a
    /// sample of four operations 2 ns slower is under it.
    #[test]
    fn a_failing_class_decides_over_a_larger_t_under_the_floor() {
        // A class's one comparison, of `t`, its fixed class `difference`
        // ns an operation slower, in samples of four operations.
        let comparison = |t: f64, difference: f64| {
            vec![Comparison {
                t,
                test: 0,
                fixed: 1_000,
                random: 3_000,
                fixed_mean: 400.0 + 4.0 * difference,
                random_mean: 400.0,
            }]
        };
        let report = |by_class: Vec<Vec<Comparison>>| Report {
            target: "hand".to_owned(),
            names: vec!["under", "over", "quiet"],
            by_class,
            batch: 4,
            samples: 6_000,
            warm_up: 0,
            seconds: 0.0,
        };
        let deciding = |report: &Report| report.deciding().map(|(class, _)| class);
        let mixed = report(vec![
            comparison(50.0, 0.5),
            comparison(-12.0, -2.0),
            comparison(1.0, 0.1),
        ]);
        assert_eq!(
            (deciding(&mixed), mixed.verdict()),
            (Some(1), Verdict::Leak)
        );
        assert!(
            mixed.row("LEAK").contains(" | -12.00 | "),
            "{}",
            mixed.row("LEAK")
        );
        let under = report(vec![comparison(12.0, 0.9), comparison(50.0, 0.5), vec![]]);
        assert_eq!(
            (deciding(&under), under.verdict()),
            (Some(1), Verdict::UnderFloor)
        );
        let quiet = report(vec![comparison(4.0, 3.0), vec![], comparison(-4.4, -3.0)]);
        assert_eq!(
            (deciding(&quiet), quiet.verdict()),
            (Some(2), Verdict::Pass)
        );
        assert_eq!(
            report(vec![vec![], vec![], vec![]]).verdict(),
            Verdict::TooFew
        );
        assert!(
            under.detail().contains(
                "+0.50 ns an operation against 100.0, in all samples, 1000 samples against \
                 3000, reported (under the 1 ns floor)\n"
            ),
            "{}",
            under.detail()
        );
    }

    /// A class is judged on the largest difference among its comparisons
    /// above |t| 10, not on its largest |t|'s alone, since a crop that cuts
    /// into the slower class's times shows less of its difference.  Of
    /// five comparisons, a class whose largest |t| is a crop's on 0.6 ns
    /// an operation fails on another crop's, above 10 on 1.4 ns, which
    /// decides it and is the one printed, over the first above 10 (1.1 ns),
    /// the last and largest |t| above 10 (1.2 ns) and one under 10 on
    /// 2.5 ns, and so does a class quicker by 1.6 ns in the same places.  A
    /// class whose comparisons above 10 are all under 1 ns is reported as
    /// under the floor on its largest |t|, though one under 10 differs by
    /// more.  A failing class decides the target over a larger |t| under
    /// the floor.  A class with a t that is not a number fails, as the
    /// verdict on that comparison does.
    #[test]
    fn a_class_fails_on_its_largest_difference_above_10() {
        // Test `test`'s comparison of `t`, its fixed class `difference` ns
        // an operation slower, in samples of four operations.
        let comparison = |test: usize, t: f64, difference: f64| Comparison {
            t,
            test,
            fixed: 1_000,
            random: 3_000,
            fixed_mean: 400.0 + 4.0 * difference,
            random_mean: 400.0,
        };
        let report = Report {
            target: "hand".to_owned(),
            names: vec!["trimmed", "quicker", "under"],
            by_class: vec![
                vec![
                    comparison(0, 15.0, 1.1),
                    comparison(10, 8.0, 2.5),
                    comparison(12, 11.0, 1.4),
                    comparison(19, 30.0, 1.2),
                    comparison(31, 40.0, 0.6),
                ],
                vec![
                    comparison(0, -14.0, -1.1),
                    comparison(10, -8.0, -2.5),
                    comparison(12, -10.5, -1.6),
                    comparison(19, -30.0, -0.6),
                    comparison(31, -20.0, -1.2),
                ],
                vec![
                    comparison(0, 8.0, 2.5),
                    comparison(19, 12.0, 0.9),
                    comparison(31, 40.0, 0.6),
                ],
            ],
            batch: 4,
            samples: 6_000,
            warm_up: 0,
            seconds: 0.0,
        };
        let decided: Vec<(Verdict, usize, f64)> = report
            .by_class
            .iter()
            .map(|comparisons| {
                let c = report.deciding_in(comparisons).expect("comparisons");
                (report.verdict_of(&c), c.test, c.t)
            })
            .collect();
        assert_eq!(
            decided,
            [
                (Verdict::Leak, 12, 11.0),
                (Verdict::Leak, 12, -10.5),
                (Verdict::UnderFloor, 31, 40.0)
            ]
        );
        let largest_t = report.by_class[0]
            .iter()
            .max_by(|a, b| a.t.abs().total_cmp(&b.t.abs()))
            .expect("comparisons");
        assert_eq!(report.verdict_of(largest_t), Verdict::UnderFloor);
        assert_eq!(
            (report.deciding().map(|(class, _)| class), report.verdict()),
            (Some(0), Verdict::Leak)
        );
        let not_a_number = [comparison(0, f64::NAN, 0.0), comparison(19, 12.0, 0.6)];
        let c = report.deciding_in(&not_a_number).expect("comparisons");
        assert!(
            c.t.is_nan() && report.verdict_of(&c) == Verdict::Leak,
            "{c:?}"
        );
        let row = report.row("LEAK");
        assert!(
            row.contains(" | +11.00 | +0.402 | 100.0 | +1.40 | trimmed | crop 11 (56.5%) | "),
            "{row}"
        );
        let detail = report.detail();
        for line in [
            "  trimmed: t +11.00, effect +0.402, +1.40 ns an operation against 100.0, in crop 11 \
             (56.5%), 1000 samples against 3000, LEAK\n",
            "  quicker: t -10.50, effect -0.383, -1.60 ns an operation against 100.0, in crop 11 \
             (56.5%), 1000 samples against 3000, LEAK\n",
            "  under: t +40.00, effect +1.461, +0.60 ns an operation against 100.0, in crop 30 \
             (88.3%), 1000 samples against 3000, reported (under the 1 ns floor)\n",
        ] {
            assert!(detail.contains(line), "{line}{detail}");
        }
    }

    /// The budget: ten seconds unset, else a whole number of seconds above
    /// zero.
    #[test]
    fn the_budget_is_whole_seconds_above_zero() {
        assert_eq!(budget_seconds(None), Ok(10));
        assert_eq!(budget_seconds(Some("60")), Ok(60));
        for bad in ["", "0", "-1", "1.5", " 60", "ten"] {
            assert!(budget_seconds(Some(bad)).is_err(), "{bad:?}");
        }
    }

    /// A batch makes a sample take MIN_SAMPLE_NANOS, from 1 to MAX_BATCH
    /// operations; a chunk holds CHUNK_NANOS of samples, one at least and
    /// no more than CHUNK_OPS inputs nor CHUNK_BYTES of them: 237 of an
    /// AES-256-GCM cipher's 1,104 bytes, 4,096 of a vector's 24.
    #[test]
    fn the_batch_and_the_chunk_follow_the_operations_time() {
        for (op, batch) in [
            (0, 1_000),
            (1, 1_000),
            (2, 1_000),
            (3, 667),
            (10, 200),
            (1_999, 2),
            (2_000, 1),
            (1_000_000, 1),
        ] {
            assert_eq!(batch_for(op), batch, "{op} ns");
        }
        for (op, batch, bytes, chunk) in [
            (1_000_000, 1, 24, 100),
            (50_000, 1, 24, 2_000),
            (10, 200, 24, 20),
            (0, 1_000, 24, 4),
            (2_000_000_000, 1, 24, 1),
            (100, 20, 64, 204),
            (100, 20, 0, 204),
            (100, 20, 1_104, 11),
            (1, 1_000, 1_104, 1),
        ] {
            assert_eq!(
                chunk_for(op, batch, bytes),
                chunk,
                "{op} ns, {batch} a sample, {bytes} bytes an input"
            );
        }
    }

    /// The run's bookkeeping, on a simulated target: the calibration's
    /// operations are of the random class and their median sizes the
    /// batch; every sample is a whole batch of one class; the warm-up's
    /// samples are thrown away and every later one counted once, in its
    /// class; and the run ends with the first sample past the budget.
    #[test]
    fn each_sample_is_a_batch_of_one_class_counted_once() {
        let budget = 40_000_000;
        let (measured, ran) = simulate(budget, 0);
        let (calibration, sampled) = ran.split_at(CALIBRATION_OPS);
        assert!(calibration.iter().all(|(class, _)| class.is_none()));
        let mut single: Vec<u64> = calibration.iter().map(|(_, nanos)| *nanos).collect();
        single.sort_unstable();
        assert_eq!(measured.batch, batch_for(single[CALIBRATION_OPS / 2]));
        let batch = measured.batch as usize;
        assert!(batch > 1, "a batch of {batch}");
        assert_eq!(sampled.len() % batch, 0);
        let classes: Vec<Option<usize>> = sampled
            .chunks(batch)
            .map(|ops| {
                assert!(ops.iter().all(|(class, _)| *class == ops[0].0), "{ops:?}");
                ops[0].0
            })
            .collect();
        assert_eq!(measured.warm_up, WARM_UP_SAMPLES);
        assert_eq!(
            classes.len() as u64,
            measured.warm_up as u64 + measured.samples
        );
        let mut counted = vec![0; 1 + SIMULATED.len()];
        for &class in &classes[measured.warm_up..] {
            counted[slot(class)] += 1;
        }
        let uncropped: Vec<u64> = measured.stats.tests[0].iter().map(|m| m.n).collect();
        assert_eq!(counted, uncropped);
        let total: u64 = ran.iter().map(|(_, nanos)| nanos).sum();
        let last: u64 = sampled[sampled.len() - batch..]
            .iter()
            .map(|(_, nanos)| nanos)
            .sum();
        assert_eq!(measured.nanos, total);
        assert!(total >= budget && total - last < budget, "{total} {last}");
    }

    /// Every input is made the same way, whatever its class: each build
    /// follows a draw of its own and is given the drawn bytes, a fixed
    /// class's written over them, so what building allocates does not
    /// depend on the class.  The random class's inputs are the draws and a
    /// fixed class's its own bytes, a batch's all of its sample's class.
    #[test]
    fn every_class_is_built_from_a_draw() {
        let classes = [("ones", vec![1; 8]), ("twos", vec![2; 8])];
        let clock = Simulated(Cell::new(0));
        let draws = Cell::new(0u64);
        let builds = RefCell::new(Vec::new());
        let ran = RefCell::new(Vec::new());
        let mut rng = SplitMix64(0x6275_696c_645f_6279);
        let measured = measure(
            &clock,
            &mut rng,
            40_000_000,
            classes.len(),
            by_class(
                &classes,
                |rng| {
                    draws.set(draws.get() + 1);
                    // A draw, told from both classes by its first byte.
                    let mut bytes = vec![0; 8];
                    rng.fill(&mut bytes);
                    bytes[0] = 0xff;
                    bytes
                },
                |bytes| {
                    builds.borrow_mut().push(draws.get());
                    bytes.to_vec()
                },
            ),
            |bytes| {
                clock.advance(1_000);
                ran.borrow_mut().push(bytes.clone());
            },
        );
        let builds = builds.into_inner();
        assert_eq!(builds, (1..=draws.get()).collect::<Vec<u64>>());
        let ran = ran.into_inner();
        let kind = |bytes: &[u8]| match bytes[0] {
            0xff => 0,
            fixed => {
                assert_eq!(bytes, classes[usize::from(fixed) - 1].1, "{bytes:02x?}");
                usize::from(fixed)
            }
        };
        let (calibration, sampled) = ran.split_at(CALIBRATION_OPS);
        assert!(calibration.iter().all(|bytes| kind(bytes) == 0));
        let batch = measured.batch as usize;
        let kinds: Vec<usize> = sampled
            .chunks(batch)
            .map(|ops| {
                assert!(ops.iter().all(|op| kind(op) == kind(&ops[0])), "{ops:02x?}");
                kind(&ops[0])
            })
            .collect();
        let mut counted = [0; 3];
        for &kind in &kinds[measured.warm_up..] {
            counted[kind] += 1;
        }
        let uncropped: Vec<u64> = measured.stats.tests[0].iter().map(|m| m.n).collect();
        assert_eq!(counted.to_vec(), uncropped);
        assert!(uncropped.iter().all(|&n| n >= MIN_SAMPLES), "{uncropped:?}");
    }

    /// The timed region holds the operations alone: an input's drop and a
    /// result's come after the clock is read, however long they take.
    /// Here each drop takes a simulated millisecond and each operation
    /// 500 ns: the batch is sized from the 500 ns, and every sample takes
    /// its batch's operations exactly.
    #[test]
    fn drops_fall_outside_the_timed_region() {
        /// A value whose drop takes a simulated millisecond.
        struct SlowDrop<'a>(&'a Simulated);

        impl Drop for SlowDrop<'_> {
            fn drop(&mut self) {
                self.0.advance(1_000_000);
            }
        }

        let clock = Simulated(Cell::new(0));
        let mut rng = SplitMix64(0x736c_6f77_5f64_726f);
        let measured = measure(
            &clock,
            &mut rng,
            20_000_000_000,
            2,
            |_, _| SlowDrop(&clock),
            |_| {
                clock.advance(500);
                SlowDrop(&clock)
            },
        );
        assert_eq!(measured.batch, batch_for(500));
        let sample = (500 * measured.batch) as f64;
        for class in &measured.stats.tests[0] {
            assert!(class.n >= MIN_SAMPLES, "{class:?}");
            assert_eq!((class.mean, class.m2), (sample, 0.0), "{class:?}");
        }
    }

    /// The harness finds a fixed class 100 ns slower an operation, and only
    /// that class; the target fails and the control's check passes.
    #[test]
    fn the_harness_finds_a_planted_difference() {
        let report = simulated_report(40_000_000, 100);
        let (class, deciding) = report.deciding().expect("comparisons");
        assert_eq!(class, 2, "{}", report.detail());
        assert!(deciding.t > T_FAIL, "{}", report.detail());
        assert_eq!(report.verdict(), Verdict::Leak);
        for (other, comparisons) in report.by_class.iter().enumerate() {
            if other != 2 {
                assert!(!comparisons.is_empty(), "{}", report.detail());
                for c in comparisons {
                    assert!(c.t.abs() <= T_REPORT, "{}", report.detail());
                }
            }
        }
        report.assert_leak_found();
        // The prefix, then the summary's twelve columns: the class slower,
        // so its t, its effect and its difference an operation positive.
        let row = report.row("LEAK");
        let columns: Vec<&str> = row.split(" | ").collect();
        assert_eq!(columns.len(), 13, "{row}");
        assert_eq!(
            (columns[0], columns[1], columns[6]),
            ("ct_check row", "simulated", "c")
        );
        for at in [2, 3, 5] {
            assert!(columns[at].starts_with('+'), "{row}");
        }
        assert_eq!(columns[12], "LEAK |");
    }

    /// With every class alike, nothing is reported: the target passes.
    #[test]
    fn the_harness_finds_nothing_in_classes_alike() {
        let report = simulated_report(40_000_000, 0);
        assert_eq!(report.verdict(), Verdict::Pass, "{}", report.detail());
        report.assert_constant_time();
    }

    #[test]
    #[should_panic(expected = "|t| above 10")]
    fn a_leak_fails_its_target() {
        simulated_report(40_000_000, 100).assert_constant_time();
    }

    #[test]
    #[should_panic(expected = "does not see a leak")]
    fn a_control_whose_leak_is_not_found_fails() {
        simulated_report(40_000_000, 0).assert_leak_found();
    }

    /// A difference under the floor, half a nanosecond an operation, is
    /// found far above |t| 10 and reported, not failed: the target passes,
    /// its row says why, and the other classes pass.
    #[test]
    fn a_difference_under_the_floor_is_reported() {
        let report = floor_report(1);
        let (class, deciding) = report.deciding().expect("comparisons");
        let (_, difference) = report.per_op(&deciding);
        assert_eq!(class, 2, "{}", report.detail());
        assert!(report.batch > 100, "{}", report.detail());
        assert!(deciding.t > T_FAIL, "{}", report.detail());
        assert!(
            (0.3..0.7).contains(&difference),
            "{difference}\n{}",
            report.detail()
        );
        assert_eq!(report.verdict(), Verdict::UnderFloor, "{}", report.detail());
        for (other, comparisons) in report.by_class.iter().enumerate() {
            if other != 2 {
                let comparison = report.deciding_in(comparisons).expect("enough samples");
                assert_eq!(
                    report.verdict_of(&comparison),
                    Verdict::Pass,
                    "{}",
                    report.detail()
                );
            }
        }
        let row = report.row(&report.verdict().word());
        assert!(
            row.ends_with(" | reported (under the 1 ns floor) |"),
            "{row}"
        );
        report.assert_constant_time();
    }

    /// A difference above the floor, a nanosecond and a half an operation
    /// in the same simulated run, fails the target, and as the control's
    /// leak it is found.
    #[test]
    fn a_difference_above_the_floor_fails() {
        let report = floor_report(3);
        let (class, deciding) = report.deciding().expect("comparisons");
        let (_, difference) = report.per_op(&deciding);
        assert_eq!(class, 2, "{}", report.detail());
        assert!(deciding.t > T_FAIL, "{}", report.detail());
        assert!(
            (1.2..1.8).contains(&difference),
            "{difference}\n{}",
            report.detail()
        );
        assert_eq!(report.verdict(), Verdict::Leak, "{}", report.detail());
        report.assert_leak_found();
    }

    #[test]
    #[should_panic(expected = "|t| above 10 and by 1 ns an operation or more")]
    fn a_difference_above_the_floor_fails_its_target() {
        floor_report(3).assert_constant_time();
    }

    /// A control whose difference is under the floor is not found, however
    /// large its |t|.
    #[test]
    #[should_panic(expected = "does not see a leak")]
    fn a_control_under_the_floor_fails() {
        floor_report(1).assert_leak_found();
    }

    /// A difference that the crops trim away is judged where it shows: on
    /// a simulated target of single operations of about 2 microseconds,
    /// the random class and three fixed classes take 0 to 3 ns over 2,000,
    /// and fixed class 2 takes 1 to 3 ns over in 99 operations of 100 and
    /// 100 ns over in the other, which no crop keeps.  Its largest |t| is a
    /// crop's, on half a nanosecond an operation, which alone would be
    /// under the floor; the uncropped test, above 10 on more than a
    /// nanosecond, fails it, and the control's check finds it.
    #[test]
    fn a_difference_the_crops_trim_away_fails() {
        let (measured, _) = simulate_with(200_000_000, 400, |class, drawn| {
            if class != Some(2) {
                2_000 + drawn % 4
            } else if drawn < 4 {
                2_100
            } else {
                2_001 + drawn % 3
            }
        });
        let report = Report::new("simulated", SIMULATED.to_vec(), &measured);
        assert_eq!(report.batch, 1, "{}", report.detail());
        let (class, deciding) = report.deciding().expect("comparisons");
        let (_, difference) = report.per_op(&deciding);
        assert_eq!(class, 2, "{}", report.detail());
        assert_eq!(deciding.test, 0, "{}", report.detail());
        assert!(deciding.t > T_FAIL, "{}", report.detail());
        assert!(
            (1.0..2.0).contains(&difference),
            "{difference}\n{}",
            report.detail()
        );
        let largest_t = report.by_class[2]
            .iter()
            .max_by(|a, b| a.t.abs().total_cmp(&b.t.abs()))
            .expect("comparisons");
        let (_, cropped) = report.per_op(largest_t);
        assert!(
            largest_t.test > 0 && largest_t.t > deciding.t,
            "{largest_t:?}\n{}",
            report.detail()
        );
        assert!(
            (0.3..0.7).contains(&cropped),
            "{cropped}\n{}",
            report.detail()
        );
        assert_eq!(report.verdict_of(largest_t), Verdict::UnderFloor);
        assert_eq!(report.verdict(), Verdict::Leak, "{}", report.detail());
        for (other, comparisons) in report.by_class.iter().enumerate() {
            if other != 2 {
                let comparison = report.deciding_in(comparisons).expect("enough samples");
                assert_eq!(
                    report.verdict_of(&comparison),
                    Verdict::Pass,
                    "{}",
                    report.detail()
                );
            }
        }
        report.assert_leak_found();
    }

    /// A budget of a millisecond: the warm-up ends at a tenth of it, short
    /// of WARM_UP_SAMPLES, and no fixed class has the samples to count.
    #[test]
    fn a_short_budget_warms_up_for_a_tenth_of_it() {
        let (measured, _) = simulate(1_000_000, 0);
        assert!(
            (10..WARM_UP_SAMPLES).contains(&measured.warm_up),
            "{}",
            measured.warm_up
        );
        let report = Report::new("simulated", SIMULATED.to_vec(), &measured);
        assert_eq!(report.verdict(), Verdict::TooFew, "{}", report.detail());
        let row = report.row("TOO FEW SAMPLES");
        assert!(
            row.starts_with("ct_check row | simulated | - | - | - | - | - | - | - | - | "),
            "{row}"
        );
    }

    #[test]
    #[should_panic(expected = "raise DCROXIDE_CT_SECONDS")]
    fn too_few_samples_fail_the_target() {
        simulated_report(1_000_000, 0).assert_constant_time();
    }

    /// `value`'s set bits.
    fn weight(value: &[u8]) -> u32 {
        value.iter().map(|byte| byte.count_ones()).sum()
    }

    /// The value of the class `name` among `classes`.
    fn class(classes: &[(&'static str, Vec<u8>)], name: &str) -> Vec<u8> {
        classes
            .iter()
            .find(|(class, _)| *class == name)
            .unwrap_or_else(|| panic!("no class {name}"))
            .1
            .clone()
    }

    /// No two classes share a name or a value.
    fn assert_distinct(classes: &[(&'static str, Vec<u8>)]) {
        for (i, (name, value)) in classes.iter().enumerate() {
            for (other, other_value) in &classes[..i] {
                assert!(name != other && value != other_value, "{name} and {other}");
            }
        }
    }

    /// Each NIST class is the value it is named for, in `[1, n)` by the
    /// curve's own check, and no two are alike; on P-521 the top window is
    /// the top bit, so it has eleven.  The orders are right: n - 1 is a
    /// scalar and n is not.
    #[test]
    fn the_nist_classes_are_the_extremes_they_are_named_for() {
        for (curve, count) in [(&P256, 12), (&P384, 12), (&P521, 11)] {
            let n = unhex(curve.order);
            let len = n.len();
            let bits = 8 * len - n[0].leading_zeros() as usize;
            let n_minus_1 = plus(&n, -1);
            let classes = nist_classes(&n);
            let value = |name| class(&classes, name);
            let below = |value: &[u8], at: usize| (at..8 * len).all(|i| !bit(value, i));
            assert_eq!(classes.len(), count, "{:?}", curve.group);
            assert_distinct(&classes);
            let name = format!("{:?}", curve.group);
            for (byte, class) in [(1, "1"), (2, "2"), (0xff, "0xff")] {
                let mut want = vec![0; len];
                want[len - 1] = byte;
                assert_eq!(value(class), want, "{name}");
            }
            let mut want = vec![0; len];
            want[len - 8..].fill(0xff);
            assert_eq!(value("2^64 - 1"), want, "{name}");
            let top = value("top bit alone");
            assert!(weight(&top) == 1 && bit(&top, bits - 1), "{name}");
            assert_eq!(plus(&value("n - 1"), 1), n, "{name}");
            assert_eq!(plus(&value("n - 2"), 2), n, "{name}");
            let half = len - len / 2;
            let bottom_zero = value("bottom half zero");
            assert_eq!(bottom_zero[..half], n_minus_1[..half], "{name}");
            assert!(bottom_zero[half..].iter().all(|&b| b == 0), "{name}");
            let top_zero = value("top half zero");
            assert!(top_zero[..half].iter().all(|&b| b == 0), "{name}");
            assert_eq!(top_zero[half..], n_minus_1[half..], "{name}");
            let low = value("low weight");
            assert!(weight(&low) == 8 && below(&low, bits - 1), "{name}");
            let high = value("high weight");
            assert_eq!(weight(&high), weight(&n_minus_1) - 8, "{name}");
            assert!(
                high.iter().zip(&n_minus_1).all(|(h, m)| h & !m == 0),
                "{name}"
            );
            let window = 4 * ((bits - 1) / 4);
            if count == 12 {
                let windows = value("top window alone");
                assert!((0..window).all(|i| !bit(&windows, i)), "{name}");
                assert!(
                    (window..8 * len).all(|i| bit(&windows, i) == bit(&n_minus_1, i)),
                    "{name}"
                );
                assert_ne!(windows, top, "{name}");
            } else {
                assert!(below(&n_minus_1, window + 1) && bit(&n_minus_1, window));
            }
            for (class, value) in classes.iter().chain([&("fixed", fixed_scalar(&n))]) {
                assert!(
                    exchange_with(curve.group, value).is_some(),
                    "{name}: {class} in [1, n)"
                );
            }
            assert!(exchange_with(curve.group, &n).is_none(), "{name}: n");
        }
    }

    /// Whether `signature` of `message` verifies under the uncompressed
    /// point `public` on the curve of `scheme`: by the provider's verifier
    /// for P-256 and P-384, and the `p521` crate's for P-521, which the
    /// provider does not verify.
    fn ecdsa_verifies(scheme: SignatureScheme, public: &[u8], signature: &[u8]) -> bool {
        match scheme {
            SignatureScheme::ECDSA_NISTP256_SHA256 => verify::ECDSA_P256_SHA256
                .verify_signature(public, MESSAGE, signature)
                .is_ok(),
            SignatureScheme::ECDSA_NISTP384_SHA384 => verify::ECDSA_P384_SHA384
                .verify_signature(public, MESSAGE, signature)
                .is_ok(),
            SignatureScheme::ECDSA_NISTP521_SHA512 => {
                let key = p521::ecdsa::VerifyingKey::from_sec1_bytes(public).expect("a point");
                p521::ecdsa::DerSignature::from_bytes(signature)
                    .is_ok_and(|signature| key.verify(MESSAGE, &signature).is_ok())
            }
            other => panic!("{other:?}"),
        }
    }

    /// The timing check's ECDSA key takes the scalars in `[1, n)` at the
    /// field's length on the three ECDSA schemes, and nothing else.
    #[test]
    fn the_ecdsa_hook_takes_only_scalars_in_range() {
        for curve in [&P256, &P384, &P521] {
            let n = unhex(curve.order);
            let n_minus_1 = plus(&n, -1);
            let takes = |scalar: &[u8]| timing::Ecdsa::new(curve.scheme, scalar).is_some();
            assert!(takes(&n_minus_1), "{:?}", curve.scheme);
            for refused in [vec![0; n.len()], n.clone(), n_minus_1[1..].to_vec()] {
                assert!(!takes(&refused), "{:?}: {refused:02x?}", curve.scheme);
            }
        }
        assert!(timing::Ecdsa::new(SignatureScheme::ED25519, &[1; 32]).is_none());
    }

    /// Each key class reaches the signer: the key made from it has that
    /// scalar's public point, the one the key exchange computes for it, and
    /// its hedged signature verifies under it.  The hedge is the one given,
    /// not a draw: a signature with it is made again byte for byte, and
    /// one with another hedge differs.
    #[test]
    fn the_ecdsa_key_classes_are_the_signing_keys() {
        for curve in [&P256, &P384, &P521] {
            let n = unhex(curve.order);
            let hedge = vec![0xa5; n.len()];
            let key = timing::Ecdsa::new(curve.scheme, &fixed_scalar(&n)).expect("the key");
            let signature = key.sign_hedged(MESSAGE, &hedge);
            assert_eq!(
                key.sign_hedged(MESSAGE, &hedge),
                signature,
                "{:?}",
                curve.scheme
            );
            let other = key.sign_hedged(MESSAGE, &vec![0x5b; n.len()]);
            assert_ne!(other, signature, "{:?}", curve.scheme);
            for (name, scalar) in nist_classes(&n) {
                let key = timing::Ecdsa::new(curve.scheme, &scalar).expect("a scalar in [1, n)");
                let public = exchange_with(curve.group, &scalar).expect("a scalar");
                assert_eq!(key.public(), public.pub_key(), "{:?}: {name}", curve.scheme);
                let signature = key.sign_hedged(MESSAGE, &hedge);
                assert!(
                    ecdsa_verifies(curve.scheme, &key.public(), &signature),
                    "{:?}: {name}",
                    curve.scheme
                );
            }
        }
    }

    /// The r of the DER ECDSA signature `signature`, at `len` bytes.
    fn der_r(signature: &[u8], len: usize) -> Vec<u8> {
        // The SEQUENCE's length takes a second byte past 127, as P-521's
        // can.
        let at = if signature[1] == 0x81 { 3 } else { 2 };
        assert_eq!(signature[at], 0x02, "{signature:02x?}");
        let r = &signature[at + 2..at + 2 + usize::from(signature[at + 1])];
        let r = r.strip_prefix(&[0]).unwrap_or(r);
        [vec![0; len - r.len()], r.to_vec()].concat()
    }

    /// `a` minus `b`, big-endian at their length, `a` at least `b`.
    fn minus(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut out = vec![0; a.len()];
        let mut borrow = 0;
        for ((out, &a), &b) in out.iter_mut().zip(a).zip(b).rev() {
            let difference = i16::from(a) - i16::from(b) - borrow;
            *out = difference.rem_euclid(256) as u8;
            borrow = i16::from(difference < 0);
        }
        assert_eq!(borrow, 0);
        out
    }

    /// Each nonce class reaches the signature: its r is the x-coordinate
    /// of the nonce times the generator, reduced mod n, and the signature
    /// verifies under the fixed key.
    #[test]
    fn the_ecdsa_nonce_classes_reach_r() {
        for curve in [&P256, &P384, &P521] {
            let n = unhex(curve.order);
            let len = n.len();
            let key = timing::Ecdsa::new(curve.scheme, &fixed_scalar(&n)).expect("the key");
            for (name, nonce) in nist_classes(&n) {
                let signature = key
                    .sign_with_nonce(&nonce, MESSAGE)
                    .unwrap_or_else(|| panic!("{:?}: {name} signs", curve.scheme));
                let point = exchange_with(curve.group, &nonce).expect("a scalar");
                let x = point.pub_key()[1..1 + len].to_vec();
                let want = if x.as_slice() < n.as_slice() {
                    x
                } else {
                    minus(&x, &n)
                };
                assert_eq!(der_r(&signature, len), want, "{:?}: {name}", curve.scheme);
                assert!(
                    ecdsa_verifies(curve.scheme, &key.public(), &signature),
                    "{:?}: {name}",
                    curve.scheme
                );
            }
        }
    }

    /// Each NIST class reaches both steps of the exchange: the secret it
    /// shares with a fixed peer, from its side, is the one the peer
    /// computes from the class's public key.
    #[test]
    fn the_nist_exchange_classes_reach_both_steps() {
        for curve in [&P256, &P384, &P521] {
            let n = unhex(curve.order);
            let peer = fixed_scalar(&n);
            let peer_public = exchange_with(curve.group, &peer)
                .expect("the peer")
                .pub_key()
                .to_vec();
            for (name, secret) in nist_classes(&n) {
                let ours = exchange_with(curve.group, &secret).expect("a scalar");
                let public = ours.pub_key().to_vec();
                let ours = ours.complete(&peer_public).expect("completed");
                let theirs = exchange_with(curve.group, &peer)
                    .expect("the peer")
                    .complete(&public)
                    .expect("completed");
                assert_eq!(
                    ours.secret_bytes(),
                    theirs.secret_bytes(),
                    "{:?}: {name}",
                    curve.group
                );
            }
        }
    }

    /// Each X25519 class clamps to the value it is named for and reaches
    /// both steps: its public key is the ladder's X25519 of it and 9, and
    /// the secret it shares with a fixed peer is the peer's.
    #[test]
    fn the_x25519_classes_reach_both_steps() {
        let classes = x25519_classes();
        assert_distinct(&classes);
        let clamped = |name| clamp_integer(class(&classes, name).try_into().expect("32 bytes"));
        let mut least = [0; 32];
        least[31] = 0x40;
        let mut greatest = [0xff; 32];
        greatest[0] = 0xf8;
        greatest[31] = 0x7f;
        assert_eq!(clamped("all zeros"), least);
        assert_eq!(clamped("all ones"), greatest);
        assert_eq!(weight(&clamped("low weight")), 8);
        assert_eq!(weight(&clamped("high weight")), 252 - 8);
        let peer = [0x5a; 32];
        let peer_public = exchange_with(NamedGroup::X25519, &peer)
            .expect("32 bytes")
            .pub_key()
            .to_vec();
        let mut nine = [0; 32];
        nine[0] = 9;
        for (name, secret) in &classes {
            let ours = exchange_with(NamedGroup::X25519, secret).expect("32 bytes");
            let public = ours.pub_key().to_vec();
            let ladder =
                MontgomeryPoint(nine).mul_clamped(secret.as_slice().try_into().expect("32 bytes"));
            assert_eq!(public, ladder.to_bytes(), "{name}");
            let ours = ours.complete(&peer_public).expect("completed");
            let theirs = exchange_with(NamedGroup::X25519, &peer)
                .expect("32 bytes")
                .complete(&public)
                .expect("completed");
            assert_eq!(ours.secret_bytes(), theirs.secret_bytes(), "{name}");
        }
    }

    /// Each Ed25519 scalar class is within the clamp and the value it is
    /// named for, the two named for their residues reduce to them, and the
    /// key made from each has its residue's public key and signs, through
    /// the handshake signer's code, what that key verifies, with the nonce
    /// RFC 8032 hashes from the prefix and the message.
    #[test]
    fn the_ed25519_scalar_classes_are_clamped_extremes_that_sign() {
        let classes = ed25519_scalar_classes();
        assert_eq!(classes.len(), 7);
        assert_distinct(&classes);
        let mut least = [0; 32];
        least[31] = 0x40;
        let mut next = least;
        next[0] = 0x08;
        let mut greatest = [0xff; 32];
        greatest[0] = 0xf8;
        greatest[31] = 0x7f;
        assert_eq!(class(&classes, "2^254"), least);
        assert_eq!(class(&classes, "2^254 + 8"), next);
        assert_eq!(class(&classes, "2^255 - 8"), greatest);
        assert_eq!(weight(&class(&classes, "low weight")), 8);
        assert_eq!(weight(&class(&classes, "high weight")), 252 - 8);
        // The nonce RFC 8032 hashes from the prefix and the message, which
        // the handshake signer's signature is made with.
        let hash: [u8; 64] = Sha512::new()
            .chain_update(PREFIX)
            .chain_update(MESSAGE)
            .finalize()
            .into();
        let nonce = Scalar::from_bytes_mod_order_wide(&hash);
        for (name, scalar) in &classes {
            let scalar: [u8; 32] = scalar.as_slice().try_into().expect("32 bytes");
            assert_eq!(clamp_integer(scalar), scalar, "{name}: within the clamp");
            let residue = Scalar::from_bytes_mod_order(scalar);
            match *name {
                "6L + 2, residue 2" => assert_eq!(residue, Scalar::from(2u64)),
                "5L - 1, residue L - 1" => assert_eq!(residue, -Scalar::ONE),
                _ => {}
            }
            let key = timing::Ed25519::new(scalar, PREFIX);
            let public = EdwardsPoint::mul_base(&residue).compress().to_bytes();
            assert_eq!(key.public(), public, "{name}");
            let signature = key.sign(MESSAGE);
            assert!(
                verify::ED25519
                    .verify_signature(&public, MESSAGE, &signature)
                    .is_ok(),
                "{name}"
            );
            assert_eq!(signature, key.sign_with_nonce(&nonce, MESSAGE), "{name}");
        }
    }

    /// Each Ed25519 nonce class is below L and the value it is named for,
    /// is the scalar the target builds from it, and reaches the signature:
    /// its R is the nonce times the base point, the identity's encoding for
    /// 0, and the signature verifies.
    #[test]
    fn the_ed25519_nonce_classes_reach_r() {
        let classes = ed25519_nonce_classes();
        assert_distinct(&classes);
        let mut one = [0; 32];
        one[0] = 1;
        assert_eq!(class(&classes, "0"), [0; 32]);
        assert_eq!(class(&classes, "1"), one);
        assert_eq!(class(&classes, "L - 1"), (-Scalar::ONE).to_bytes());
        let low = class(&classes, "low weight");
        assert!(weight(&low) == 8 && low[31] < 0x10);
        let l_minus_1 = (-Scalar::ONE).to_bytes();
        let high = class(&classes, "high weight");
        assert_eq!(weight(&high), weight(&l_minus_1) - 8);
        assert!(high.iter().zip(&l_minus_1).all(|(h, m)| h & !m == 0));
        let key = timing::Ed25519::new(clamp_integer([0x5a; 32]), PREFIX);
        for (name, r) in &classes {
            let r: [u8; 32] = r.as_slice().try_into().expect("32 bytes");
            let nonce = nonce_scalar(r);
            assert_eq!(nonce.to_bytes(), r, "{name}");
            let signature = key.sign_with_nonce(&nonce, MESSAGE);
            let big_r = EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(r))
                .compress()
                .to_bytes();
            assert_eq!(signature[..32], big_r, "{name}");
            assert!(
                verify::ED25519
                    .verify_signature(&key.public(), MESSAGE, &signature)
                    .is_ok(),
                "{name}"
            );
        }
        assert_eq!(key.sign_with_nonce(&Scalar::ZERO, MESSAGE)[..32], one);
    }

    /// Each AEAD key class is the pattern it is named for and keys the
    /// cipher: a record it seals opens under a cipher made afresh from the
    /// class's key, and not under another key.
    #[test]
    fn the_aead_key_classes_key_the_cipher() {
        fn check<A: RecordAead>() {
            let len = A::key_size();
            let classes = aead_key_classes(len);
            assert_distinct(&classes);
            assert_eq!(class(&classes, "all zeros"), vec![0; len]);
            assert_eq!(class(&classes, "all ones"), vec![0xff; len]);
            let turns = class(&classes, "0x55 and 0xaa");
            assert_eq!((turns.len(), &turns[..3]), (len, &[0x55, 0xaa, 0x55][..]));
            let other = A::new_from_slice(&vec![0x5a; len]).expect("a key");
            for (name, key) in &classes {
                let mut record = RECORD;
                let aead = A::new_from_slice(key).expect("a key");
                let tag = aead::seal(&aead, NONCE, &AAD, &mut record).expect("sealed");
                let sealed = [&record[..], &tag].concat();
                let fresh = A::new_from_slice(key).expect("a key");
                assert_eq!(
                    aead::open(&fresh, NONCE, &AAD, &mut sealed.clone()),
                    Ok(RECORD.len()),
                    "{name}"
                );
                assert_eq!(
                    aead::open(&other, NONCE, &AAD, &mut sealed.clone()),
                    Err(Error::DecryptError),
                    "{name}"
                );
            }
        }
        check::<Aes128Gcm>();
        check::<Aes256Gcm>();
        check::<ChaCha20Poly1305>();
    }

    /// Each bad tag is wrong only where it is named for, and the random
    /// class's always; each is refused, the record left as it was, and
    /// the right tag opens it.
    #[test]
    fn the_bad_tags_are_wrong_where_they_are_named_for() {
        fn check<A: RecordAead>() {
            let aead = A::new_from_slice(&vec![0x5a; A::key_size()]).expect("a key");
            let mut record = RECORD;
            let tag = aead::seal(&aead, NONCE, &AAD, &mut record).expect("sealed");
            let classes = bad_tag_classes(&tag);
            let wrong_at = |wrong: &[u8]| -> Vec<usize> {
                (0..tag.len()).filter(|&i| wrong[i] != tag[i]).collect()
            };
            assert_eq!(wrong_at(&class(&classes, "wrong first byte")), [0]);
            assert_eq!(wrong_at(&class(&classes, "wrong last byte")), [15]);
            let mut rng = SplitMix64(0x7461_6773);
            let random: Vec<Vec<u8>> = (0..64).map(|_| wrong_tag(&tag, &mut rng)).collect();
            for wrong in classes.iter().map(|(_, wrong)| wrong).chain(&random) {
                let mut sealed = [&record[..], wrong].concat();
                assert_eq!(
                    aead::open(&aead, NONCE, &AAD, &mut sealed),
                    Err(Error::DecryptError)
                );
                assert_eq!(sealed[..record.len()], record);
            }
            let mut sealed = [&record[..], &tag].concat();
            assert_eq!(
                aead::open(&aead, NONCE, &AAD, &mut sealed),
                Ok(RECORD.len())
            );
            assert_eq!(sealed[..RECORD.len()], RECORD);
        }
        check::<Aes128Gcm>();
        check::<Aes256Gcm>();
        check::<ChaCha20Poly1305>();
    }

    /// Each HMAC key class is the pattern it is named for and keys the tag
    /// the provider makes, which is HMAC's under that key, computed by
    /// `hmac` directly.
    #[test]
    fn the_hmac_key_classes_key_the_tag() {
        for (hmac, len) in [(&HMAC_SHA256 as &dyn Hmac, 32), (&HMAC_SHA384, 48)] {
            let classes = hmac_key_classes(len);
            assert_distinct(&classes);
            assert_eq!(class(&classes, "all zeros"), vec![0; len]);
            assert_eq!(class(&classes, "all ones"), vec![0xff; len]);
            let one_bit = class(&classes, "one bit set");
            assert!(weight(&one_bit) == 1 && one_bit[0] == 0x80);
            for (name, key) in &classes {
                let tag = hmac.with_key(key).sign(&[HMAC_MESSAGE]);
                let want = if len == 32 {
                    ::hmac::Hmac::<Sha256>::new_from_slice(key)
                        .expect("any length")
                        .chain_update(HMAC_MESSAGE)
                        .finalize()
                        .into_bytes()
                        .to_vec()
                } else {
                    ::hmac::Hmac::<Sha384>::new_from_slice(key)
                        .expect("any length")
                        .chain_update(HMAC_MESSAGE)
                        .finalize()
                        .into_bytes()
                        .to_vec()
                };
                assert_eq!(tag.as_ref(), want, "{len}: {name}");
            }
        }
    }

    /// The control's comparison finds equal inputs equal and an input that
    /// differs in any one byte unequal; its random class's first byte is
    /// the reference's, inverted.
    #[test]
    fn the_control_compares_byte_by_byte() {
        assert!(leaky_eq(&REFERENCE, &REFERENCE));
        for at in 0..REFERENCE.len() {
            let mut other = REFERENCE;
            other[at] ^= 0x10;
            assert!(!leaky_eq(&other, &REFERENCE), "byte {at}");
        }
        let mut rng = SplitMix64(0x636f_6e74_726f_6c21);
        for _ in 0..100 {
            let input = control_input(&mut rng);
            assert_eq!(input[0], !REFERENCE[0]);
            assert!(!leaky_eq(&input.try_into().expect("64 bytes"), &REFERENCE));
        }
    }

    /// The random classes' draws: NIST scalars in `[1, n)`, P-521's first
    /// byte within the order's one bit; Ed25519 scalars within the clamp
    /// and nonces below L.
    #[test]
    fn the_random_classes_are_drawn_in_range() {
        let mut rng = SplitMix64(0x7261_6e64_6f6d_2121);
        for curve in [&P256, &P384, &P521] {
            let n = unhex(curve.order);
            for _ in 0..200 {
                let scalar = random_scalar(&n, &mut rng);
                assert_eq!(scalar.len(), n.len());
                assert!(scalar.iter().any(|&b| b != 0) && scalar < n);
                assert!(scalar[0] <= n[0]);
            }
        }
        for _ in 0..200 {
            let scalar: [u8; 32] = random_clamped(&mut rng).try_into().expect("32 bytes");
            assert_eq!(clamp_integer(scalar), scalar);
            let nonce: [u8; 32] = random_nonce(&mut rng).try_into().expect("32 bytes");
            assert!(bool::from(Scalar::from_canonical_bytes(nonce).is_some()));
        }
    }
}
