// SPDX-License-Identifier: ISC
//! dudect's fixed-against-random timing test (Reparaz, Balasch and
//! Verbauwhede, "Dude, is my code constant time?", 2017), shared by the
//! crates that time their secret-dependent code: `dcroxide-tlscrypto`'s
//! `ct_check` module (ADR-0015 T10) times its provider's secrets on it,
//! and `dcroxide-dcrec`'s its secp256k1 and Ed25519 secrets.  It began as
//! `dcroxide-tlscrypto`'s own harness, which gave the random class half of
//! the samples; each crate keeps its own targets and classes, and the
//! measurement and the verdict are one piece of code with one set of
//! tests.  A target known to report on one architecture says so through
//! [`Report::with_known_report`].
//!
//! An operation is timed with `std::time::Instant` on inputs of fixed
//! classes and of a random class, interleaved, and Welch's t-test asks
//! whether a fixed class's mean time differs from the random class's:
//!
//! * **Fixed classes at extremes.**  A fixed secret drawn at random has
//!   about the random class's average count of whatever a leak would key
//!   on, so a target names several fixed classes, each a corner case of its
//!   secret.  Each fixed class is compared with the random class on its
//!   own.
//! * **Every class an equal share.**  Each sample is of the random class
//!   or of one of the K fixed classes, each with probability 1/(K + 1),
//!   the choice drawn from [`SplitMix64`].  Welch's t estimates each side's
//!   variance from that side's samples alone, and a run's slow tail is
//!   rare outliers that fall on whichever sample they hit, such as a
//!   neighbour's burst on the processor the run is pinned to.  A class
//!   that gets none of the outliers its share should bring has a lower mean
//!   and a far smaller variance than the random class, and its t comes out
//!   near -√k for the k outliers the random class got.  When the random
//!   class had half of the samples and each of 24 fixed classes 1/48, k was
//!   24 times a fixed class's expected count: a burst of 1 ms every 42 ms on
//!   average, on the pinned processor of an x86_64 desktop, drove a class
//!   that happened to get none past |t| 10 in the uncropped test, a false
//!   leak on unchanged code in 4 of 25 runs and 3 of 14 in a second
//!   series.  With equal shares k is about the class's own expected count,
//!   and t follows the difference of two counts of the same expectation,
//!   about a standard normal whatever the outliers' size.  For a leak on one
//!   class the equal shares cost no power: the variance of the difference
//!   of the two means is σ²(1/n_fixed + 1/n_random), 2(K + 1)σ²/N of N
//!   samples, the same as with half of them random.  The harness's tests
//!   simulate such a neighbour.
//! * **Inputs built ahead, every class's the same way** ([`by_class`]): a
//!   chunk of samples' inputs is built before any of them is timed, each
//!   from a buffer the random class's draw fills, over which a fixed
//!   class's bytes are written, so that what building allocates and frees
//!   does not depend on the class.  The timed region runs the operations,
//!   each on an input it borrows, and keeps their results; the inputs and
//!   the results are dropped outside it.  A chunk's inputs fit in a core's
//!   cache ([`CHUNK_BYTES`]).  An operation quicker than about two
//!   microseconds runs in a batch of the sample's class, so that the
//!   clock's cost and resolution are a small part of a sample.
//! * **dudect's crops.**  The first samples warm up and set the crops'
//!   thresholds, and are thrown away: crop i keeps the samples quicker than
//!   the warm-up's quantile 1 - 0.5^(10(i + 1)/100), for i from 0 to 99.
//!   Each fixed class is compared with the random class in the uncropped
//!   test and in every crop with [`MIN_SAMPLES`] samples on each side.
//! * **The verdict.**  A class fails the target when a comparison's |t| is
//!   above [`T_FAIL`], 10, dudect's threshold for a clear leak, and the
//!   largest difference between the class's mean time and the random
//!   class's among those comparisons is [`MIN_FAIL_NANOS`], 1 ns an
//!   operation, or more.  Above 10 on smaller differences alone a class is
//!   reported as under the floor, and above [`T_REPORT`], 4.5, it is
//!   reported; both pass.  A positive control must fail by the same rule
//!   ([`Report::assert_leak_found`]), or the run fails.
//! * **A known report.**  A crate can name, for one target, a failure it
//!   has measured and judged ([`KnownReport`]): on the architecture the
//!   binary is built for, a failure in which every comparison that fails
//!   has the fixed class quicker than the random class, by the report's
//!   bound or less, passes, and its row and its failing classes' lines
//!   say so where they would say LEAK.  A class slower than the random
//!   class, a difference beyond the bound, any other architecture and any
//!   target that names no known report fail as before.
//! * **A trace for reading a failure against other runs.**  Each target
//!   prints, whatever its verdict, each class's t and difference in the
//!   uncropped test and in crop 32 ([`FIXED_CROP`]), its t in each of six
//!   equal segments of the counted time ([`SEGMENTS`]), the random class's
//!   mean in each, the address of one of the harness's functions and of
//!   the first chunk of inputs, and the processors the thread may run on
//!   (`Cpus_allowed_list` of `/proc/self/status`, or `-` where there is
//!   none), which shows whether the run was pinned.  None of it changes
//!   what is timed or the verdict.
//!
//! Each target's budget is [`BUDGET_VAR`] seconds of wall time
//! ([`DEFAULT_SECONDS`] when it is unset).  A target prints one row,
//! marked `ct_check row |`, which `.github/workflows/constant-time.yml`
//! takes into the job's summary, and below it, when it passes, each
//! class's result and the trace (lines marked `ct_check run |`,
//! `ct_check random |` and `ct_check class |`); a failure's message
//! carries the same lines.  The harness's own tests run in every
//! `cargo test` and time nothing: they drive it with a simulated clock.
//!
//! It is statistical.  It sees a difference large enough to show on the
//! machine that runs it, fails only on one of a nanosecond an operation or
//! more, and a pass is not a proof.
#![allow(
    clippy::arithmetic_side_effects,
    reason = "test-harness arithmetic over counts, lengths, bit positions and nanoseconds, \
              each far below its type's limit"
)]

use std::env;
use std::fs;
use std::hint::black_box;
use std::time::Instant;

use crate::SplitMix64;

/// |t| above which a fixed class fails its target, on a difference of
/// [`MIN_FAIL_NANOS`] an operation or more: dudect's threshold for a clear
/// leak.
pub const T_FAIL: f64 = 10.0;

/// |t| above which a fixed class is reported, though it passes.
pub const T_REPORT: f64 = 4.5;

/// The difference between a fixed class's mean time and the random
/// class's, in nanoseconds an operation, that fails the class: its
/// comparisons above [`T_FAIL`] fail it when the largest difference among
/// them is this or more, and are reported, as under the floor, when it is
/// less.  The largest difference, since a crop that cuts into the slower
/// class's times shows less of the difference than the class has, often
/// in the comparison of the largest |t|, whose spread it cut more.  |t|
/// grows with the root of the samples, so at the millions of samples a
/// quick operation's run takes, a difference far below an instruction's
/// cost crosses 10: in `dcroxide-tlscrypto`'s targets, AES-256-GCM's seal
/// on the portable backends, 586 ns an operation, failed one of two 60 s
/// runs on one x86_64 processor at |t| 13.28, on a difference of 0.07 ns
/// that every fixed class showed alike.  A secret-dependent instruction
/// path costs a few cycles an operation at least, about a nanosecond at 3
/// to 5 GHz, which is the floor.  For an operation of tens of microseconds,
/// such as a secp256k1 signature, |t| 10 needs a difference of tens of
/// nanoseconds or more at the samples a minute gives, a limit of the
/// statistics and not of the floor.
pub const MIN_FAIL_NANOS: f64 = 1.0;

/// dudect's crops, in addition to the uncropped test.
const CROPS: usize = 100;

/// The crop whose comparison each class's trace line gives beside the
/// uncropped test's, whatever their |t|: crop 32, which keeps the samples
/// quicker than the warm-up's quantile 0.898, the nearest of dudect's to
/// nine tenths.  A class's result is its largest |t| over every test, so
/// results pooled over runs are statistics of a maximum; these two are
/// the same tests in every run.
pub const FIXED_CROP: usize = 32;

/// The equal parts of a run's counted time, from the warm-up's end to the
/// budget's, in each of which every fixed class is also compared with the
/// random class, uncropped: a sixth of the run each, about 10 s in a
/// nightly's 60 s and 50 s at 300 s.  A difference that lasts the whole
/// run shows in every one; one that comes and goes, in some.
pub const SEGMENTS: usize = 6;

/// The fewest samples each side of a comparison needs, in the uncropped
/// test or a crop, for its t to count.
pub const MIN_SAMPLES: u64 = 100;

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
/// the code under test finds the key it keeps.  In `dcroxide-tlscrypto`'s
/// targets a chunk of AES-GCM ciphers, about a kilobyte each, read from
/// beyond the cache made the fixed classes, whose ciphers are alike,
/// slightly quicker than the random class on one x86_64 processor; within
/// this bound it did not.
pub const CHUNK_BYTES: u64 = 256 * 1024;

/// The timed nanoseconds a chunk aims at, which bounds the building that
/// the end of the budget wastes for a slow operation.
const CHUNK_NANOS: u64 = 100_000_000;

/// The variable that sets each target's budget, in whole seconds.
pub const BUDGET_VAR: &str = "DCROXIDE_CT_SECONDS";

/// Each target's budget when [`BUDGET_VAR`] is unset: the push and pull
/// request screen's.
pub const DEFAULT_SECONDS: u64 = 10;

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

/// The segment ([`SEGMENTS`]) of a sample that began at `began`, of the
/// equal parts of the time from `from`, where the warm-up ended, to
/// `until`, where the budget does: the last for a sample begun at `until`
/// or later, and the first for one begun before `from`.
fn segment(began: u64, from: u64, until: u64) -> usize {
    let span = until.saturating_sub(from).max(1);
    let at = began.saturating_sub(from);
    (at.saturating_mul(SEGMENTS as u64) / span).min(SEGMENTS as u64 - 1) as usize
}

/// The comparisons of one target: for the uncropped samples and for each
/// crop, every class's [`Moments`], and for each segment of the run, every
/// class's uncropped.
struct Stats {
    /// Each crop's threshold in nanoseconds: a sample counts in crop i
    /// when it took less.
    thresholds: Vec<u64>,
    /// `tests[0]` counts every sample, and `tests[1 + i]` crop i's.  Each
    /// has a slot per class: the random class's is slot 0, and fixed class
    /// j's slot 1 + j.
    tests: Vec<Vec<Moments>>,
    /// `segments[k]` counts every sample of segment k ([`segment`]), with
    /// the slots of `tests`.
    segments: Vec<Vec<Moments>>,
}

impl Stats {
    /// No samples yet of the random class and `fixed` fixed classes, with
    /// the crops the warm-up's times set.
    fn new(warm_up: &mut [u64], fixed: usize) -> Stats {
        warm_up.sort_unstable();
        Stats {
            thresholds: crop_thresholds(warm_up),
            tests: vec![vec![Moments::default(); 1 + fixed]; 1 + CROPS],
            segments: vec![vec![Moments::default(); 1 + fixed]; SEGMENTS],
        }
    }

    /// Counts a sample of `nanos` of the class in `slot`, which began in
    /// segment `segment`.
    fn push(&mut self, slot: usize, nanos: u64, segment: usize) {
        let x = nanos as f64;
        self.tests[0][slot].push(x);
        for (crop, &threshold) in self.tests[1..].iter_mut().zip(&self.thresholds) {
            if nanos < threshold {
                crop[slot].push(x);
            }
        }
        self.segments[segment][slot].push(x);
    }

    /// Each fixed class's t against the random class in each segment, in
    /// the segments' order: `None` where a side has fewer than
    /// [`MIN_SAMPLES`].
    fn by_segment(&self) -> Vec<Vec<Option<f64>>> {
        (1..self.tests[0].len())
            .map(|slot| {
                self.segments
                    .iter()
                    .map(|segment| {
                        (segment[0].n >= MIN_SAMPLES && segment[slot].n >= MIN_SAMPLES)
                            .then(|| welch_t(&segment[slot], &segment[0]))
                    })
                    .collect()
            })
            .collect()
    }

    /// The random class's moments in the tests the trace gives: the
    /// uncropped test, [`FIXED_CROP`] and each segment, in that order.
    fn random(&self) -> Vec<Moments> {
        [&self.tests[0], &self.tests[1 + FIXED_CROP]]
            .into_iter()
            .chain(&self.segments)
            .map(|test| test[0])
            .collect()
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

/// A sample's class: the random class, `None`, or one of the `fixed` fixed
/// classes, each with probability 1/(`fixed` + 1), so that every
/// comparison is of two classes of equal shares (the module's notes say
/// why).
fn draw_class(rng: &mut SplitMix64, fixed: usize) -> Option<usize> {
    (rng.below(fixed as u64 + 1) as usize).checked_sub(1)
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
    /// The clock's time when the warm-up ended, where the segments begin.
    counted_from: u64,
    /// The clock's time when the budget ends, where the segments end.
    deadline: u64,
    /// The address of the first chunk's inputs, on the heap.
    inputs_at: usize,
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
/// their chunk.  The first samples warm up and set the crops; each later
/// one is counted in the segment of the time left that it began in
/// ([`segment`]); the run ends with the first sample to end past the
/// budget.  `build` takes the class,
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
    let mut counted_from = start;
    let mut inputs_at = None;
    loop {
        let classes: Vec<Option<usize>> = (0..chunk).map(|_| draw_class(rng, fixed)).collect();
        let mut inputs = Vec::with_capacity((chunk * batch) as usize);
        for &class in &classes {
            for _ in 0..batch {
                inputs.push(build(class, rng));
            }
        }
        inputs_at.get_or_insert(inputs.as_ptr().addr());
        for (class, batch_inputs) in classes.into_iter().zip(inputs.chunks_mut(batch as usize)) {
            let began = clock.now();
            for input in batch_inputs {
                results.push(black_box(op(black_box(input))));
            }
            let ended = clock.now();
            results.clear();
            let nanos = ended.saturating_sub(began);
            if let Some(stats) = stats.as_mut() {
                stats.push(slot(class), nanos, segment(began, counted_from, deadline));
                samples += 1;
            } else {
                warm_up.push(nanos);
                if warm_up.len() >= WARM_UP_SAMPLES || ended >= warm_up_end {
                    stats = Some(Stats::new(&mut warm_up, fixed));
                    counted_from = ended;
                }
            }
            if ended >= deadline {
                return Measured {
                    stats: stats.unwrap_or_else(|| Stats::new(&mut warm_up, fixed)),
                    batch,
                    samples,
                    warm_up: warm_up.len(),
                    nanos: ended.saturating_sub(start),
                    counted_from,
                    deadline,
                    inputs_at: inputs_at.unwrap_or_default(),
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
    /// A leak that is the target's known report ([`Report::is_known_report`]):
    /// every comparison that fails is quicker than the random class by the
    /// bound it carries, in nanoseconds an operation, or less.  Reported,
    /// and a pass.
    Known(u32),
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
            Verdict::Known(bound) => format!("known report (quicker by {bound} ns or less)"),
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

/// A failure a target is known to show on one architecture, measured and
/// judged by the crate that times it, which passes when it keeps to its
/// pattern: every comparison that fails has the fixed class quicker than
/// the random class, its t and its difference both below zero, by
/// `bound_nanos` an operation or less ([`Report::with_known_report`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KnownReport {
    /// The architecture the binary must be built for, as
    /// `std::env::consts::ARCH` names it.
    pub arch: &'static str,
    /// How much quicker than the random class, in whole nanoseconds an
    /// operation, a failing comparison can be and still be the known
    /// report.
    pub bound_nanos: u32,
}

/// A target's result: each fixed class's comparisons, and the run, from
/// [`time_target`] or [`time_inputs`].  [`Report::assert_constant_time`]
/// judges a target and [`Report::assert_leak_found`] a positive control.
pub struct Report {
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
    trace: Trace,
    /// The architecture the run's binary was built for,
    /// `std::env::consts::ARCH`, against which a known report's is matched.
    arch: &'static str,
    /// The target's known report, if it names one.
    known: Option<KnownReport>,
}

/// What a target's trace lines give besides its verdict, so that a failure
/// can be read against other runs: each fixed class's t in each segment,
/// the random class's moments in the tests the trace gives, and where the
/// run's code and inputs lay.
#[derive(Debug, Default)]
struct Trace {
    /// Each fixed class's t in each segment ([`Stats::by_segment`]).
    by_segment: Vec<Vec<Option<f64>>>,
    /// The random class's moments in the uncropped test, [`FIXED_CROP`]
    /// and each segment ([`Stats::random`]).
    random: Vec<Moments>,
    /// A segment's length in nanoseconds.
    segment_nanos: u64,
    /// The address of one of the harness's functions, `Stats::push`.  The
    /// binary is mapped whole, so with its symbols every function's
    /// address follows from this one.
    code: usize,
    /// The address of the run's first chunk of inputs, on the heap.
    inputs: usize,
    /// The processors the thread may run on, as `/proc/self/status` gives
    /// them in its `Cpus_allowed_list` line ([`allowed_cpus`]): one
    /// processor when the run was pinned, as `taskset -c` pins it.
    cpus: String,
}

/// The processors this thread may run on, from `status`, the text of
/// `/proc/self/status`: its `Cpus_allowed_list` line's value, or `-` when
/// there is none, as on a system without `/proc`.
fn allowed_cpus(status: Option<&str>) -> String {
    status
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))
        })
        .map_or_else(|| "-".to_owned(), |list| list.trim().to_owned())
}

impl Report {
    /// The report of the target `target`, whose fixed classes are `names`,
    /// on what [`measure`] found.
    fn new(target: &str, names: Vec<&'static str>, measured: &Measured) -> Report {
        let push: fn(&mut Stats, usize, u64, usize) = Stats::push;
        Report {
            target: target.to_owned(),
            names,
            by_class: measured.stats.by_class(),
            batch: measured.batch,
            samples: measured.samples,
            warm_up: measured.warm_up,
            seconds: measured.nanos as f64 / 1e9,
            trace: Trace {
                by_segment: measured.stats.by_segment(),
                random: measured.stats.random(),
                segment_nanos: measured.deadline.saturating_sub(measured.counted_from)
                    / SEGMENTS as u64,
                code: push as usize,
                inputs: measured.inputs_at,
                cpus: allowed_cpus(fs::read_to_string("/proc/self/status").ok().as_deref()),
            },
            arch: env::consts::ARCH,
            known: None,
        }
    }

    /// The report with `known` as its target's known report, or with none
    /// for `None`: a leak keeps to it when the binary was built for its
    /// architecture and every comparison of every class that fails has the
    /// fixed class quicker than the random class, its t and its difference
    /// both below zero, by its bound or less; such a leak then passes under
    /// a verdict of its own, which the row and the failing classes' lines
    /// give.  A comparison of a t or a difference that is not a number is
    /// never quicker.
    #[must_use]
    pub fn with_known_report(mut self, known: Option<KnownReport>) -> Report {
        self.known = known;
        self
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

    /// The target's verdict: that of the comparison that decides it
    /// ([`Report::deciding`]), as [`Report::known`] gives it.
    fn verdict(&self) -> Verdict {
        self.known(
            self.deciding()
                .map_or(Verdict::TooFew, |(_, c)| self.verdict_of(&c)),
        )
    }

    /// `verdict`, but a leak is [`Verdict::Known`] when the report is its
    /// target's known report ([`Report::is_known_report`]).
    fn known(&self, verdict: Verdict) -> Verdict {
        match self.known {
            Some(known) if verdict == Verdict::Leak && self.is_known_report() => {
                Verdict::Known(known.bound_nanos)
            }
            _ => verdict,
        }
    }

    /// Whether a failure of this report is its target's known report: the
    /// target names one ([`Report::with_known_report`]), the binary was
    /// built for its architecture, and every comparison of every class
    /// that fails, not only those that decide a class, has the fixed class
    /// quicker than the random class, t and difference both below zero, by
    /// the report's bound an operation or less.  A comparison of a t or a
    /// difference that is not a number is never quicker.
    fn is_known_report(&self) -> bool {
        self.known.is_some_and(|known| {
            let bound = f64::from(known.bound_nanos);
            self.arch == known.arch
                && self
                    .by_class
                    .iter()
                    .flatten()
                    .filter(|c| self.verdict_of(c) == Verdict::Leak)
                    .all(|c| c.t < 0.0 && (-bound..0.0).contains(&self.per_op(c).1))
        })
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
    /// each, a class that fails marked as the known report when the target
    /// is one ([`Report::known`]), and the run, followed by the trace
    /// ([`Report::trace_lines`]).
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
                        self.known(self.verdict_of(&c)).word()
                    )
                }
                None => format!("  {name}: no test with {MIN_SAMPLES} samples on each side\n"),
            };
        }
        out + &self.trace_lines()
    }

    /// The trace, the same lines whatever the verdict, each marked at its
    /// start and its columns split by ` | ` as the row's are, a `-` where
    /// there is nothing to give:
    ///
    /// * `ct_check run |` the target, [`FIXED_CROP`]'s name, the segments
    ///   and their length, the addresses of the harness's code and of the
    ///   first chunk's inputs, and the processors the thread may run on;
    /// * `ct_check random |` the target and the random class's mean
    ///   nanoseconds an operation in the uncropped test, in
    ///   [`FIXED_CROP`] and in each segment;
    /// * `ct_check class |`, for each fixed class, the target, the class,
    ///   its t and its difference in nanoseconds an operation in the
    ///   uncropped test and in [`FIXED_CROP`], whatever their |t|, and its
    ///   t in each segment.
    fn trace_lines(&self) -> String {
        let trace = &self.trace;
        let mut out = format!(
            "ct_check run | {} | {} | {SEGMENTS} segments of {:.1} s | code {:#x} | inputs {:#x} \
             | cpus {} |\n",
            self.target,
            test_name(1 + FIXED_CROP),
            trace.segment_nanos as f64 / 1e9,
            trace.code,
            trace.inputs,
            trace.cpus
        );
        let batch = self.batch as f64;
        let means: Vec<String> = (0..2 + SEGMENTS)
            .map(|test| match trace.random.get(test) {
                Some(m) if m.n > 0 => format!("{:.1}", m.mean / batch),
                _ => "-".to_owned(),
            })
            .collect();
        out += &format!(
            "ct_check random | {} | {} |\n",
            self.target,
            means.join(" | ")
        );
        for (class, (name, comparisons)) in self.names.iter().zip(&self.by_class).enumerate() {
            let mut columns = Vec::new();
            for test in [0, 1 + FIXED_CROP] {
                match comparisons.iter().find(|c| c.test == test) {
                    Some(c) => {
                        columns.push(format!("{:+.2}", c.t));
                        columns.push(format!("{:+.2}", self.per_op(c).1));
                    }
                    None => columns.extend(["-".to_owned(), "-".to_owned()]),
                }
            }
            for at in 0..SEGMENTS {
                columns.push(
                    match trace
                        .by_segment
                        .get(class)
                        .and_then(|segments| segments.get(at).copied().flatten())
                    {
                        Some(t) => format!("{t:+.2}"),
                        None => "-".to_owned(),
                    },
                );
            }
            out += &format!(
                "ct_check class | {} | {name} | {} |\n",
                self.target,
                columns.join(" | ")
            );
        }
        out
    }

    /// What a target prints: the row, with `verdict` as its verdict, and
    /// below it, when the target `passed`, the target's name and its
    /// detail, the lines a failure's message gives.
    fn printed(&self, verdict: &str, passed: bool) -> String {
        let mut out = self.row(verdict) + "\n";
        if passed {
            out += &format!("{}: {}", self.target, self.detail());
        }
        out
    }

    /// Prints the row, and the detail when the target passes, and fails
    /// when a fixed class has a comparison of |t| above [`T_FAIL`] on a
    /// difference of [`MIN_FAIL_NANOS`] an operation or more, unless that
    /// is the target's known report ([`Report::with_known_report`]), or when
    /// no comparison had the samples to count.  Returns what it printed.
    ///
    /// # Panics
    ///
    /// On a leak, or on too few samples, with each class's result and the
    /// trace in the message.
    pub fn assert_constant_time(&self) -> String {
        let verdict = self.verdict();
        let passed = matches!(
            verdict,
            Verdict::Pass | Verdict::Reported | Verdict::UnderFloor | Verdict::Known(_)
        );
        let printed = self.printed(&verdict.word(), passed);
        print!("{printed}");
        match verdict {
            Verdict::Pass | Verdict::Reported | Verdict::UnderFloor | Verdict::Known(_) => printed,
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

    /// The positive control's check: prints the row, and the detail when
    /// the control is found, and fails unless the control fails by the
    /// targets' rule, a comparison of |t| above [`T_FAIL`] on a difference
    /// of [`MIN_FAIL_NANOS`] an operation or more, since a run that does
    /// not see the control's leak, far larger than any a target looks for,
    /// sees none: its clock or its measurement is broken.  Returns what it
    /// printed.
    ///
    /// # Panics
    ///
    /// When the control's leak is not found.
    pub fn assert_leak_found(&self) -> String {
        let found = self.verdict() == Verdict::Leak;
        let verdict = if found {
            "control found"
        } else {
            "CONTROL NOT FOUND"
        };
        let printed = self.printed(verdict, found);
        print!("{printed}");
        assert!(
            found,
            "{}: the control's leak was not found, no comparison of |t| above {T_FAIL} on \
             {MIN_FAIL_NANOS} ns an operation or more: this run's clock or measurement does not \
             see a leak\n{}",
            self.target,
            self.detail()
        );
        printed
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
/// the class.  The placebo ([`PLACEBO`]) is the one class of no bytes:
/// nothing is written over its draw, so its input is drawn as the random
/// class's is.  Any other class of no bytes, or a placebo with bytes, is
/// a mistake in the class list, and building its input panics.
pub fn by_class<I>(
    classes: &[(&'static str, Vec<u8>)],
    mut draw: impl FnMut(&mut SplitMix64) -> Vec<u8>,
    mut build: impl FnMut(&[u8]) -> I,
) -> impl FnMut(Option<usize>, &mut SplitMix64) -> I {
    move |class, rng| {
        let mut bytes = draw(rng);
        if let Some(fixed) = class {
            let (label, value) = &classes[fixed];
            assert_eq!(
                value.is_empty(),
                *label == PLACEBO,
                "{label}: only the placebo is a class of no bytes"
            );
            if !value.is_empty() {
                bytes.copy_from_slice(value);
            }
        }
        build(&bytes)
    }
}

/// The inputs `input` makes, each with a hedge of `len` bytes drawn after
/// it from the same generator, for every class alike: a fixed class fixes
/// what `input` makes and not the hedge, which differs from one input to
/// the next, as a hedged signer's draw does from one signature to the
/// next.
pub fn with_hedge<I>(
    mut input: impl FnMut(Option<usize>, &mut SplitMix64) -> I,
    len: usize,
) -> impl FnMut(Option<usize>, &mut SplitMix64) -> (I, Vec<u8>) {
    move |class, rng| {
        let made = input(class, rng);
        (made, random_bytes(rng, len))
    }
}

/// The label of a placebo class, which has no bytes of its own: its
/// samples' inputs are drawn as the random class's are ([`by_class`]), so
/// it can lean only on what its label brings, from the harness or the
/// machine, and not on a value.
pub const PLACEBO: &str = "placebo";

/// Times `op` as the target `target`, for the budget [`BUDGET_VAR`] gives,
/// on inputs made from byte strings by [`by_class`]: each fixed class's
/// own, and for the random class one that `draw` makes.
///
/// # Panics
///
/// When [`BUDGET_VAR`] is set to anything but a whole number of seconds
/// above zero.
pub fn time_target<I, R>(
    target: &str,
    classes: &[(&'static str, Vec<u8>)],
    draw: impl FnMut(&mut SplitMix64) -> Vec<u8>,
    build: impl FnMut(&[u8]) -> I,
    op: impl FnMut(&mut I) -> R,
) -> Report {
    time_inputs(target, classes, by_class(classes, draw, build), op)
}

/// Times `op` as the target `target` of fixed classes `classes`, for the
/// budget [`BUDGET_VAR`] gives, on inputs `input` makes from the sample's
/// class, `None` for the random class, and the generator the random
/// class's input is drawn from.
///
/// # Panics
///
/// When [`BUDGET_VAR`] is set to anything but a whole number of seconds
/// above zero.
pub fn time_inputs<I, R>(
    target: &str,
    classes: &[(&'static str, Vec<u8>)],
    input: impl FnMut(Option<usize>, &mut SplitMix64) -> I,
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
        input,
        op,
    );
    let names = classes.iter().map(|(name, _)| *name).collect();
    Report::new(target, names, &measured)
}

/// `value` plus `delta`, big-endian at its own length.
///
/// # Panics
///
/// When the sum leaves `value`'s length, above or below.
pub fn plus(value: &[u8], delta: i16) -> Vec<u8> {
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
///
/// # Panics
///
/// When the product leaves `value`'s length.
pub fn times(value: &[u8], factor: u8) -> Vec<u8> {
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
pub fn bit(value: &[u8], at: usize) -> bool {
    value[value.len() - 1 - at / 8] >> (at % 8) & 1 == 1
}

/// Sets bit `at` of the big-endian `value` to `on`.
pub fn set_bit(value: &mut [u8], at: usize, on: bool) {
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
///
/// # Panics
///
/// When `value` has no set bit.
pub fn clear_eight(value: &[u8]) -> Vec<u8> {
    let set: Vec<usize> = (0..8 * value.len()).filter(|&at| bit(value, at)).collect();
    let mut out = value.to_vec();
    for i in 0..8 {
        set_bit(&mut out, set[i * set.len() / 8], false);
    }
    out
}

/// The classes in `candidates` but those whose value an earlier one has.
pub fn distinct(candidates: Vec<(&'static str, Vec<u8>)>) -> Vec<(&'static str, Vec<u8>)> {
    let mut out: Vec<(&'static str, Vec<u8>)> = Vec::new();
    for (name, value) in candidates {
        if out.iter().all(|(_, earlier)| *earlier != value) {
            out.push((name, value));
        }
    }
    out
}

/// `len` random bytes.
pub fn random_bytes(rng: &mut SplitMix64, len: usize) -> Vec<u8> {
    let mut bytes = vec![0; len];
    rng.fill(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::ops::Range;

    use super::*;

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
            trace: Trace::default(),
            arch: "x86_64",
            known: None,
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
        stats.push(1, 67, 0);
        stats.push(0, 66, 0);
        stats.push(1, 999, 0);
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
            stats.push(0, 1_000 + rng.below(100), 0);
            stats.push(1, 1_010 + rng.below(100), 0);
            stats.push(2, 1_000 + rng.below(100), 0);
            if i < MIN_SAMPLES - 1 {
                stats.push(3, 5_000, 0);
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

    /// A sample is of the random class or of each fixed class with the same
    /// probability: of 120,000 draws with five fixed classes, each of the
    /// six gets 20,000 within 700, about five standard deviations.
    #[test]
    fn every_class_has_an_equal_share() {
        let mut rng = SplitMix64(0x636c_6173_7365_7321);
        let mut counts = [0u32; 6];
        for _ in 0..120_000 {
            counts[slot(draw_class(&mut rng, 5))] += 1;
        }
        for count in counts {
            assert!((19_300..20_700).contains(&count), "{counts:?}");
        }
        assert_eq!(slot(None), 0);
        assert_eq!(slot(Some(4)), 5);
    }

    /// The fixed classes of the simulated bursty neighbour's target.
    const BURSTY_CLASSES: usize = 60;

    /// The report on a simulated target of [`BURSTY_CLASSES`] fixed classes
    /// alike, operations of 2,000 ns and up to 300 of noise, beside a
    /// neighbour that takes the processor for 100 µs in one operation of
    /// 100, drawn from a generator of its own seeded by `seed`, whatever
    /// the class: a run of about 30,000 samples, with about 300 outliers
    /// in the counted ones.  And the bursts the run met.
    fn bursty_report(seed: u64) -> (Report, u64) {
        let clock = Simulated(Cell::new(0));
        let neighbour = RefCell::new(SplitMix64(seed ^ 0x6e65_6967_6862_6f75));
        let bursts = Cell::new(0u64);
        let mut rng = SplitMix64(seed);
        let measured = measure(
            &clock,
            &mut rng,
            100_000_000,
            BURSTY_CLASSES,
            |_, rng| rng.below(300),
            |noise: &mut u64| {
                let burst = neighbour.borrow_mut().below(100) == 0;
                if burst {
                    bursts.set(bursts.get() + 1);
                }
                clock.advance(2_000 + *noise + if burst { 100_000 } else { 0 });
            },
        );
        let names = vec!["alike"; BURSTY_CLASSES];
        (Report::new("bursty", names, &measured), bursts.get())
    }

    /// A neighbour's rare bursts on the processor do not fail a class:
    /// on [`bursty_report`]'s target, under three seeds, every class's
    /// |t| stays at most [`T_FAIL`] in every test, and the target passes.
    /// The bursts are data-independent outliers of 50 operations' time,
    /// as a neighbour's spin on a pinned processor makes them.  With every
    /// class an equal share each gets about 300/61 of them.  When the
    /// random class had half of the samples, as the harness once drew
    /// them, it got about 150 and each fixed class about 2.5, so in nearly
    /// every run a few fixed classes got none, and their t, near -√150,
    /// about -12, in the uncropped test, failed them: the false leak a
    /// periodic neighbour caused on unchanged code (the module's notes).
    /// More classes than any target has make that near certain here with
    /// few samples; at a target's 24 the rate was lower, about one run in
    /// six.
    #[test]
    fn a_bursty_neighbour_does_not_fail_a_class() {
        for seed in [
            0x6275_7273_7479_2131,
            0x6275_7273_7479_2132,
            0x6275_7273_7479_2133,
        ] {
            let (report, bursts) = bursty_report(seed);
            assert!(
                report.samples > 25_000 && bursts > 250,
                "{bursts} bursts\n{}",
                report.detail()
            );
            assert_eq!(report.by_class.len(), BURSTY_CLASSES);
            for comparisons in &report.by_class {
                assert!(
                    comparisons.iter().any(|c| c.test == 0),
                    "{}",
                    report.detail()
                );
                for c in comparisons {
                    assert!(c.t.abs() <= T_FAIL, "{c:?}\n{}", report.detail());
                }
            }
            assert!(
                matches!(report.verdict(), Verdict::Pass | Verdict::Reported),
                "{}",
                report.detail()
            );
        }
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
            trace: Trace::default(),
            arch: "x86_64",
            known: None,
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
            trace: Trace::default(),
            arch: "x86_64",
            known: None,
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

    /// The known report the tests name: built for x86_64, quicker by 40 ns
    /// an operation or less, as `dcroxide-tlscrypto`'s P-256 signing by the
    /// nonce names it.
    const KNOWN: KnownReport = KnownReport {
        arch: "x86_64",
        bound_nanos: 40,
    };

    /// The report, with `known` as its known report, on a simulated run
    /// built for `arch`, in which each operation takes 1,000 ns, or
    /// `fixed`'s nanoseconds for a fixed class, and its input's noise,
    /// drawn up to 100 ns.
    fn known_report(known: Option<KnownReport>, arch: &'static str, fixed: [u64; 4]) -> Report {
        let (measured, _) = simulate_with(40_000_000, 100, |class, noise| {
            class.map_or(1_000, |class| fixed[class]) + noise
        });
        let mut report =
            Report::new("simulated", SIMULATED.to_vec(), &measured).with_known_report(known);
        assert_eq!(report.arch, env::consts::ARCH);
        report.arch = arch;
        report
    }

    /// A known report: built for its architecture, with two classes 15 ns
    /// an operation quicker than the random class, as `dcroxide-tlscrypto`
    /// measured them, it passes under a verdict of its own, which its row
    /// and those two classes' lines give, while the other classes pass as
    /// before.
    #[test]
    fn a_known_report_passes_under_its_own_verdict() {
        let report = known_report(Some(KNOWN), "x86_64", [985, 985, 1_000, 1_000]);
        let (class, deciding) = report.deciding().expect("comparisons");
        assert!(class < 2 && deciding.t < -T_FAIL, "{}", report.detail());
        assert_eq!(report.verdict_of(&deciding), Verdict::Leak);
        assert_eq!(report.verdict(), Verdict::Known(40), "{}", report.detail());
        let word = "known report (quicker by 40 ns or less)";
        assert_eq!(Verdict::Known(40).word(), word);
        let printed = report.assert_constant_time();
        let (row, detail) = printed.split_once('\n').expect("a row and a detail");
        assert!(row.ends_with(&format!(" | {word} |")), "{row}");
        for name in ["a", "b"] {
            let line = detail
                .lines()
                .find(|line| line.starts_with(&format!("  {name}: t -")))
                .expect("the class's line");
            assert!(line.ends_with(&format!(", {word}")), "{line}");
        }
        for name in ["c", "d"] {
            let line = detail
                .lines()
                .find(|line| line.starts_with(&format!("  {name}: t ")))
                .expect("the class's line");
            assert!(line.ends_with(", pass"), "{line}");
        }
    }

    /// Anything outside the known report fails as before: a class slower
    /// than the random class beside two quicker ones, a quicker class
    /// beyond the bound, the same pattern in a target that names no known
    /// report, and the same pattern built for another architecture than
    /// the known report's.
    #[test]
    fn only_the_known_pattern_is_a_known_report() {
        for (known, arch, fixed) in [
            (Some(KNOWN), "x86_64", [985, 985, 1_015, 1_000]),
            (Some(KNOWN), "x86_64", [985, 950, 1_000, 1_000]),
            (None, "x86_64", [985, 985, 1_000, 1_000]),
            (Some(KNOWN), "aarch64", [985, 985, 1_000, 1_000]),
        ] {
            let report = known_report(known, arch, fixed);
            assert_eq!(
                report.verdict(),
                Verdict::Leak,
                "{known:?} {arch} {fixed:?}\n{}",
                report.detail()
            );
            assert!(
                !report.detail().contains("known report"),
                "{}",
                report.detail()
            );
        }
    }

    #[test]
    #[should_panic(expected = "|t| above 10 and by 1 ns an operation or more")]
    fn a_slower_class_fails_a_target_with_a_known_report() {
        known_report(Some(KNOWN), "x86_64", [985, 985, 1_015, 1_000]).assert_constant_time();
    }

    #[test]
    #[should_panic(expected = "|t| above 10 and by 1 ns an operation or more")]
    fn the_known_pattern_fails_on_another_architecture() {
        known_report(Some(KNOWN), "aarch64", [985, 985, 1_000, 1_000]).assert_constant_time();
    }

    /// A known report does not find a positive control: a control whose
    /// leak keeps to a known report it was given is not found.
    #[test]
    #[should_panic(expected = "does not see a leak")]
    fn a_control_under_a_known_report_is_not_found() {
        known_report(Some(KNOWN), "x86_64", [985, 985, 1_000, 1_000]).assert_leak_found();
    }

    /// The known report's bound, on comparisons built by hand: quicker by
    /// 40 ns an operation is within it and by more is not; every failing
    /// comparison counts, not only the one that decides its class, so a
    /// class that fails quicker in one crop and slower in another is no
    /// known report; a comparison quicker in its means but of a positive t,
    /// or in its t but not its means, or of a t or a difference that is not
    /// a number, is not quicker; and comparisons that do not fail, slower
    /// or far quicker, leave a known report as it is.  Without a known
    /// report each failure is a leak.
    #[test]
    fn the_known_report_holds_every_failing_comparison_to_its_bound() {
        // Test `test`'s comparison of `t`, its fixed class `difference` ns
        // an operation slower, in samples of four operations.
        let comparison = |test: usize, t: f64, difference: f64| Comparison {
            t,
            test,
            fixed: 1_000,
            random: 3_000,
            fixed_mean: 40_000.0 + 4.0 * difference,
            random_mean: 40_000.0,
        };
        let report = |by_class: Vec<Vec<Comparison>>, known: Option<KnownReport>| Report {
            target: "hand".to_owned(),
            names: vec!["x", "y"],
            by_class,
            batch: 4,
            samples: 6_000,
            warm_up: 0,
            seconds: 0.0,
            trace: Trace::default(),
            arch: "x86_64",
            known,
        };
        let quiet = vec![comparison(0, 2.0, 3.0)];
        let known = Verdict::Known(40);
        for (failing, want) in [
            (vec![comparison(0, -12.0, -15.0)], known),
            (vec![comparison(0, -30.0, -40.0)], known),
            (vec![comparison(0, -30.0, -40.01)], Verdict::Leak),
            (vec![comparison(0, -30.0, -1.0)], known),
            (vec![comparison(0, 12.0, 15.0)], Verdict::Leak),
            (
                vec![comparison(0, -20.0, -15.0), comparison(12, 11.0, 1.5)],
                Verdict::Leak,
            ),
            (
                vec![comparison(0, -20.0, -15.0), comparison(12, -11.0, -41.0)],
                Verdict::Leak,
            ),
            (vec![comparison(0, 12.0, -15.0)], Verdict::Leak),
            (vec![comparison(0, -12.0, 15.0)], Verdict::Leak),
            (vec![comparison(0, f64::NAN, -15.0)], Verdict::Leak),
            (vec![comparison(0, -12.0, f64::NAN)], Verdict::Leak),
            (
                vec![
                    comparison(0, -20.0, -15.0),
                    comparison(12, 9.0, 3.0),
                    comparison(19, -9.0, -80.0),
                    comparison(31, 40.0, 0.5),
                ],
                known,
            ),
        ] {
            let both = report(vec![failing.clone(), quiet.clone()], Some(KNOWN));
            assert_eq!(both.verdict(), want, "{failing:?}\n{}", both.detail());
            let two = report(
                vec![failing.clone(), vec![comparison(0, -11.0, -20.0)]],
                Some(KNOWN),
            );
            assert_eq!(two.verdict(), want, "{failing:?}\n{}", two.detail());
            let none = report(vec![failing.clone(), quiet.clone()], None);
            assert_eq!(
                none.verdict(),
                Verdict::Leak,
                "{failing:?}\n{}",
                none.detail()
            );
        }
        let passing = report(vec![quiet.clone(), quiet], Some(KNOWN));
        assert_eq!(passing.verdict(), Verdict::Pass);
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

    /// A sample's segment is the sixth of the time from the warm-up's end
    /// to the budget's that it began in: the first from the start, the
    /// next from a sixth of the way, the last up to the budget's end and
    /// past it, and the first for a time before the start, which no
    /// counted sample has; a span that does not divide by six still splits
    /// at the sixths, and one of no time does not divide by zero.
    #[test]
    fn a_sample_falls_in_the_segment_it_began_in() {
        for (began, want) in [
            (1_000, 0),
            (1_099, 0),
            (1_100, 1),
            (1_299, 2),
            (1_300, 3),
            (1_500, 5),
            (1_599, 5),
            (1_600, 5),
            (50_000, 5),
            (999, 0),
        ] {
            assert_eq!(segment(began, 1_000, 1_600), want, "{began}");
        }
        for (began, want) in [(0, 0), (1, 0), (2, 1), (5, 3), (8, 4), (9, 5)] {
            assert_eq!(segment(began, 0, 10), want, "{began}");
        }
        assert_eq!(segment(5, 5, 5), 0);
        assert_eq!(segment(7, 5, 5), SEGMENTS - 1);
    }

    /// [`simulate`]'s target, operations of 500 ns and up to 1,000 of
    /// noise, for `budget`, in which fixed class 2 takes `leak` ns more in
    /// each operation that begins within `window`: the run, and each
    /// sample's class and the time it began, its first operation's.
    fn simulate_episode(
        budget: u64,
        leak: u64,
        window: Range<u64>,
    ) -> (Measured, Vec<(Option<usize>, u64)>) {
        let clock = Simulated(Cell::new(0));
        let ran = RefCell::new(Vec::new());
        let mut rng = SplitMix64(0x6570_6973_6f64_6573);
        let measured = measure(
            &clock,
            &mut rng,
            budget,
            SIMULATED.len(),
            |class, rng| (class, rng.below(1_000)),
            |&mut (class, noise): &mut (Option<usize>, u64)| {
                let now = clock.now();
                ran.borrow_mut().push((class, now));
                let extra = if class == Some(2) && window.contains(&now) {
                    leak
                } else {
                    0
                };
                clock.advance(500 + noise + extra);
            },
        );
        let batch = measured.batch as usize;
        let began = ran.into_inner()[CALIBRATION_OPS..]
            .chunks(batch)
            .map(|ops| ops[0])
            .collect();
        (measured, began)
    }

    /// Each counted sample is compared in the segment it began in, a sixth
    /// of the time from the warm-up's end to the budget's.  By the
    /// simulation's own count, from the sixths' bounds, each segment holds
    /// the samples of each class begun in it, and between them every
    /// counted sample; in a run of classes alike each holds about a sixth.
    /// A class 1,000 ns an operation slower in the fourth sixth alone is
    /// above |t| 10 there and within 4.5 in the other five, and every other
    /// class within 4.5 in all six.  The report keeps each t and the
    /// segments' length.
    #[test]
    fn each_class_is_compared_in_each_segment_of_the_run() {
        let budget = 40_000_000;
        let counts = |measured: &Measured| -> Vec<Vec<u64>> {
            measured
                .stats
                .segments
                .iter()
                .map(|segment| segment.iter().map(|m| m.n).collect())
                .collect()
        };
        let (alike, _) = simulate_episode(budget, 0, 0..0);
        let (from, until) = (alike.counted_from, alike.deadline);
        assert!(from > 0 && until == budget, "{from} {until}");
        let span = until - from;
        let sixth = alike.samples as f64 / SEGMENTS as f64;
        for segment in counts(&alike) {
            let total = segment.iter().sum::<u64>() as f64;
            assert!((total - sixth).abs() < 0.02 * sixth, "{total} {sixth}");
        }

        let bound = |k: u64| from + (k * span).div_ceil(SEGMENTS as u64);
        let (episode, began) = simulate_episode(budget, 1_000, bound(3)..bound(4));
        assert_eq!(episode.counted_from, from);
        let mut want = vec![vec![0; 1 + SIMULATED.len()]; SEGMENTS];
        for &(class, at) in &began[episode.warm_up..] {
            let k = (1..SEGMENTS as u64).filter(|&k| bound(k) <= at).count();
            want[k][slot(class)] += 1;
        }
        assert_eq!(counts(&episode), want);
        let uncropped: Vec<u64> = episode.stats.tests[0].iter().map(|m| m.n).collect();
        let summed: Vec<u64> = (0..=SIMULATED.len())
            .map(|slot| want.iter().map(|segment| segment[slot]).sum())
            .collect();
        assert_eq!(summed, uncropped);

        let by_segment = episode.stats.by_segment();
        assert_eq!(by_segment.len(), SIMULATED.len());
        for (class, segments) in by_segment.iter().enumerate() {
            assert_eq!(segments.len(), SEGMENTS);
            for (at, t) in segments.iter().enumerate() {
                let t = t.unwrap_or_else(|| panic!("class {class}, segment {at}: too few"));
                if (class, at) == (2, 3) {
                    assert!(t > T_FAIL, "{by_segment:?}");
                } else {
                    assert!(t.abs() <= T_REPORT, "{by_segment:?}");
                }
            }
        }
        let report = Report::new("simulated", SIMULATED.to_vec(), &episode);
        assert_eq!(report.trace.by_segment, by_segment);
        assert_eq!(report.trace.segment_nanos, span / SEGMENTS as u64);
    }

    /// A class is compared in a segment only with [`MIN_SAMPLES`] on each
    /// side: a segment one sample short on either side gives no t, one
    /// with enough on both Welch's t of its moments, and an empty one none.
    #[test]
    fn a_segment_short_of_samples_on_either_side_gives_no_t() {
        let mut warm_up: Vec<u64> = (1..=999).collect();
        let mut stats = Stats::new(&mut warm_up, 1);
        for i in 0..MIN_SAMPLES {
            let (random, fixed) = (500 + i % 7, 510 + i % 5);
            stats.push(0, random, 0);
            stats.push(1, fixed, 2);
            stats.push(0, random, 2);
            if i > 0 {
                stats.push(1, fixed, 0);
                stats.push(0, random, 1);
            }
            stats.push(1, fixed, 1);
        }
        let by_segment = stats.by_segment();
        assert_eq!(by_segment.len(), 1);
        assert_eq!(by_segment[0][..2], [None, None]);
        assert_eq!(
            by_segment[0][2],
            Some(welch_t(&stats.segments[2][1], &stats.segments[2][0]))
        );
        assert!(
            by_segment[0][2].is_some_and(|t| t > T_FAIL),
            "{by_segment:?}"
        );
        assert!(by_segment[0][3..].iter().all(Option::is_none));
    }

    /// The crop the trace gives beside the uncropped test is the one of
    /// dudect's whose quantile is nearest nine tenths, crop 32.
    #[test]
    fn the_fixed_crop_is_dudects_nearest_to_nine_tenths() {
        let off = |crop: usize| (crop_fraction(crop) - 0.9).abs();
        assert!(
            (0..CROPS).all(|crop| off(FIXED_CROP) <= off(crop)),
            "{FIXED_CROP}"
        );
        assert_eq!(test_name(1 + FIXED_CROP), "crop 32 (89.8%)");
    }

    /// The random class's moments in each test the trace gives, by hand:
    /// over warm-up times 1 to 999, crop 32 keeps the times under 898 (and
    /// crop 31 those under 891), so of the random class's 100 and 300 in
    /// the first segment and 894 and 902 in the last, every sample counts
    /// 4 at a mean of 549, crop 32 three at 431.3, the first segment two at
    /// 200 and the last two at 898, and the segments between none, though
    /// the fixed class has a sample in the third.  The trace gives them an
    /// operation, over a batch of 2, and a class without the samples to
    /// compare a `-` in each column.  Ten
    /// seconds a segment, from the warm-up's end at 1 s to the budget's at
    /// 61 s; the code is `Stats::push`'s.
    #[test]
    fn the_trace_gives_the_random_class_in_each_test_it_names() {
        let mut warm_up: Vec<u64> = (1..=999).collect();
        let mut stats = Stats::new(&mut warm_up, 1);
        assert_eq!(stats.thresholds[FIXED_CROP], 898);
        stats.push(0, 100, 0);
        stats.push(0, 300, 0);
        stats.push(0, 894, SEGMENTS - 1);
        stats.push(0, 902, SEGMENTS - 1);
        stats.push(1, 50, 2);
        let random = stats.random();
        let ns: Vec<u64> = random.iter().map(|m| m.n).collect();
        assert_eq!(ns, [4, 3, 2, 0, 0, 0, 0, 2]);
        for (test, want) in [(0, 549.0), (1, 1_294.0 / 3.0), (2, 200.0), (7, 898.0)] {
            assert!(
                (random[test].mean - want).abs() < 1e-9,
                "{test}: {random:?}"
            );
        }
        let measured = Measured {
            stats,
            batch: 2,
            samples: 5,
            warm_up: 999,
            nanos: 61_000_000_000,
            counted_from: 1_000_000_000,
            deadline: 61_000_000_000,
            inputs_at: 0x7f00_0000_1000,
        };
        let report = Report::new("hand", vec!["x"], &measured);
        let push: fn(&mut Stats, usize, u64, usize) = Stats::push;
        assert_eq!(report.trace.code, push as usize);
        assert_eq!(
            report.trace_lines(),
            format!(
                "ct_check run | hand | crop 32 (89.8%) | 6 segments of 10.0 s | code {:#x} | \
                 inputs 0x7f0000001000 | cpus {} |\n\
                 ct_check random | hand | 274.5 | 215.7 | 100.0 | - | - | - | - | 449.0 |\n\
                 ct_check class | hand | x | - | - | - | - | - | - | - | - | - | - |\n",
                push as usize, report.trace.cpus
            )
        );
    }

    /// The trace's lines by hand: each class's t and difference an
    /// operation in the uncropped test and crop 32, over a batch of 2,
    /// though another crop's |t| is larger and crop 31's sits beside it;
    /// its t in each segment, `-` where a segment had too few; the random
    /// class's means an operation, `-` where it had no sample; and a class
    /// with no comparison at all.  They end the detail.
    #[test]
    fn the_trace_lines_answer_a_hand_computation() {
        let comparison = |test: usize, t: f64, fixed_mean: f64, random_mean: f64| Comparison {
            t,
            test,
            fixed: 100,
            random: 400,
            fixed_mean,
            random_mean,
        };
        let moments = |n: u64, mean: f64| Moments { n, mean, m2: 0.0 };
        let report = Report {
            target: "hand".to_owned(),
            names: vec!["x", "y"],
            by_class: vec![
                vec![
                    comparison(0, -1.9, 3.0, 6.0),
                    comparison(5, 9.0, 500.0, 400.0),
                    comparison(1 + FIXED_CROP - 1, 7.77, 450.0, 400.0),
                    comparison(1 + FIXED_CROP, 2.346, 410.0, 400.0),
                ],
                vec![],
            ],
            batch: 2,
            samples: 1_000,
            warm_up: 0,
            seconds: 0.0,
            trace: Trace {
                by_segment: vec![
                    vec![
                        Some(1.234),
                        None,
                        Some(-0.5),
                        Some(10.0),
                        Some(-12.346),
                        None,
                    ],
                    vec![None; SEGMENTS],
                ],
                random: vec![
                    moments(10, 800.0),
                    moments(9, 780.0),
                    moments(2, 801.0),
                    moments(0, 0.0),
                    moments(1, 799.0),
                    moments(3, 802.0),
                    moments(4, 798.6),
                    moments(5, 800.25),
                ],
                segment_nanos: 9_870_000_000,
                code: 0x5555_0000_1234,
                inputs: 0xffff_8000_0010,
                cpus: "3".to_owned(),
            },
            arch: "x86_64",
            known: None,
        };
        let want = "ct_check run | hand | crop 32 (89.8%) | 6 segments of 9.9 s | code \
                    0x555500001234 | inputs 0xffff80000010 | cpus 3 |\n\
                    ct_check random | hand | 400.0 | 390.0 | 400.5 | - | 399.5 | 401.0 | 399.3 | \
                    400.1 |\n\
                    ct_check class | hand | x | -1.90 | -1.50 | +2.35 | +5.00 | +1.23 | - | -0.50 \
                    | +10.00 | -12.35 | - |\n\
                    ct_check class | hand | y | - | - | - | - | - | - | - | - | - | - |\n";
        assert_eq!(report.trace_lines(), want);
        assert!(report.detail().ends_with(want), "{}", report.detail());
    }

    /// A run gives where its code and its first chunk's inputs lay, and
    /// below its row, for every class, a trace line of ten columns, none
    /// empty in a run with the samples for each.
    #[test]
    fn a_run_traces_its_code_its_inputs_and_every_class() {
        let report = simulated_report(40_000_000, 0);
        let push: fn(&mut Stats, usize, u64, usize) = Stats::push;
        assert_eq!(report.trace.code, push as usize);
        assert!(
            report.trace.inputs != 0 && report.trace.inputs != report.trace.code,
            "{:?}",
            report.trace
        );
        let printed = report.assert_constant_time();
        assert!(
            printed.contains(&format!(
                "\nct_check run | simulated | crop 32 (89.8%) | 6 segments of 0.0 s | code {:#x} \
                 | inputs {:#x} | cpus {} |\n",
                report.trace.code, report.trace.inputs, report.trace.cpus
            )),
            "{printed}"
        );
        let random = printed
            .lines()
            .find(|line| line.starts_with("ct_check random | simulated | "))
            .expect("the random class's line");
        let columns: Vec<&str> = random
            .strip_suffix(" |")
            .expect("a closing bar")
            .split(" | ")
            .collect();
        assert_eq!(columns.len(), 2 + 2 + SEGMENTS, "{random}");
        assert!(!columns.contains(&"-"), "{random}");
        for name in SIMULATED {
            let prefix = format!("ct_check class | simulated | {name} | ");
            let line = printed
                .lines()
                .find(|line| line.starts_with(&prefix))
                .unwrap_or_else(|| panic!("{name}'s line in {printed}"));
            let columns: Vec<&str> = line
                .strip_suffix(" |")
                .expect("a closing bar")
                .split(" | ")
                .collect();
            assert_eq!(columns.len(), 3 + 4 + SEGMENTS, "{line}");
            assert!(!columns.contains(&"-"), "{line}");
        }
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

    /// A placebo, a class of no bytes, is built from its draw as it is,
    /// as the random class is, where a fixed class's bytes are written
    /// over the draw: from generators alike, a placebo's input and the
    /// random class's are the same draw, and inputs drawn one after
    /// another differ.
    #[test]
    fn a_placebo_is_built_from_the_draw_itself() {
        let classes = [("ones", vec![1; 8]), (PLACEBO, Vec::new())];
        let mut build = by_class(&classes, |rng| random_bytes(rng, 8), <[u8]>::to_vec);
        let seed = 0x706c_6163_6562_6f21;
        let (mut placebo, mut random) = (SplitMix64(seed), SplitMix64(seed));
        let mut inputs = Vec::new();
        for _ in 0..8 {
            let input = build(Some(1), &mut placebo);
            assert_eq!(input, build(None, &mut random));
            assert_eq!(build(Some(0), &mut random), vec![1; 8]);
            build(Some(0), &mut placebo);
            inputs.push(input);
        }
        assert!(
            inputs.windows(2).all(|pair| pair[0] != pair[1]),
            "{inputs:02x?}"
        );
    }

    /// A hedge is drawn for every input, after it, whatever its class:
    /// from generators alike, a fixed class's hedge and the placebo's are
    /// the random class's, and a fixed class's inputs one after another
    /// keep its value and differ in their hedges.
    #[test]
    fn a_hedge_is_drawn_for_every_input_whatever_its_class() {
        let classes = [("ones", vec![1; 8]), (PLACEBO, Vec::new())];
        let mut build = with_hedge(
            by_class(&classes, |rng| random_bytes(rng, 8), <[u8]>::to_vec),
            16,
        );
        let seed = 0x6865_6467_6573_2121;
        let (mut fixed, mut placebo, mut random) =
            (SplitMix64(seed), SplitMix64(seed), SplitMix64(seed));
        let mut hedges = Vec::new();
        for _ in 0..8 {
            let (value, hedge) = build(Some(0), &mut fixed);
            assert_eq!(value, vec![1; 8]);
            assert_eq!(hedge.len(), 16);
            let (drawn, random_hedge) = build(None, &mut random);
            assert_eq!(hedge, random_hedge);
            assert_eq!(build(Some(1), &mut placebo), (drawn, random_hedge));
            hedges.push(hedge);
        }
        assert!(
            hedges.windows(2).all(|pair| pair[0] != pair[1]),
            "{hedges:02x?}"
        );
    }

    /// Only the placebo may have no bytes: a fixed class of none under
    /// another label is a mistake, and building its input panics rather
    /// than timing it as a placebo under a value's name.
    #[test]
    #[should_panic(expected = "only the placebo is a class of no bytes")]
    fn an_empty_class_that_is_not_the_placebo_panics() {
        let classes = [("ones", Vec::new())];
        let mut build = by_class(&classes, |rng| random_bytes(rng, 8), <[u8]>::to_vec);
        build(Some(0), &mut SplitMix64(1));
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

    /// A target that passes prints its row and below it its detail under
    /// its name, every class's line as a failure's message gives them, and
    /// so does a control that is found; printed as a failure, with
    /// `passed` false, a target gives its row alone.
    #[test]
    fn a_passing_target_prints_its_detail_below_its_row() {
        let check = |report: &Report, printed: String, verdict: &str| {
            let (row, detail) = printed.split_once('\n').expect("a row and a detail");
            assert_eq!(row, report.row(verdict));
            assert_eq!(detail, format!("simulated: {}", report.detail()));
            for name in SIMULATED {
                assert!(detail.contains(&format!("\n  {name}: t ")), "{detail}");
            }
        };
        let alike = simulated_report(40_000_000, 0);
        check(&alike, alike.assert_constant_time(), "pass");
        let leak = simulated_report(40_000_000, 100);
        check(&leak, leak.assert_leak_found(), "control found");
        assert_eq!(leak.printed("LEAK", false), leak.row("LEAK") + "\n");
    }

    #[test]
    #[should_panic(expected = "|t| above 10")]
    fn a_leak_fails_its_target() {
        simulated_report(40_000_000, 100).assert_constant_time();
    }

    /// A target that fails gives its trace in its message, as it gives its
    /// classes' results.
    #[test]
    #[should_panic(expected = "\nct_check class | simulated | c | +")]
    fn a_failing_target_gives_its_trace_in_its_message() {
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

    /// The processors the trace names: the value of `/proc/self/status`'s
    /// `Cpus_allowed_list` line, trimmed, a single processor for a pinned
    /// run and a range for one that is not, and `-` without the line or
    /// the file.  This process's own status, where there is one, gives a
    /// value that is not empty.
    #[test]
    fn the_trace_names_the_processors_the_thread_may_run_on() {
        let status = "Name:\tct\nCpus_allowed:\t8000\nCpus_allowed_list:\t15\nMems_allowed:\t1\n";
        assert_eq!(allowed_cpus(Some(status)), "15");
        assert_eq!(allowed_cpus(Some("Cpus_allowed_list:\t0-31\n")), "0-31");
        assert_eq!(allowed_cpus(Some("Name:\tct\n")), "-");
        assert_eq!(allowed_cpus(None), "-");
        if let Ok(own) = fs::read_to_string("/proc/self/status") {
            let cpus = allowed_cpus(Some(&own));
            assert!(!cpus.is_empty() && cpus != "-", "{cpus}");
        }
    }
}
