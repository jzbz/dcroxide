// SPDX-License-Identifier: ISC
//! Signature pre-verification of the blocks read ahead, as the daemon
//! runs it (`dcroxide_blockchain::preverify`), which dcrd does not do
//! (PARITY *Signature pre-verification ahead of the block thread*): its
//! setting, how many helper threads it may hold, the one pre-verifier
//! of the process that the reading threads hand blocks to
//! ([`crate::readahead`]) and the sync chain gives its floor
//! ([`crate::sync`]), and the lines it logs.
//!
//! A reading thread hands the pre-verifier each block it has hashed
//! while the handler of its connection wants reading ahead, which it
//! does on the sync peer's connection until the initial chain sync is
//! done; the reading thread a connection keeps after that hands over
//! none of the blocks it reads in turn.  The pre-verifier checks the
//! block's signatures on script pool helpers no batch of a connected
//! block wants, and fills the signature cache the chain's connect checks
//! consult.  The thread that processes blocks withdraws a block as it
//! takes it, and from then on checks whatever was not reached, as it
//! does with pre-verification off.

use std::sync::{Arc, OnceLock};

use dcroxide_blockchain::preverify::Preverifier;
use dcroxide_blockchain::process::Chain;
use dcroxide_netsync::manager::LogLevel;
use dcroxide_txscript::SigCache;

/// The environment variable that sets signature pre-verification
/// ([`preverify_setting`]).
pub const PREVERIFY_VAR: &str = "DCROXIDE_PREVERIFY";

/// What [`PREVERIFY_VAR`] asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreverifySetting {
    /// No pre-verification: blocks are checked as dcrd checks them.
    Off,
    /// Pre-verification on the default number of helpers
    /// ([`default_helpers`]).
    Default,
    /// Pre-verification on at most this many helpers, never more than
    /// the script pool holds.
    Helpers(usize),
}

/// The setting [`PREVERIFY_VAR`] holds, with the line to log about it
/// now, if any, and the level to log it at.
///
/// Unset, pre-verification is on with the default number of helpers,
/// and nothing is said.  `off`, in any case, or a whole number that is
/// zero (`0`, `00`, `+0`) turns it off.  A positive whole number is the
/// most helpers it may hold; how many it holds is known, and said
/// ([`started_line`]), only once it is started.  Surrounding whitespace
/// is ignored.  Any other value is ignored with a warning rather than
/// being fatal, like the daemon's other tuning variables.
pub fn preverify_setting(setting: Option<&str>) -> (PreverifySetting, Option<(LogLevel, String)>) {
    let Some(raw) = setting else {
        return (PreverifySetting::Default, None);
    };
    let value = raw.trim();
    let helpers = if value.eq_ignore_ascii_case("off") {
        Some(0)
    } else {
        value.parse::<usize>().ok()
    };
    match helpers {
        Some(0) => {
            let line = format!("Signature pre-verification disabled by {PREVERIFY_VAR}");
            (PreverifySetting::Off, Some((LogLevel::Info, line)))
        }
        Some(helpers) => (PreverifySetting::Helpers(helpers), None),
        None => {
            let line = format!(
                "{PREVERIFY_VAR}={value} is neither off, 0 nor a whole number of helper threads; \
                 using the default"
            );
            (PreverifySetting::Default, Some((LogLevel::Warn, line)))
        }
    }
}

/// The helpers pre-verification holds by default, given the physical
/// cores the process may run on, if known, and its logical CPUs: two
/// fewer than the cores, which leaves one core to the thread that
/// processes blocks and one to the reading, index and commit threads,
/// plus one for every two logical CPUs beyond the cores, counting at
/// most one beyond each core; at least one where there are two cores or
/// more; none on a machine of one core.  Unknown, the cores are taken to
/// be half the logical CPUs.
///
/// Where the cores are known, any logical CPU beyond them is a hardware
/// thread SMT adds, so without SMT, or with one hardware thread of each
/// core allowed, the count is two fewer than the cores.  Where they are
/// not, the logical CPUs not taken for cores count as beyond them, at
/// most one for each, whether or not the machine has SMT: eight logical
/// CPUs give four helpers and sixteen give ten, where two fewer than the
/// cores taken would give two and six.  With two hardware threads to
/// each of eight known cores it is ten, where two fewer than the cores
/// is six: in syncs on one such machine ten helpers checked about nine
/// tenths of the inputs guessed for ahead of the thread that processes
/// blocks, and six about two thirds (PARITY *Signature pre-verification
/// ahead of the block thread*); no other count and no other machine was
/// measured.  It is a count, not a placement: where each helper runs is
/// the kernel's choice.
pub fn default_helpers(physical_cores: Option<usize>, logical_cpus: usize) -> usize {
    let cores = physical_cores.unwrap_or(logical_cpus / 2).min(logical_cpus);
    if cores < 2 {
        return 0;
    }
    let beyond = logical_cpus.saturating_sub(cores).min(cores);
    cores.saturating_sub(2).saturating_add(beyond / 2).max(1)
}

/// The CPUs a list in the kernel's format names (`0-3,8,10-11`), or
/// `None` when it is not one.
pub fn parse_cpu_list(list: &str) -> Option<Vec<usize>> {
    let list = list.trim();
    let mut cpus = Vec::new();
    if list.is_empty() {
        return Some(cpus);
    }
    for part in list.split(',') {
        match part.split_once('-') {
            Some((first, last)) => {
                let (first, last) = (first.parse::<usize>().ok()?, last.parse::<usize>().ok()?);
                if first > last || last.saturating_sub(first) > 65_536 {
                    return None;
                }
                cpus.extend(first..=last);
            }
            None => cpus.push(part.parse().ok()?),
        }
    }
    Some(cpus)
}

/// The number of distinct cores among CPUs whose sibling lists (each
/// CPU's `topology/core_cpus_list`) are given: CPUs of one core share
/// one list.
pub fn count_cores<'a>(sibling_lists: impl IntoIterator<Item = &'a str>) -> usize {
    let mut cores: Vec<Vec<usize>> = sibling_lists
        .into_iter()
        .map(|list| parse_cpu_list(list).unwrap_or_default())
        .collect();
    cores.sort_unstable();
    cores.dedup();
    cores.len()
}

/// The physical cores among the CPUs this process may run on, read from
/// `/proc/self/status` and each allowed CPU's topology in `/sys`, or
/// `None` where those cannot be read, as outside Linux.
pub fn physical_cores() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let allowed = status
        .lines()
        .find_map(|line| line.strip_prefix("Cpus_allowed_list:"))?;
    let cpus = parse_cpu_list(allowed)?;
    let mut lists = Vec::with_capacity(cpus.len());
    for cpu in cpus {
        let topology = format!("/sys/devices/system/cpu/cpu{cpu}/topology");
        let list = std::fs::read_to_string(format!("{topology}/core_cpus_list"))
            .or_else(|_| std::fs::read_to_string(format!("{topology}/thread_siblings_list")))
            .ok()?;
        lists.push(list);
    }
    let cores = count_cores(lists.iter().map(String::as_str));
    (cores > 0).then_some(cores)
}

/// The most bytes of serialized blocks the pre-verifier's queue holds:
/// every frame the read-ahead may hold, and the block being read, each
/// of the largest size a block message may have.
pub fn max_queued_bytes() -> usize {
    let block = usize::try_from(dcroxide_wire::MAX_BLOCK_PAYLOAD).unwrap_or(usize::MAX);
    block.saturating_mul(crate::readahead::READ_AHEAD_MAX_ITEMS.saturating_add(1))
}

/// The pre-verifier of the process, once [`install`] has made one.
static PREVERIFIER: OnceLock<Arc<Preverifier>> = OnceLock::new();

/// Why [`install`] started no pre-verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotStarted {
    /// The setting is off.
    Off,
    /// The chain has no signature cache, or one that keeps no entry
    /// (`--sigcachemaxsize=0`): what was verified ahead would be dropped.
    NoCache,
    /// No helper thread could take it: the default leaves none on a
    /// machine of fewer than two cores, and the script pool has none on
    /// a machine of one logical CPU.
    NoHelper,
    /// The process has a pre-verifier already.
    AlreadyStarted,
}

/// The pre-verifier `setting` asks for, filling `sig_cache`, which keeps
/// at most `sig_cache_max_entries` entries, or why there is none.
fn preverifier_for(
    sig_cache: Option<&Arc<SigCache>>,
    sig_cache_max_entries: u64,
    setting: PreverifySetting,
) -> Result<Preverifier, NotStarted> {
    let helpers = match setting {
        PreverifySetting::Off => return Err(NotStarted::Off),
        PreverifySetting::Helpers(helpers) => helpers,
        PreverifySetting::Default => {
            let logical = std::thread::available_parallelism().map_or(1, |n| n.get());
            default_helpers(physical_cores(), logical)
        }
    };
    let sig_cache = match sig_cache {
        Some(sig_cache) if sig_cache_max_entries > 0 => Arc::clone(sig_cache),
        _ => return Err(NotStarted::NoCache),
    };
    Preverifier::new(sig_cache, helpers, max_queued_bytes()).ok_or(NotStarted::NoHelper)
}

/// Start the process's pre-verifier as `setting` asks, filling the
/// signature cache of `chain`, which keeps at most
/// `sig_cache_max_entries` entries: the most helper threads it holds at
/// once, never more than the script pool holds, or why none was started.
pub fn install(
    chain: &Chain,
    sig_cache_max_entries: u64,
    setting: PreverifySetting,
) -> Result<usize, NotStarted> {
    let preverifier = preverifier_for(chain.sig_cache.as_ref(), sig_cache_max_entries, setting)?;
    let helpers = preverifier.helpers();
    PREVERIFIER
        .set(Arc::new(preverifier))
        .map_err(|_| NotStarted::AlreadyStarted)?;
    Ok(helpers)
}

/// The line to log about what [`install`] did with `setting`, or `None`
/// when the setting is off, which [`preverify_setting`]'s line has said:
/// the most helper threads in effect, or why none was started.  The
/// daemon logs it at info level when [`PREVERIFY_VAR`] named a number of
/// helpers, and at debug level for the default.
pub fn started_line(
    setting: PreverifySetting,
    started: Result<usize, NotStarted>,
) -> Option<String> {
    let by = match setting {
        PreverifySetting::Off => return None,
        PreverifySetting::Default => String::new(),
        PreverifySetting::Helpers(_) => format!(" by {PREVERIFY_VAR}"),
    };
    let why = match started {
        Ok(helpers) => {
            return Some(format!(
                "Signature pre-verification on at most {helpers} helper threads{by}"
            ));
        }
        Err(NotStarted::Off) => "it is off",
        Err(NotStarted::NoCache) => "the signature cache keeps no entry",
        Err(NotStarted::NoHelper) => "no helper thread can take it",
        Err(NotStarted::AlreadyStarted) => "it was started before",
    };
    Some(format!("Signature pre-verification not started: {why}"))
}

/// The process's pre-verifier, if one was started.
pub fn installed() -> Option<&'static Arc<Preverifier>> {
    PREVERIFIER.get()
}

/// Shut the process's pre-verifier down, if one was started: refuse
/// every later block, let go of the queued ones, and return once no
/// helper is checking one of them.
pub fn shutdown() {
    if let Some(preverifier) = installed() {
        preverifier.shutdown();
    }
}

/// What the process's pre-verifier did, as one line, or `None` when it
/// was never handed a block.  Blocks are those queued, inputs those that
/// got a guess, checked those the helpers ran, verified those whose
/// guessed script verified, which the chain's checks then find in the
/// signature cache unless an entry was evicted first; blocks cut short
/// are those the thread that processes blocks took, or the shutdown let
/// go of, before every input was run, and refused those the queue had no
/// room for.
pub fn shutdown_line() -> Option<String> {
    let preverifier = installed()?;
    let counts = preverifier.counts();
    if counts.blocks == 0 && counts.refused == 0 {
        return None;
    }
    Some(format!(
        "Signature pre-verification: {} blocks with {} inputs to guess for on at most {} \
         helpers; {} inputs checked ahead of the block thread, {} verified; {} blocks cut short \
         by the block thread or the shutdown; {} refused for room",
        counts.blocks,
        counts.inputs,
        preverifier.helpers(),
        counts.checked,
        counts.verified,
        counts.cut_short,
        counts.refused,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `off` and every spelling of zero turn it off and say so; a
    /// positive number is the most helpers, said once they are known;
    /// anything else warns and keeps the default.
    #[test]
    fn preverify_settings_parse() {
        assert_eq!(preverify_setting(None), (PreverifySetting::Default, None));
        for raw in ["off", "OFF", " Off ", "0", " 0\n", "00", "+0", "000"] {
            let (setting, line) = preverify_setting(Some(raw));
            assert_eq!(setting, PreverifySetting::Off, "{raw:?}");
            assert_eq!(
                line,
                Some((
                    LogLevel::Info,
                    "Signature pre-verification disabled by DCROXIDE_PREVERIFY".to_string()
                )),
                "{raw:?}"
            );
        }
        for (raw, helpers) in [("1", 1), (" 6 ", 6), ("64", 64), ("06", 6), ("+2", 2)] {
            let (setting, line) = preverify_setting(Some(raw));
            assert_eq!(setting, PreverifySetting::Helpers(helpers), "{raw:?}");
            assert_eq!(line, None, "{raw:?}");
        }
        for raw in ["", "on", "-1", "6 helpers", "1.5", "0x6"] {
            let (setting, line) = preverify_setting(Some(raw));
            assert_eq!(setting, PreverifySetting::Default, "{raw:?}");
            let (level, text) = line.expect("a warning");
            assert_eq!(level, LogLevel::Warn);
            assert!(
                text.starts_with(&format!("DCROXIDE_PREVERIFY={} is neither", raw.trim())),
                "{text}"
            );
        }
    }

    /// Two fewer helpers than cores, plus one for every two logical CPUs
    /// beyond the cores, at most one beyond each core counted; at least
    /// one from two cores, none on one, and half the logical CPUs taken
    /// for the cores when they are not known; never more cores than
    /// logical CPUs.  The rows are machines of each shape; then, for
    /// every count of cores up to 256, unknown included, and every count
    /// of logical CPUs up to 256, the default is never under two fewer
    /// than the cores, is exactly that where no CPU is beyond the cores,
    /// and never reaches past the pool's width, one fewer than the
    /// logical CPUs, so that width never has to cap it.
    #[test]
    fn the_default_is_two_under_the_cores_plus_half_of_at_most_one_cpu_beyond_each() {
        for (physical, logical, helpers) in [
            // One core.
            (Some(1), 1, 0),
            // No SMT: four, eight and sixteen cores.
            (Some(4), 4, 2),
            (Some(8), 8, 6),
            (Some(16), 16, 14),
            // Two hardware threads to each of two, four, eight and
            // sixteen cores; eight is the shape the default was measured
            // on.
            (Some(2), 4, 1),
            (Some(4), 8, 4),
            (Some(8), 16, 10),
            (Some(16), 32, 22),
            // Four hardware threads to each of four and eight cores.
            (Some(4), 16, 4),
            (Some(8), 32, 10),
            // Eight cores of two hardware threads and four of one.
            (Some(12), 20, 14),
            // Three whole cores of two hardware threads and one thread
            // of each of two more.
            (Some(5), 8, 4),
            // A quota of eight CPUs where sixteen cores are allowed.
            (Some(16), 8, 6),
            // The cores not read.
            (None, 4, 1),
            (None, 7, 2),
            (None, 8, 4),
            (None, 16, 10),
            // Edges.
            (Some(3), 3, 1),
            (Some(1), 2, 0),
            (Some(16), 4, 2),
            (None, 3, 0),
            (None, 1, 0),
            (Some(0), 8, 0),
        ] {
            assert_eq!(
                default_helpers(physical, logical),
                helpers,
                "{physical:?} cores, {logical} CPUs"
            );
        }
        for logical in 1..=256usize {
            for physical in std::iter::once(None).chain((0..=256).map(Some)) {
                let helpers = default_helpers(physical, logical);
                let cores = physical.unwrap_or(logical / 2).min(logical);
                let two_under = if cores < 2 {
                    0
                } else {
                    cores.saturating_sub(2).max(1)
                };
                assert!(
                    helpers >= two_under,
                    "{physical:?} cores, {logical} CPUs: {helpers}"
                );
                if logical == cores {
                    assert_eq!(helpers, two_under, "{physical:?} cores, {logical} CPUs");
                }
                assert!(
                    helpers <= logical.saturating_sub(1),
                    "{physical:?} cores, {logical} CPUs: {helpers}"
                );
            }
        }
    }

    #[test]
    fn cpu_lists_and_cores_parse() {
        assert_eq!(
            parse_cpu_list("0-3,8,10-11\n"),
            Some(vec![0, 1, 2, 3, 8, 10, 11])
        );
        assert_eq!(parse_cpu_list("5"), Some(vec![5]));
        assert_eq!(parse_cpu_list(""), Some(Vec::new()));
        for bad in ["3-1", "a", "1,,2", "1-", "-1", "0-999999"] {
            assert_eq!(parse_cpu_list(bad), None, "{bad:?}");
        }
        // Sixteen CPUs, two to a core, listed both ways the kernel does.
        let paired: Vec<String> = (0..16)
            .map(|cpu| format!("{},{}", cpu % 8, cpu % 8 + 8))
            .collect();
        assert_eq!(count_cores(paired.iter().map(String::as_str)), 8);
        let ranged: Vec<String> = (0..8)
            .map(|cpu| format!("{}-{}", cpu & !1, (cpu & !1) + 1))
            .collect();
        assert_eq!(count_cores(ranged.iter().map(String::as_str)), 4);
        assert_eq!(count_cores(["0", "1", "2"]), 3);
        assert_eq!(count_cores([]), 0);
    }

    /// The queue's bound is the read-ahead's frames and one more, each
    /// as large as a block message may be.
    #[test]
    fn the_queue_holds_what_the_read_ahead_may() {
        assert_eq!(max_queued_bytes(), 17 * 1_310_720);
    }

    /// Nothing is started with the setting off, without a cache, with a
    /// cache that keeps no entry or without a helper; otherwise the
    /// pre-verifier holds the helpers asked for, at most the script
    /// pool's.  (`install` itself, which sets the process's one
    /// pre-verifier, is pinned by `tests/preverify_install.rs`, in a
    /// process of its own.)
    #[test]
    fn the_off_switch_and_the_cache_decide_whether_one_starts() {
        let cache = Arc::new(SigCache::new(100));
        let not_started = |cache: Option<&Arc<SigCache>>, entries, setting| {
            preverifier_for(cache, entries, setting).err()
        };
        assert_eq!(
            not_started(Some(&cache), 100, PreverifySetting::Off),
            Some(NotStarted::Off)
        );
        for setting in [PreverifySetting::Default, PreverifySetting::Helpers(2)] {
            assert_eq!(not_started(None, 100, setting), Some(NotStarted::NoCache));
            assert_eq!(
                not_started(Some(&cache), 0, setting),
                Some(NotStarted::NoCache)
            );
        }
        assert_eq!(
            not_started(Some(&cache), 100, PreverifySetting::Helpers(0)),
            Some(NotStarted::NoHelper)
        );
        let pool_width = std::thread::available_parallelism()
            .map_or(1, |n| n.get())
            .saturating_sub(1);
        for asked in [1, 2, 64] {
            match preverifier_for(Some(&cache), 100, PreverifySetting::Helpers(asked)) {
                Ok(preverifier) => assert_eq!(preverifier.helpers(), asked.min(pool_width)),
                Err(reason) => {
                    assert_eq!((reason, pool_width), (NotStarted::NoHelper, 0));
                }
            }
        }
    }

    /// What is logged once `install` has run: the helpers in effect, not
    /// the number asked for, or why none started; nothing for off.
    #[test]
    fn the_started_line_says_what_is_in_effect() {
        let line = |setting, started| started_line(setting, started);
        assert_eq!(line(PreverifySetting::Off, Err(NotStarted::Off)), None);
        assert_eq!(
            line(PreverifySetting::Helpers(64), Ok(15)).as_deref(),
            Some("Signature pre-verification on at most 15 helper threads by DCROXIDE_PREVERIFY")
        );
        assert_eq!(
            line(PreverifySetting::Default, Ok(10)).as_deref(),
            Some("Signature pre-verification on at most 10 helper threads")
        );
        for (setting, reason, why) in [
            (
                PreverifySetting::Helpers(4),
                NotStarted::NoCache,
                "the signature cache keeps no entry",
            ),
            (
                PreverifySetting::Default,
                NotStarted::NoHelper,
                "no helper thread can take it",
            ),
            (
                PreverifySetting::Helpers(4),
                NotStarted::AlreadyStarted,
                "it was started before",
            ),
        ] {
            assert_eq!(
                line(setting, Err(reason)),
                Some(format!("Signature pre-verification not started: {why}"))
            );
        }
    }
}
