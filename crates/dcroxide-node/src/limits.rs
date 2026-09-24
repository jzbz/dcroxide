// SPDX-License-Identifier: ISC
//! Process limits (dcrd `internal/limits`), together with the
//! descriptor-limit raise every Go program gets from its runtime before
//! dcrd's `main` runs.
//!
//! dcrd runs with its soft `RLIMIT_NOFILE` one below the hard limit:
//! Go's `syscall` package init raises it (`syscall/rlimit.go`), and
//! `limits.SetLimits` then only has to check it.  A Rust program keeps
//! whatever soft limit it inherits -- 1024 under systemd's default and
//! in most Linux shells, 256 in macOS shells -- so the daemon performs
//! both steps itself.

/// The soft limit `SetLimits` settles for when the limit is lower
/// (dcrd `fileLimitWant`).
const FILE_LIMIT_WANT: u64 = 2048;

/// The hard limit below which `SetLimits` refuses to run (dcrd
/// `fileLimitMin`).
const FILE_LIMIT_MIN: u64 = 1024;

/// The soft descriptor limit the Go runtime's `syscall` package init
/// asks for, or `None` when it leaves the limit alone
/// (`syscall/rlimit.go`): one below the hard limit, so that a later
/// `prlimit` to exactly the hard limit is recognizable, and only when
/// the soft limit is lower than that.  Limits are Go's numbers, with an
/// unlimited value as the platform's `RLIM_INFINITY`.
pub fn go_runtime_nofile(cur: u64, max: u64) -> Option<u64> {
    // Go's `lim.Max > 0 && lim.Cur < lim.Max-1`.
    let want = max.checked_sub(1)?;
    (cur < want).then_some(want)
}

/// What dcrd's `SetLimits` does with a descriptor limit
/// (`internal/limits/limits_unix.go`): `Ok(None)` leaves a soft limit
/// above 2048 alone, `Ok(Some(soft))` is the soft limit it sets --
/// 2048, or the hard limit when that is lower -- and a hard limit below
/// 1024 is its error.
pub fn set_limits_target(cur: u64, max: u64) -> Result<Option<u64>, String> {
    if cur > FILE_LIMIT_WANT {
        return Ok(None);
    }
    if max < FILE_LIMIT_MIN {
        return Err(format!("need at least {FILE_LIMIT_MIN} file descriptors"));
    }
    Ok(Some(max.min(FILE_LIMIT_WANT)))
}

/// The largest soft limit in `(known_good, want]` that `try_set`
/// accepts, leaving it set, or `known_good` (the limit already in
/// effect) when none is.  macOS refuses a soft descriptor limit above
/// `kern.maxfilesperproc` with `EINVAL` (older releases even refuse the
/// unlimited value), so Go clamps to that sysctl before asking
/// (`syscall/rlimit_darwin.go` `adjustFileLimit`).  With no safe sysctl
/// to read, the bisection finds the same value for an ordinary user,
/// since every limit up to it is accepted and every one above refused
/// (root's ceiling is `kern.maxfiles` instead).  A refused attempt
/// leaves the limit untouched, so the one in effect afterwards is the
/// last accepted, which is the result.
pub fn largest_accepted(known_good: u64, want: u64, try_set: &mut dyn FnMut(u64) -> bool) -> u64 {
    if want <= known_good || try_set(want) {
        return want.max(known_good);
    }
    let (mut lo, mut hi) = (known_good, want);
    while hi.abs_diff(lo) > 1 {
        let mid = lo.saturating_add(hi.abs_diff(lo) / 2);
        if try_set(mid) {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    lo
}

/// The platform's `RLIM_INFINITY` as Go's `Rlimit` fields carry it:
/// Go reads the Linux limits through `prlimit64`, whose unlimited value
/// is all ones, as rustix's does.
#[cfg(any(target_os = "linux", target_os = "android"))]
const RLIM_INFINITY: u64 = u64::MAX;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
#[allow(clippy::unnecessary_cast)] // rlim_t is u64 on Apple, i64 on the BSDs.
const RLIM_INFINITY: u64 = libc::RLIM_INFINITY as u64;

#[cfg(unix)]
fn to_go(limit: Option<u64>) -> u64 {
    limit.unwrap_or(RLIM_INFINITY)
}

#[cfg(unix)]
fn from_go(limit: u64) -> Option<u64> {
    (limit != RLIM_INFINITY).then_some(limit)
}

/// Raise the soft descriptor limit as the Go runtime does for dcrd
/// before any of its code runs (`syscall/rlimit.go` `init`).  Like Go,
/// it reports nothing: a refused raise leaves the inherited limit for
/// [`set_limits`] to judge.
#[cfg(unix)]
pub fn raise_nofile_like_go_runtime() {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

    let lim = getrlimit(Resource::Nofile);
    let (cur, max) = (to_go(lim.current), to_go(lim.maximum));
    let Some(want) = go_runtime_nofile(cur, max) else {
        return;
    };
    let mut try_set = |soft: u64| {
        setrlimit(
            Resource::Nofile,
            Rlimit {
                current: from_go(soft),
                maximum: lim.maximum,
            },
        )
        .is_ok()
    };
    if cfg!(target_vendor = "apple") {
        largest_accepted(cur, want, &mut try_set);
    } else {
        try_set(want);
    }
}

/// Windows has no descriptor limit to raise, and Go's runtime raises
/// none there.
#[cfg(not(unix))]
pub fn raise_nofile_like_go_runtime() {}

/// Raise the process limits dcrd needs to run (dcrd `limits.SetLimits`,
/// which its `main` calls first, exiting with `failed to set limits:
/// <err>` and status 1 on an error).
#[cfg(unix)]
pub fn set_limits() -> Result<(), String> {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

    let lim = getrlimit(Resource::Nofile);
    let Some(soft) = set_limits_target(to_go(lim.current), to_go(lim.maximum))? else {
        return Ok(());
    };
    let set = |soft: u64| {
        setrlimit(
            Resource::Nofile,
            Rlimit {
                current: from_go(soft),
                maximum: lim.maximum,
            },
        )
    };
    // On a refusal, try the minimum value.
    set(soft)
        .or_else(|_| set(FILE_LIMIT_MIN))
        .map_err(|e| go_errno_text(&e))
}

/// Windows needs no limits raised (dcrd `limits_windows.go`).
#[cfg(not(unix))]
pub fn set_limits() -> Result<(), String> {
    Ok(())
}

/// An errno as Go's `syscall.Errno` renders it: the C library's text
/// with a lowercase first letter and no "(os error N)" suffix.
#[cfg(unix)]
fn go_errno_text(e: &rustix::io::Errno) -> String {
    let text = std::io::Error::from_raw_os_error(e.raw_os_error()).to_string();
    let text = text.split(" (os error ").next().unwrap_or_default();
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().chain(chars).collect(),
        None => format!("errno {}", e.raw_os_error()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Go lifts the soft limit to one below the hard limit, and leaves
    /// it alone once it is there or above, or when there is no room.
    #[test]
    fn the_go_runtime_raises_to_one_below_the_hard_limit() {
        assert_eq!(go_runtime_nofile(1024, 524_288), Some(524_287));
        assert_eq!(go_runtime_nofile(256, u64::MAX), Some(u64::MAX - 1));
        assert_eq!(go_runtime_nofile(524_286, 524_288), Some(524_287));
        assert_eq!(go_runtime_nofile(524_287, 524_288), None);
        assert_eq!(go_runtime_nofile(524_288, 524_288), None);
        assert_eq!(go_runtime_nofile(0, 1), None);
        assert_eq!(go_runtime_nofile(0, 0), None);
    }

    /// dcrd's `SetLimits`: above 2048 is left alone, a hard limit below
    /// 1024 is refused with its error text, and otherwise the soft
    /// limit goes to 2048 or the hard limit, whichever is lower.
    #[test]
    fn set_limits_wants_2048_and_needs_1024() {
        assert_eq!(set_limits_target(2049, 4096), Ok(None));
        assert_eq!(set_limits_target(524_287, 524_288), Ok(None));
        assert_eq!(set_limits_target(1024, 524_288), Ok(Some(2048)));
        assert_eq!(set_limits_target(2048, 4096), Ok(Some(2048)));
        assert_eq!(set_limits_target(256, 1500), Ok(Some(1500)));
        assert_eq!(set_limits_target(1024, 1024), Ok(Some(1024)));
        assert_eq!(
            set_limits_target(512, 1023),
            Err("need at least 1024 file descriptors".to_string())
        );
    }

    /// Against a kernel that refuses anything above its per-process
    /// maximum, the bisection lands on that maximum and leaves it set,
    /// as Go's clamp to `kern.maxfilesperproc` does.
    #[test]
    fn the_bisection_finds_the_largest_accepted_limit() {
        for per_proc in [256, 257, 10_240, 245_760, u64::MAX - 1] {
            let mut current = 256u64;
            let mut try_set = |soft: u64| {
                let ok = soft <= per_proc;
                if ok {
                    current = soft;
                }
                ok
            };
            let got = largest_accepted(256, u64::MAX - 1, &mut try_set);
            assert_eq!(got, per_proc, "per-process maximum {per_proc}");
            assert_eq!(current, per_proc, "the limit left in effect");
        }
        // Nothing to raise.
        let mut never = |_: u64| -> bool { panic!("no attempt expected") };
        assert_eq!(largest_accepted(4096, 4096, &mut never), 4096);
    }

    /// Errnos read as Go's `syscall.Errno` strings.
    #[cfg(unix)]
    #[test]
    fn errnos_render_as_go_does() {
        assert_eq!(
            go_errno_text(&rustix::io::Errno::PERM),
            "operation not permitted"
        );
        assert_eq!(go_errno_text(&rustix::io::Errno::INVAL), "invalid argument");
    }
}
