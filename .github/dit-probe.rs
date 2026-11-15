// SPDX-License-Identifier: ISC
//! Whether user space on this arm64 machine can switch DIT on: Arm's mode
//! in which the timing of its listed instructions does not depend on their
//! data.  A kernel that does not report DIT may still run on a processor
//! that has it, the feature hidden from the guest, so the probe sets
//! PSTATE.DIT, reads it back, and clears it again.
//!
//! `.github/workflows/constant-time.yml` compiles this with plain `rustc`
//! and runs it in the arm64 jobs' step that describes the processor, which
//! never fails a job.  It is no part of the workspace, which forbids
//! `unsafe`: reading and writing PSTATE.DIT takes `asm!`, an `mrs` and an
//! `msr`, which have no stable intrinsic.  Nothing ships it and `cargo
//! test` does not build it.  The process ends once it has printed, so the
//! timed targets, which run in a process of their own, keep DIT as Linux
//! leaves it, off, unless a dispatch asks for DIT, which
//! `.github/dit-on.rs` then switches on in the test binary itself.

#[cfg(target_arch = "aarch64")]
fn main() {
    let reported = std::arch::is_aarch64_feature_detected!("dit");
    // SAFETY: the instructions touch no memory and no register but the one
    // they name and PSTATE.DIT.  On a processor without FEAT_DIT they are
    // undefined, and the kernel ends the process with SIGILL, which the
    // workflow reports.
    let (before, set, cleared) = unsafe { switch() };
    println!(
        "DIT probe: the kernel {} DIT; PSTATE.DIT read {before} at first, {set} once set, \
         {cleared} once cleared",
        if reported {
            "reports"
        } else {
            "does not report"
        }
    );
    println!(
        "DIT probe: {}",
        if (set, cleared) == (1, 0) {
            "user space can switch DIT on"
        } else {
            "DIT did not hold when set"
        }
    );
}

/// Reads PSTATE.DIT, sets it and reads it again, clears it and reads it
/// once more: the three readings, 0 or 1 each.
///
/// # Safety
///
/// The processor must implement FEAT_DIT; on one that does not, the
/// instructions are undefined.
#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "dit")]
unsafe fn switch() -> (u64, u64, u64) {
    use std::arch::asm;

    let (before, set, cleared): (u64, u64, u64);
    // SAFETY: the caller's; see `main`.
    unsafe {
        asm!("mrs {}, dit", out(reg) before, options(nomem, nostack, preserves_flags));
        asm!("msr dit, #1", options(nomem, nostack, preserves_flags));
        asm!("mrs {}, dit", out(reg) set, options(nomem, nostack, preserves_flags));
        asm!("msr dit, #0", options(nomem, nostack, preserves_flags));
        asm!("mrs {}, dit", out(reg) cleared, options(nomem, nostack, preserves_flags));
    }
    // DIT is bit 24 of the register.
    ((before >> 24) & 1, (set >> 24) & 1, (cleared >> 24) & 1)
}

#[cfg(not(target_arch = "aarch64"))]
fn main() {
    println!("DIT probe: not an arm64 machine");
}
