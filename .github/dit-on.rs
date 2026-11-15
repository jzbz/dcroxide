// SPDX-License-Identifier: ISC
//! Switches Arm's DIT on for a whole test binary, for a dispatch of
//! `.github/workflows/constant-time.yml` that asks for it on the arm64
//! legs.  DIT is the mode in which the timing of Arm's listed
//! instructions does not depend on their data.  The kernels of those
//! runners do not report DIT, so `constant_time_eq`'s switch, which asks
//! the kernel first, leaves it off; `.github/dit-probe.rs` found that user
//! space can set it there all the same.
//!
//! The workflow compiles this with plain `rustc` as a `cdylib` and runs
//! the test binary with it in `LD_PRELOAD`, through cargo's runner for the
//! target, so that it loads into that binary alone.  Its constructor runs
//! in the main thread before `main`: it sets PSTATE.DIT and reads it back,
//! and reads it in a thread it starts, since the test harness runs each
//! target on a thread of its own.  Linux keeps PSTATE.DIT for each thread
//! (saved with the rest of PSTATE on each entry to the kernel and restored
//! on return), a new thread starts with its parent's, and exec clears it,
//! which is why it is set here, after exec, and not by a program that
//! starts the test binary.  At exit it reads it again in the main thread.
//! Each reading is printed in a line marked `ct_check dit |`, which the
//! workflow looks for, and a reading of 0 after the switch stops the
//! process, so that a run that asked for DIT never passes with DIT seen
//! off in the main thread or in a new thread.  The test harness's own
//! threads are not read; that they keep it rests on the kernel.
//!
//! It is no part of the workspace, which forbids `unsafe`, for the same
//! reason as the probe: PSTATE.DIT is read and written with `mrs` and
//! `msr`, which have no stable intrinsic, and its constructor is a
//! pointer to a function in `.init_array`.  Nothing ships it and `cargo
//! test` does not build it.

#![cfg(target_arch = "aarch64")]

use std::arch::asm;

/// Run by the dynamic loader once the library has loaded, before the
/// program's `main`.
#[used]
// SAFETY: `.init_array` holds pointers to functions that take no
// arguments the callee reads and return nothing, which `switch_on` is.
#[unsafe(link_section = ".init_array")]
static SWITCH_ON: extern "C" fn() = switch_on;

/// Run by `exit`, in the thread that calls it.
#[used]
// SAFETY: as for `.init_array`.
#[unsafe(link_section = ".fini_array")]
static READ_AT_EXIT: extern "C" fn() = read_at_exit;

extern "C" fn switch_on() {
    // SAFETY: the instructions touch no memory and no register but the
    // one they name and PSTATE.DIT.  On a processor without FEAT_DIT they
    // are undefined, and the kernel ends the process with SIGILL, which
    // fails the run that asked for DIT.
    let before = unsafe { read() };
    // SAFETY: as above.
    unsafe { set() };
    // SAFETY: as above.
    let set = unsafe { read() };
    // SAFETY: as above, in a thread that inherits PSTATE.DIT from this
    // one.
    let thread = std::thread::spawn(|| unsafe { read() })
        .join()
        .unwrap_or(u64::MAX);
    eprintln!(
        "ct_check dit | PSTATE.DIT read {before} at load, {set} once set, \
         {thread} in a new thread"
    );
    if (set, thread) != (1, 1) {
        eprintln!("ct_check dit | DIT did not hold; stopping");
        std::process::abort();
    }
}

extern "C" fn read_at_exit() {
    // SAFETY: as in `switch_on`, whose switch has run on this processor.
    let now = unsafe { read() };
    eprintln!("ct_check dit | PSTATE.DIT read {now} at exit");
    if now != 1 {
        eprintln!("ct_check dit | DIT did not hold; stopping");
        std::process::abort();
    }
}

/// PSTATE.DIT, 0 or 1.
///
/// # Safety
///
/// The processor must implement FEAT_DIT; on one that does not, the
/// instruction is undefined.
#[target_feature(enable = "dit")]
unsafe fn read() -> u64 {
    let dit: u64;
    // SAFETY: the caller's.
    unsafe { asm!("mrs {}, dit", out(reg) dit, options(nomem, nostack, preserves_flags)) };
    // DIT is bit 24 of the register.
    (dit >> 24) & 1
}

/// Sets PSTATE.DIT.
///
/// # Safety
///
/// As for [`read`].
#[target_feature(enable = "dit")]
unsafe fn set() {
    // SAFETY: the caller's.
    unsafe { asm!("msr dit, #1", options(nomem, nostack, preserves_flags)) };
}
