// SPDX-License-Identifier: ISC
//! promptsecret on a real terminal, which `script(1)` provides: it runs
//! the tool on a fresh pty fed from this test's pipe and copies the
//! pty's output back.
//!
//! - The terminal-state snapshot ran `stty -g` through
//!   `Command::output`, which gives the child a null stdin, so stty
//!   never saw the terminal and the tool refused every secret with
//!   "inappropriate ioctl for device" (dcrd's x/term reads it).
//! - The secret went through std's buffered `Stdin` and `Stdout`, whose
//!   buffers kept copies after the zeroing for the rest of the process;
//!   dcrd reads and writes the descriptors directly and zeroes its one
//!   buffer.

#![cfg(target_os = "linux")]
// Test-harness arithmetic over fixed deadlines and memory ranges.
#![allow(clippy::arithmetic_side_effects)]

use std::io::{Read, Write};
use std::os::unix::fs::FileExt;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// An eight-byte secret: `Vec` growth starts at eight bytes of
/// capacity, so reading it leaves no reallocated prefix behind (the
/// growth copies x/term's `append` leaves too) and every full copy in
/// memory is one the tool made.
const SECRET: &str = "zY8qWv3K";

/// promptsecret running on a pty under `script`.
struct Session {
    child: Child,
    stdin: ChildStdin,
    output: mpsc::Receiver<Vec<u8>>,
    seen: Vec<u8>,
}

impl Session {
    /// Start `promptsecret -n <n>` on a pty, or `None` when `script` is
    /// not installed.
    fn start(n: u32) -> Option<Session> {
        let command = format!("exec '{}' -n {n}", env!("CARGO_BIN_EXE_promptsecret"));
        let spawned = Command::new("script")
            .args(["-qec", &command, "/dev/null"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let mut child = match spawned {
            Ok(child) => child,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipped: script(1) is not installed");
                return None;
            }
            Err(e) => panic!("spawn script: {e}"),
        };
        let stdin = child.stdin.take().expect("stdin");
        let mut stdout = child.stdout.take().expect("stdout");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stdout.read(&mut buf)
                && n > 0
                && tx.send(buf[..n].to_vec()).is_ok()
            {}
        });
        Some(Session {
            child,
            stdin,
            output: rx,
            seen: Vec::new(),
        })
    }

    /// Wait until the output holds `count` copies of `needle`.
    fn wait_for(&mut self, needle: &str, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while occurrences(&self.seen, needle.as_bytes()) < count {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.output.recv_timeout(left) {
                Ok(chunk) => self.seen.extend(chunk),
                Err(_) => panic!(
                    "no {count} of {needle:?} in the output: {:?}",
                    String::from_utf8_lossy(&self.seen)
                ),
            }
        }
    }

    /// Type a line at the terminal.
    fn type_line(&mut self, line: &str) {
        self.stdin
            .write_all(format!("{line}\n").as_bytes())
            .expect("type at the pty");
        self.stdin.flush().expect("flush");
    }

    /// Wait for the tool to exit and collect the rest of its output.
    fn finish(mut self) -> (ExitStatus, String) {
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = self.child.try_wait().expect("wait") {
                break status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                panic!(
                    "promptsecret kept running: {:?}",
                    String::from_utf8_lossy(&self.seen)
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        drop(self.stdin);
        while let Ok(chunk) = self.output.recv_timeout(Duration::from_secs(5)) {
            self.seen.extend(chunk);
        }
        (status, String::from_utf8_lossy(&self.seen).into_owned())
    }
}

/// How many times `needle` occurs in `haystack`.
fn occurrences(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

/// The process id and parent id of every process, with its command name.
fn processes() -> Vec<(u32, u32, String)> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc").expect("read /proc").flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse().ok()) else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        // "pid (comm) state ppid ...", where comm may hold spaces.
        let (Some(open), Some(close)) = (stat.find('('), stat.rfind(')')) else {
            continue;
        };
        let comm = stat[open + 1..close].to_string();
        let Some(ppid) = stat[close + 1..]
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
        else {
            continue;
        };
        found.push((pid, ppid, comm));
    }
    found
}

/// The promptsecret process running under `script` (not one of its own
/// short-lived forks for stty).
fn promptsecret_pid(script_pid: u32) -> u32 {
    let all = processes();
    let parent_of = |pid: u32| all.iter().find(|p| p.0 == pid).map(|p| p.1);
    let comm_of = |pid: u32| all.iter().find(|p| p.0 == pid).map(|p| p.2.as_str());
    let descends = |mut pid: u32| {
        while let Some(parent) = parent_of(pid) {
            if parent == script_pid {
                return true;
            }
            if parent <= 1 {
                return false;
            }
            pid = parent;
        }
        false
    };
    all.iter()
        .find(|(pid, ppid, comm)| {
            comm == "promptsecret" && comm_of(*ppid) != Some("promptsecret") && descends(*pid)
        })
        .map(|p| p.0)
        .expect("promptsecret runs under script")
}

/// Count the copies of `needle` in the readable memory of the process,
/// or `None` when this process may not read it.
fn copies_in_memory(pid: u32, needle: &[u8]) -> Option<usize> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    let mem = match std::fs::File::open(format!("/proc/{pid}/mem")) {
        Ok(mem) => mem,
        Err(e) => {
            eprintln!("skipped the memory scan: /proc/{pid}/mem: {e}");
            return None;
        }
    };
    let mut copies = 0;
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let (Some(range), Some(perms)) = (fields.next(), fields.next()) else {
            continue;
        };
        if !perms.starts_with('r') {
            continue;
        }
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
        else {
            continue;
        };
        let Ok(len) = usize::try_from(end - start) else {
            continue;
        };
        let mut region = vec![0u8; len];
        // Regions such as [vvar] refuse reads; they hold no secret.
        if mem.read_exact_at(&mut region, start).is_ok() {
            copies += occurrences(&region, needle);
        }
    }
    Some(copies)
}

/// A secret typed at the terminal comes back on stdout, and the tool
/// exits zero.
#[test]
fn promptsecret_reads_a_secret_from_a_terminal() {
    let Some(mut session) = Session::start(1) else {
        return;
    };
    session.wait_for("Secret: ", 1);
    session.type_line(SECRET);
    let (status, output) = session.finish();
    assert!(
        !output.contains("unable to read secret"),
        "the terminal must be usable: {output:?}"
    );
    assert!(status.success(), "{status:?}: {output:?}");
    let after_prompt = &output[output.find("Secret: ").expect("the prompt")..];
    assert!(
        after_prompt.contains(&format!("{SECRET}\r\n")),
        "the secret must reach stdout: {output:?}"
    );
}

/// Once a secret is written and zeroed, no copy of it stays in the
/// tool's memory while it waits for the next one.
#[test]
fn promptsecret_keeps_no_copy_of_a_written_secret() {
    let Some(mut session) = Session::start(2) else {
        return;
    };
    session.wait_for("Secret: ", 1);
    session.type_line(SECRET);
    // The second prompt follows the first secret's write and zeroing.
    session.wait_for("Secret: ", 2);
    // Let the second round settle into its read.
    std::thread::sleep(Duration::from_millis(300));

    let pid = promptsecret_pid(session.child.id());
    let copies = copies_in_memory(pid, SECRET.as_bytes());

    session.type_line("second");
    let (status, output) = session.finish();
    assert!(status.success(), "{status:?}: {output:?}");
    if let Some(copies) = copies {
        assert_eq!(
            copies, 0,
            "the written secret must leave no copy in the tool's memory"
        );
    }
}
