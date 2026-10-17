// SPDX-License-Identifier: ISC
//! What the process holds in memory at one instant, read from Linux's
//! `/proc/self` for a flush observer ([`crate::FlushObservation`]).
//!
//! A flush whose commit runs on a thread of its own keeps the captured
//! overlay layers and redb's write transaction alive while other threads
//! go on allocating, and that commit, and the frees that follow it, are
//! made by a thread that did not allocate what it frees.  The overlay's
//! own byte count cannot say what that does to the process: the allocator
//! decides.  These readings, taken around each flush, say when the
//! process's resident memory rose and by how much.  They do not say how
//! much of it the allocator holds free: see [`ArenaMaps`].

/// The process's memory at one instant.
///
/// From `/proc/self/status`, and for [`Self::arenas`] from
/// `/proc/self/maps`.  Every figure is in bytes but the thread count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProcessMemory {
    /// Resident memory (`VmRSS`).
    pub resident: u64,
    /// The most resident memory has been since the process started
    /// (`VmHWM`).
    pub peak_resident: u64,
    /// The part of [`Self::resident`] that is anonymous memory, which is
    /// where the heap is (`RssAnon`).
    pub anonymous: u64,
    /// Threads alive (`Threads`).
    pub threads: u64,
    /// The heap as the allocator has mapped it, when it was looked at:
    /// see [`ArenaMaps`].  The mappings are read less often than the
    /// counters above, since listing them costs more.
    pub arenas: Option<ArenaMaps>,
}

/// The heap mappings of a process that uses the GNU C library's
/// allocator, counted from `/proc/self/maps`.
///
/// That allocator gives each thread an arena of its own while there are
/// arenas to give, and a chunk freed by any thread goes back to the arena
/// it was allocated from: memory freed in one arena serves no thread that
/// allocates from another.  Resident memory can therefore rise with the
/// number of arenas in use while the bytes the program holds stay the
/// same.  An arena other than the first grows in heaps that are each
/// reserved as [`ARENA_HEAP_ALIGN`] bytes at an address that is a
/// multiple of it, of which only the part in use is readable and
/// writable (glibc `malloc/arena.c`, `HEAP_MAX_SIZE` and `new_heap`).
/// The first arena grows the program break, the `[heap]` mapping.
///
/// What is counted is mappings, by that address rule alone: neither
/// arenas nor heaps.  An arena has as many heaps as it has grown by, so
/// the count rises with the bytes held in one arena as it does with the
/// number of arenas.  Neighbouring heaps the kernel merged into one
/// mapping count once.  A heap the kernel merged with a mapping of
/// another kind just below it starts off the boundary and is not counted
/// at all, and a large allocation mapped on its own that happens to start
/// on such a boundary is.
///
/// The bytes are what those mappings span, in use or freed and kept
/// alike.  In a process whose memory is mostly heap they follow its
/// anonymous resident memory: they say where that memory lies, not how
/// much of it the program still holds.  Nothing here reads an arena's
/// bytes in use against its free ones, so these figures cannot tell
/// memory that one arena keeps free while another takes more from the
/// kernel from memory that is live.  Under another allocator they mean
/// nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ArenaMaps {
    /// Private anonymous read-write mappings that start on an
    /// [`ARENA_HEAP_ALIGN`] boundary.
    pub mappings: u64,
    /// The bytes those mappings span: what the arenas other than the
    /// first have mapped for reading and writing, in use or freed and
    /// kept.
    pub bytes: u64,
    /// The bytes of the `[heap]` mapping, the first arena.
    pub program_break: u64,
}

/// The size and alignment of one heap of a thread arena on a 64-bit
/// target (glibc `HEAP_MAX_SIZE`, twice `DEFAULT_MMAP_THRESHOLD_MAX`).
pub const ARENA_HEAP_ALIGN: u64 = 64 * 1024 * 1024;

impl ProcessMemory {
    /// Read the calling process's memory, with the heap mappings when
    /// `with_arenas` is set.  `None` off Linux, and where
    /// `/proc/self/status` cannot be read or lacks a counter.
    ///
    /// The files are read through the one reader every `/proc` counter
    /// of a flush uses, so the tests that count what a flush reads see
    /// these too.
    pub fn read(with_arenas: bool) -> Option<ProcessMemory> {
        #[cfg(target_os = "linux")]
        {
            let text = |path: &str| {
                crate::dbcache::read_proc(path).and_then(|bytes| String::from_utf8(bytes).ok())
            };
            let status = text("/proc/self/status")?;
            let mut memory = parse_status(&status)?;
            if with_arenas {
                memory.arenas = text("/proc/self/maps").map(|maps| parse_maps(&maps));
            }
            Some(memory)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = with_arenas;
            None
        }
    }

    /// Render as one JSON object, with `null` for heap mappings that were
    /// not read.
    pub fn to_json(&self) -> String {
        let arenas = |pick: fn(&ArenaMaps) -> u64| {
            self.arenas
                .as_ref()
                .map_or_else(|| "null".to_string(), |a| pick(a).to_string())
        };
        format!(
            "{{\"rss\":{},\"hwm\":{},\"anon\":{},\"threads\":{},\"arena_maps\":{},\
             \"arena_bytes\":{},\"brk_bytes\":{}}}",
            self.resident,
            self.peak_resident,
            self.anonymous,
            self.threads,
            arenas(|a| a.mappings),
            arenas(|a| a.bytes),
            arenas(|a| a.program_break),
        )
    }
}

/// The counters of a `/proc/<pid>/status`; `None` when one is missing.
/// The kernel reports the sizes in kibibytes (`fs/proc/task_mmu.c`,
/// `task_mem`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_status(status: &str) -> Option<ProcessMemory> {
    let field = |name: &str| -> Option<u64> {
        status.lines().find_map(|line| {
            line.strip_prefix(name)?
                .strip_prefix(':')?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
    };
    let kib = |name: &str| field(name).map(|v: u64| v.saturating_mul(1024));
    Some(ProcessMemory {
        resident: kib("VmRSS")?,
        peak_resident: kib("VmHWM")?,
        anonymous: kib("RssAnon")?,
        threads: field("Threads")?,
        arenas: None,
    })
}

/// The heap mappings in a `/proc/<pid>/maps`.  Each line is
/// `start-end perms offset dev inode [path]`, the addresses in
/// hexadecimal; a line that does not read so is skipped.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_maps(maps: &str) -> ArenaMaps {
    let mut arenas = ArenaMaps::default();
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let (Some(range), Some(perms)) = (fields.next(), fields.next()) else {
            continue;
        };
        let path = fields.nth(3);
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
        else {
            continue;
        };
        let len = end.saturating_sub(start);
        match path {
            Some("[heap]") => arenas.program_break = arenas.program_break.saturating_add(len),
            None if perms == "rw-p" && start.is_multiple_of(ARENA_HEAP_ALIGN) => {
                arenas.mappings = arenas.mappings.saturating_add(1);
                arenas.bytes = arenas.bytes.saturating_add(len);
            }
            _ => {}
        }
    }
    arenas
}

#[cfg(test)]
mod tests {
    use super::{ARENA_HEAP_ALIGN, ArenaMaps, ProcessMemory, parse_maps, parse_status};

    /// The counters are found by name wherever they stand, and scaled from
    /// the kernel's kibibytes; a status without one of them reads as
    /// nothing rather than as zeros.
    #[test]
    fn a_status_is_read_by_name_and_scaled_to_bytes() {
        let status = "Name:\tdcroxide\nVmPeak:\t 9000000 kB\nVmHWM:\t 4288512 kB\n\
                      VmRSS:\t 3284992 kB\nRssAnon:\t 3200000 kB\nRssFile:\t   84992 kB\n\
                      Threads:\t41\n";
        assert_eq!(
            parse_status(status),
            Some(ProcessMemory {
                resident: 3_284_992 * 1024,
                peak_resident: 4_288_512 * 1024,
                anonymous: 3_200_000 * 1024,
                threads: 41,
                arenas: None,
            })
        );
        assert_eq!(
            parse_status("VmRSS:\t 1 kB\nVmHWM:\t 1 kB\nThreads:\t1\n"),
            None
        );
        // `VmRSS` is not found in a longer name.
        assert_eq!(
            parse_status("VmRSSx:\t 1 kB\nVmHWM:\t 1 kB\nRssAnon:\t 1 kB\nThreads:\t1\n"),
            None
        );
    }

    /// A thread arena's heap is the anonymous read-write mapping on a
    /// 64 MiB boundary; its unreadable remainder, a file's mapping, a
    /// stack and an anonymous mapping elsewhere are not, and the program
    /// break is counted apart.  A heap that was merged with an anonymous
    /// mapping just below it is one mapping that starts off the boundary,
    /// and is missed.
    #[test]
    fn arena_heaps_are_told_from_other_mappings_by_where_they_start() {
        let maps = "\
55d0a6a00000-55d0a6c00000 r-xp 00000000 fe:01 1234                       /usr/bin/dcroxide
55d0a8000000-55d0a8400000 rw-p 00000000 00:00 0                          [heap]
7f1e40000000-7f1e41234000 rw-p 00000000 00:00 0
7f1e41234000-7f1e44000000 ---p 00000000 00:00 0
7f1e48000000-7f1e50000000 rw-p 00000000 00:00 0
7f1e50100000-7f1e50200000 rw-p 00000000 00:00 0
7f1e54000000-7f1e54021000 rw-s 00000000 00:01 77                         /dev/shm/x
7f1e58000000-7f1e58800000 rw-p 00000000 00:00 0                          [stack]
7f1e5bf00000-7f1e5c400000 rw-p 00000000 00:00 0
not a mapping line
";
        assert_eq!(0x7f1e_4000_0000 % ARENA_HEAP_ALIGN, 0);
        assert_eq!(0x7f1e_5c00_0000 % ARENA_HEAP_ALIGN, 0);
        assert_eq!(
            parse_maps(maps),
            ArenaMaps {
                mappings: 2,
                bytes: 0x0123_4000 + 0x0800_0000,
                program_break: 0x0040_0000,
            }
        );
    }

    /// On Linux the calling process can be read, with the mappings only
    /// when they are asked for, and the reading is rendered whole.
    #[cfg(target_os = "linux")]
    #[test]
    fn this_process_reads_itself() {
        let quick = ProcessMemory::read(false).expect("a status");
        assert!(quick.resident > 0 && quick.peak_resident >= quick.resident / 2);
        assert!(quick.threads >= 1);
        assert_eq!(quick.arenas, None);
        assert!(
            quick
                .to_json()
                .ends_with(r#""arena_maps":null,"arena_bytes":null,"brk_bytes":null}"#)
        );
        let full = ProcessMemory::read(true).expect("a status");
        assert!(full.arenas.is_some());
        assert!(full.to_json().starts_with(r#"{"rss":"#));
        assert!(!full.to_json().contains("null"));
    }
}
