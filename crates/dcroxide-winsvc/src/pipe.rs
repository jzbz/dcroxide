// SPDX-License-Identifier: ISC
//! Adopting a pipe handle a parent process left open for the daemon:
//! dcrd's `os.NewFile` over the `--piperx` and `--pipetx` numbers
//! (`ipc.go:45`, `:74`), which on Windows name the anonymous-pipe
//! handles a parent such as Decrediton made inheritable.
//!
//! `os.NewFile` takes the number as it is.  It returns nil only for
//! `INVALID_HANDLE_VALUE`, and every read or write dcrd then makes fails
//! with `os.ErrInvalid` (`invalid argument`); any other number that
//! names no open handle fails at the first read or write instead, with
//! `ERROR_INVALID_HANDLE`.  Taking the number the same way in Rust,
//! with `OwnedHandle::from_raw_handle`, would be unsound for a number the
//! daemon does not own outright: one that names no open handle, or one
//! that names a handle something else in the process holds and would
//! then see closed under it.  [`adopt_inherited_handle`] therefore
//! duplicates the handle within the process (`DuplicateHandle`, same
//! access), as the Linux side of the daemon duplicates an inherited
//! descriptor with `pidfd_getfd`.  The kernel looks the number up, so
//! one that names no open handle fails there with the same
//! `ERROR_INVALID_HANDLE`, and the duplicate is a new handle to the same
//! pipe that nothing else in the process knows of, which the daemon
//! then owns.
//!
//! The inherited handle itself is left open.  What the parent sees
//! depends only on the daemon's writes and on the handles to the
//! parent's own ends, so the extra handle changes nothing for it: the
//! parent closing its end still ends `--piperx` with end-of-file, and the
//! `--pipetx` end stays open until the daemon exits, as dcrd's does.

use std::fs::File;
use std::io;

/// Take the inherited handle `handle` names as a file the daemon owns
/// (dcrd's `os.NewFile(fd, ...)` on Windows); see the module
/// documentation for why it is a duplicate.
///
/// `INVALID_HANDLE_VALUE`, and a number too wide to be a handle on this
/// target, fail with `InvalidInput` and Go's `os.ErrInvalid` text,
/// `invalid argument`.  A number that names no open handle fails with
/// the system's `ERROR_INVALID_HANDLE`.  Off Windows this always fails
/// with `Unsupported`: the daemon takes unix descriptors itself.
pub fn adopt_inherited_handle(handle: u64) -> io::Result<File> {
    imp::adopt(handle)
}

#[cfg(windows)]
mod imp {
    use std::fs::File;
    use std::io;
    use std::os::windows::io::{FromRawHandle, OwnedHandle};

    use windows_sys::Win32::Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, FALSE, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    /// Go's `os.ErrInvalid`, what every read or write on the nil file
    /// `os.NewFile` returns for `INVALID_HANDLE_VALUE` fails with.
    fn invalid_argument() -> io::Error {
        io::Error::new(io::ErrorKind::InvalidInput, "invalid argument")
    }

    pub(super) fn adopt(handle: u64) -> io::Result<File> {
        // A handle is a pointer-sized number, not a pointer, so it is
        // built without provenance.
        let source: HANDLE = match usize::try_from(handle) {
            Ok(raw) => std::ptr::without_provenance_mut(raw),
            Err(_) => return Err(invalid_argument()),
        };
        if source == INVALID_HANDLE_VALUE {
            return Err(invalid_argument());
        }

        let mut duplicate: HANDLE = std::ptr::null_mut();
        // SAFETY: `GetCurrentProcess` takes nothing and returns the
        // current-process pseudo-handle, which needs no closing.
        // `DuplicateHandle` takes `source` only as a number the kernel
        // looks up in this process's handle table, so a number that
        // names no open handle fails the call instead of reaching
        // memory, and it writes one handle through `&mut duplicate`, a
        // live local of the out-parameter's type; no other pointer is
        // passed.  Without `DUPLICATE_CLOSE_SOURCE` the call leaves
        // `source` open, so whoever owns it is unaffected.
        #[allow(unsafe_code)]
        let duplicated = unsafe {
            let process = GetCurrentProcess();
            DuplicateHandle(
                process,
                source,
                process,
                &mut duplicate,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS,
            )
        };
        if duplicated == FALSE {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: the call succeeded, so `duplicate` is an open handle
        // that it created in this process just now and that nothing else
        // in the process holds, so ownership is the daemon's to take and
        // closing it can close nothing another owner uses.  It names a
        // kernel object, the one `source` names, and `CloseHandle`, the
        // only cleanup `OwnedHandle` performs, releases a handle
        // `DuplicateHandle` made.
        #[allow(unsafe_code)]
        let owned = unsafe { OwnedHandle::from_raw_handle(duplicate) };
        Ok(File::from(owned))
    }
}

#[cfg(not(windows))]
mod imp {
    use std::fs::File;
    use std::io;

    /// Unix descriptors are taken by the daemon itself.
    pub(super) fn adopt(_handle: u64) -> io::Result<File> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "inherited handles are adopted only on Windows",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Off Windows the adoption is a stub.
    #[cfg(not(windows))]
    #[test]
    fn handles_are_adopted_only_on_windows() {
        let err = adopt_inherited_handle(3).expect_err("stub");
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[cfg(windows)]
    mod windows {
        use super::*;
        use std::io::{Read, Write};
        use std::os::windows::io::AsRawHandle;

        /// The number a parent passes for a handle.
        fn number(handle: &impl AsRawHandle) -> u64 {
            handle.as_raw_handle().addr() as u64
        }

        /// The read end of a pipe, taken by number, reads what the
        /// other end writes and then end-of-file once the writer closes
        /// (dcrd's `--piperx` reader over `os.NewFile`).
        #[test]
        fn an_adopted_read_end_reads_to_the_writers_close() {
            let (reader, mut writer) = std::io::pipe().expect("pipe");
            let mut adopted = adopt_inherited_handle(number(&reader)).expect("adopt");
            writer.write_all(b"control bytes").expect("write");
            drop(writer);
            let mut read = Vec::new();
            adopted.read_to_end(&mut read).expect("read to end-of-file");
            assert_eq!(read, b"control bytes");
            drop(reader);
        }

        /// The write end of a pipe, taken by number, delivers to the
        /// other end (dcrd's `--pipetx` writer over `os.NewFile`).
        #[test]
        fn an_adopted_write_end_reaches_the_reader() {
            let (mut reader, writer) = std::io::pipe().expect("pipe");
            let mut adopted = adopt_inherited_handle(number(&writer)).expect("adopt");
            adopted.write_all(b"lifetimeevent").expect("write");
            drop(adopted);
            drop(writer);
            let mut read = Vec::new();
            reader.read_to_end(&mut read).expect("read to end-of-file");
            assert_eq!(read, b"lifetimeevent");
        }

        /// The adopted file is a handle of its own: the inherited one
        /// keeps its owner, and closing either leaves the other working.
        #[test]
        fn the_adopted_handle_is_independent_of_the_inherited_one() {
            let (reader, mut writer) = std::io::pipe().expect("pipe");
            let mut adopted = adopt_inherited_handle(number(&reader)).expect("adopt");
            assert_ne!(number(&adopted), number(&reader));
            drop(reader);
            writer.write_all(b"x").expect("write");
            drop(writer);
            let mut read = Vec::new();
            adopted
                .read_to_end(&mut read)
                .expect("read after the original closed");
            assert_eq!(read, b"x");
        }

        /// `INVALID_HANDLE_VALUE` is the nil file of `os.NewFile`, whose
        /// reads and writes fail with `os.ErrInvalid`.
        #[test]
        fn the_invalid_handle_value_fails_as_go_s_nil_file() {
            let err = adopt_inherited_handle(u64::MAX).expect_err("invalid handle value");
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(err.to_string(), "invalid argument");
        }

        /// A number that names no open handle fails with
        /// `ERROR_INVALID_HANDLE`, as dcrd's first read or write on it
        /// does.  Handle values are multiples of four below 2^26, so this
        /// one can name nothing.
        #[test]
        fn a_number_naming_no_handle_fails_as_the_first_read_would() {
            let err = adopt_inherited_handle(0x0fff_fff0).expect_err("no such handle");
            assert_eq!(err.raw_os_error(), Some(6));
        }
    }
}
