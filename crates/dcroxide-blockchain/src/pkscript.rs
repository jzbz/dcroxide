// SPDX-License-Identifier: ISC
//! The public key script of a UTXO entry and of a spent output, held
//! in place when it is short.
//!
//! The standard payment scripts are short, 23 to 26 bytes:
//! pay-to-pubkey-hash takes 25 bytes, pay-to-script-hash 23, and the
//! stake-tagged forms of either one byte more.  Held as a `Vec<u8>`,
//! a script is a heap allocation when its output is created, another
//! for every copy of the entry (out of the UTXO cache into a block's
//! view, into the spend journal), and a free for each of them.
//! [`PkScript`] keeps a script of up to [`PkScript::INLINE_CAPACITY`]
//! bytes inside itself and puts only a longer one on the heap, so
//! those copies of a standard script are plain byte copies.
//!
//! Which form holds a script is visible only to the crate's tests: a
//! [`PkScript`] reads, compares and prints as the script's bytes, and
//! nothing serializes it but those bytes, so the stored formats, the
//! cache's size accounting (which counts script bytes, as dcrd's does)
//! and every consensus result are the same as with a `Vec<u8>`.  dcrd
//! holds the script as a byte slice.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::ops::Deref;

/// The longest script held in place.  Thirty bytes, with the length
/// and the tag, fill 32 bytes on 64-bit targets: the least size, in
/// steps of the 8 bytes the heap form aligns to, that holds the 26-byte
/// stake-tagged pay-to-pubkey-hash script, and 8 bytes more than the
/// `Vec<u8>` it replaces.
const INLINE_CAPACITY: usize = 30;

/// Where the script's bytes are.
///
/// A script is held in place exactly when it fits, so each script has
/// one representation.
#[derive(Clone)]
enum Repr {
    /// A script of at most [`INLINE_CAPACITY`] bytes, in the first
    /// `len` bytes of `bytes`; the bytes after them are zero.
    Inline {
        len: u8,
        bytes: [u8; INLINE_CAPACITY],
    },
    /// A script longer than [`INLINE_CAPACITY`] bytes.
    Heap(Box<[u8]>),
}

/// A public key script as a UTXO entry or a spent output holds it: in
/// place up to [`PkScript::INLINE_CAPACITY`] bytes, on the heap beyond.
///
/// It dereferences to the script's bytes, and equality and `Debug` are
/// those of the bytes.
#[derive(Clone)]
pub struct PkScript(Repr);

impl PkScript {
    /// The longest script held without a heap allocation.
    pub const INLINE_CAPACITY: usize = INLINE_CAPACITY;

    /// The empty script.
    pub const fn new() -> PkScript {
        PkScript(Repr::Inline {
            len: 0,
            bytes: [0; INLINE_CAPACITY],
        })
    }

    /// A script of `len` zero bytes, for a caller that writes the
    /// bytes in place (as a decompressed script is built).
    pub(crate) fn zeroed(len: usize) -> PkScript {
        match u8::try_from(len) {
            Ok(short) if len <= INLINE_CAPACITY => PkScript(Repr::Inline {
                len: short,
                bytes: [0; INLINE_CAPACITY],
            }),
            _ => PkScript(Repr::Heap(alloc::vec![0u8; len].into_boxed_slice())),
        }
    }

    /// The script's bytes.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        match &self.0 {
            Repr::Inline { len, bytes } => &bytes[..usize::from(*len)],
            Repr::Heap(bytes) => bytes,
        }
    }

    /// The script's bytes, to write in place; the length is fixed.
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        match &mut self.0 {
            Repr::Inline { len, bytes } => &mut bytes[..usize::from(*len)],
            Repr::Heap(bytes) => bytes,
        }
    }

    /// Whether the script is held in place rather than on the heap.
    #[cfg(test)]
    pub(crate) fn is_inline(&self) -> bool {
        matches!(self.0, Repr::Inline { .. })
    }

    /// The script as a vector; a script on the heap moves into it
    /// without a copy.
    pub fn into_vec(self) -> Vec<u8> {
        match self.0 {
            Repr::Inline { .. } => self.as_slice().to_vec(),
            Repr::Heap(bytes) => bytes.into_vec(),
        }
    }
}

impl Default for PkScript {
    fn default() -> PkScript {
        PkScript::new()
    }
}

impl From<&[u8]> for PkScript {
    fn from(script: &[u8]) -> PkScript {
        match u8::try_from(script.len()) {
            Ok(len) if script.len() <= INLINE_CAPACITY => {
                let mut bytes = [0; INLINE_CAPACITY];
                bytes[..script.len()].copy_from_slice(script);
                PkScript(Repr::Inline { len, bytes })
            }
            _ => PkScript(Repr::Heap(Box::from(script))),
        }
    }
}

impl From<Vec<u8>> for PkScript {
    /// A short script is copied in place and the vector freed; a long
    /// one keeps the vector's allocation (shrunk to fit, as
    /// [`Vec::into_boxed_slice`] does).
    fn from(script: Vec<u8>) -> PkScript {
        if script.len() <= INLINE_CAPACITY {
            PkScript::from(script.as_slice())
        } else {
            PkScript(Repr::Heap(script.into_boxed_slice()))
        }
    }
}

impl From<PkScript> for Vec<u8> {
    fn from(script: PkScript) -> Vec<u8> {
        script.into_vec()
    }
}

impl Deref for PkScript {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsRef<[u8]> for PkScript {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl PartialEq for PkScript {
    fn eq(&self, other: &PkScript) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for PkScript {}

impl PartialEq<[u8]> for PkScript {
    fn eq(&self, other: &[u8]) -> bool {
        self.as_slice() == other
    }
}

impl PartialEq<Vec<u8>> for PkScript {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl fmt::Debug for PkScript {
    /// Formats as the script's bytes do, so a value prints as the
    /// `Vec<u8>` it replaces did.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_slice(), f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::vec;

    /// The script forms the module documentation names fit in place,
    /// and the type is 32 bytes on 64-bit targets.
    #[test]
    fn the_standard_scripts_fit_in_place() {
        // Pay-to-pubkey-hash and its stake-tagged form, and the same
        // for pay-to-script-hash.
        let p2pkh = [&[0x76, 0xa9, 0x14][..], &[0x11; 20], &[0x88, 0xac]].concat();
        let p2sh = [&[0xa9, 0x14][..], &[0x22; 20], &[0x87]].concat();
        for script in [
            p2pkh.clone(),
            [&[0xba][..], &p2pkh].concat(),
            p2sh.clone(),
            [&[0xbb][..], &p2sh].concat(),
        ] {
            assert!(PkScript::from(script.as_slice()).is_inline(), "{script:x?}");
        }
        #[cfg(target_pointer_width = "64")]
        assert_eq!(core::mem::size_of::<PkScript>(), 32);
    }

    /// Every length reads back the bytes it was made from, through
    /// each constructor and each way out, and is held in place exactly
    /// up to the capacity.
    #[test]
    fn every_length_round_trips_in_its_one_form() {
        for len in 0..=80usize {
            let script: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37) | 1).collect();
            let from_slice = PkScript::from(script.as_slice());
            let from_vec = PkScript::from(script.clone());
            let mut written = PkScript::zeroed(len);
            assert!(written.as_slice().iter().all(|&b| b == 0));
            written.as_mut_slice().copy_from_slice(&script);
            for held in [&from_slice, &from_vec, &written] {
                assert_eq!(held.as_slice(), script.as_slice(), "len {len}");
                assert_eq!(held.len(), len);
                assert_eq!(
                    held.is_inline(),
                    len <= PkScript::INLINE_CAPACITY,
                    "len {len}"
                );
                assert_eq!(*held, script);
                assert!(*held == *script.as_slice());
                assert_eq!(AsRef::<[u8]>::as_ref(held), script.as_slice());
                assert_eq!(held.clone().into_vec(), script);
                assert_eq!(Vec::from(held.clone()), script);
                assert_eq!(format!("{held:?}"), format!("{script:?}"));
            }
            assert_eq!(from_slice, from_vec);
            assert_eq!(from_vec, written);
        }
    }

    /// Equality is that of the bytes: scripts that differ in one byte
    /// or in length differ, whichever form holds them, and so do a
    /// script and a vector or a slice of other bytes (the dcrd vectors
    /// compare a spent output's script with a vector).
    #[test]
    fn equality_is_the_bytes() {
        let short = PkScript::from(&[1u8, 2, 3][..]);
        assert_eq!(short, PkScript::from(vec![1u8, 2, 3]));
        assert_ne!(short, PkScript::from(&[1u8, 2, 4][..]));
        assert_ne!(short, PkScript::from(&[1u8, 2][..]));
        assert_ne!(short, PkScript::from(&[1u8, 2, 3, 0][..]));
        assert_eq!(short, vec![1u8, 2, 3]);
        assert_ne!(short, vec![1u8, 2, 4]);
        assert_ne!(short, vec![1u8, 2]);
        assert!(short == [1u8, 2, 3][..]);
        assert!(short != [1u8, 2, 4][..]);
        assert!(short != [1u8, 2][..]);
        assert_eq!(PkScript::new(), PkScript::default());
        assert!(PkScript::new().is_empty());
        let long = vec![9u8; 40];
        let mut other = long.clone();
        other[39] = 8;
        let held = PkScript::from(long.clone());
        assert_eq!(held, PkScript::from(long.as_slice()));
        assert_ne!(held, other);
        assert!(held != *other.as_slice());
        assert_ne!(held, PkScript::from(other));
    }
}
