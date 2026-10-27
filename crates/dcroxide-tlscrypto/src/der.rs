// SPDX-License-Identifier: ISC
//! A DER reader with the rules of Go's `encoding/asn1`, as `asn1.Unmarshal`
//! applies them to the private-key structures of `crypto/x509`
//! (`pkcs1.go`, `pkcs8.go`, `sec1.go`), for [`crate::keys`].
//!
//! Go reads a key field by field into a struct, and is lenient in a few
//! places a key written by another tool can differ from one Go writes.
//! This reader is lenient in the same places and no others:
//!
//! * A SEQUENCE read into a struct may hold bytes after its last field,
//!   which are never looked at (`encoding/asn1/asn1.go:985-988`), and
//!   bytes after a top-level element are handed back to the caller
//!   (`:1163-1173`), which for PKCS#8 and SEC 1 ignores them.
//! * An optional field is absent when nothing is left, or when the next
//!   element carries another tag, which is then left for the field after
//!   it (`:714-719`, `:880-890`).  The next element's identifier and
//!   length must still read, or the whole structure fails.
//! * An optional field in an explicit tag (SEC 1's `[0]` and `[1]`) is
//!   absent too when the wrapper is primitive, or is there but the element
//!   inside it has another tag, and the wrapper's own length is never
//!   checked against that element (`:780-815`).  Where such a field is
//!   read, an element whose identifier and length end the SEQUENCE fails
//!   it, whatever its tag, and so does an empty wrapper (`:785-787`,
//!   `:797-800`).
//!
//! Everything else is DER as Go reads it: a tag number in the high-tag
//! form only from 31 up and written minimally (`:568-580`); a definite
//! length, in the long form only from 128 up, without leading zero
//! octets and below 2^31 (`:586-624`); INTEGERs minimally encoded
//! (`:79-92`); and each OBJECT IDENTIFIER and BIT STRING well formed
//! (`:196-212`, `:250-331`).  Every length is checked against the bytes
//! before it is used, so no input reaches past its end.

/// The class, form and number an element's identifier must carry for a
/// field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Tag {
    /// The class, from the identifier's top two bits: 0 universal, 2
    /// context-specific.
    class: u8,
    /// Whether the element is constructed.
    constructed: bool,
    /// The tag number.
    number: u32,
}

impl Tag {
    /// A universal tag.
    const fn universal(constructed: bool, number: u32) -> Tag {
        Tag {
            class: 0,
            constructed,
            number,
        }
    }
}

/// A SEQUENCE, which Go reads into a struct or a slice.
pub(crate) const SEQUENCE: Tag = Tag::universal(true, 16);
/// An INTEGER, read into an `int` or a `*big.Int`.
pub(crate) const INTEGER: Tag = Tag::universal(false, 2);
/// A BIT STRING, read into an `asn1.BitString`.
pub(crate) const BIT_STRING: Tag = Tag::universal(false, 3);
/// An OCTET STRING, read into a `[]byte`.
pub(crate) const OCTET_STRING: Tag = Tag::universal(false, 4);
/// An OBJECT IDENTIFIER, read into an `asn1.ObjectIdentifier`.
pub(crate) const OBJECT_IDENTIFIER: Tag = Tag::universal(false, 6);

/// The class of an explicit tag.
const CONTEXT_SPECIFIC: u8 = 2;

/// The structure being read does not read as Go reads it: where
/// `asn1.Unmarshal` returns an error.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Malformed;

/// An element's identifier and length, as Go's `parseTagAndLength`
/// reads them, and how many bytes they took.
struct Header {
    /// The identifier's class, form and number.
    tag: Tag,
    /// The content's length.
    len: usize,
    /// The identifier's and length's own length.
    size: usize,
}

/// Go's `parseTagAndLength` (`encoding/asn1/asn1.go:554-627`) at the
/// start of `data`.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "a header is at most a few bytes, and the length is held below 2^31 before each shift"
)]
fn header(data: &[u8]) -> Result<Header, Malformed> {
    let (&identifier, rest) = data.split_first().ok_or(Malformed)?;
    let mut number = u32::from(identifier & 0x1f);
    let mut rest = rest;
    let mut size = 1;
    if number == 0x1f {
        // The high-tag form, used only for numbers from 31 up.
        let (value, used) = base128(rest)?;
        if value < 0x1f {
            return Err(Malformed);
        }
        number = value;
        rest = rest.get(used..).ok_or(Malformed)?;
        size += used;
    }
    let (&first, mut rest) = rest.split_first().ok_or(Malformed)?;
    size += 1;
    let len = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        // The long form: no indefinite length, no leading zero octet, a
        // value below 2^31 and at least 128, as Go checks it octet by
        // octet.
        let count = usize::from(first & 0x7f);
        if count == 0 {
            return Err(Malformed);
        }
        let mut len = 0usize;
        for _ in 0..count {
            let (&octet, tail) = rest.split_first().ok_or(Malformed)?;
            rest = tail;
            if len >= 1 << 23 {
                return Err(Malformed);
            }
            len = (len << 8) | usize::from(octet);
            if len == 0 {
                return Err(Malformed);
            }
        }
        if len < 0x80 {
            return Err(Malformed);
        }
        size += count;
        len
    };
    Ok(Header {
        tag: Tag {
            class: identifier >> 6,
            constructed: identifier & 0x20 != 0,
            number,
        },
        len,
        size,
    })
}

/// Go's `parseBase128Int` (`encoding/asn1/asn1.go:298-331`): the value of
/// the base-128 number at the start of `data` and its length in bytes.
/// At most five groups, the first not `0x80`, the value at most
/// `i32::MAX`, and a last group that ends it.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "at most five seven-bit groups are shifted into a u64"
)]
fn base128(data: &[u8]) -> Result<(u32, usize), Malformed> {
    let mut value = 0u64;
    for (index, &group) in data.iter().enumerate() {
        if index == 5 || (index == 0 && group == 0x80) {
            return Err(Malformed);
        }
        value = (value << 7) | u64::from(group & 0x7f);
        if group & 0x80 == 0 {
            return match u32::try_from(value) {
                Ok(value) if value <= i32::MAX.unsigned_abs() => Ok((value, index + 1)),
                _ => Err(Malformed),
            };
        }
    }
    Err(Malformed)
}

/// An element read for a field: its content, and the bytes after it.
struct Element<'a> {
    /// The element's content.
    content: &'a [u8],
    /// What follows the element.
    after: &'a [u8],
}

/// The fields of one of Go's structures, read in order from a
/// SEQUENCE's content, or the one element of a top-level `Unmarshal`.
pub(crate) struct Reader<'a> {
    /// What is not read yet.
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    /// A reader over `data`.
    pub(crate) fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data }
    }

    /// What is not read yet: after a top-level element, what Go's
    /// `Unmarshal` returns as `rest`.
    pub(crate) fn rest(&self) -> &'a [u8] {
        self.data
    }

    /// The next element's header, and its content when it carries `tag`:
    /// `Ok(None)` for another tag, and `Malformed` for an element whose
    /// header does not read or, carrying `tag`, whose content runs past
    /// the end (Go's "data truncated").
    fn next(&self, tag: Tag) -> Result<Option<Element<'a>>, Malformed> {
        let header = header(self.data)?;
        if header.tag != tag {
            return Ok(None);
        }
        let body = self.data.get(header.size..).ok_or(Malformed)?;
        let (content, after) = body.split_at_checked(header.len).ok_or(Malformed)?;
        Ok(Some(Element { content, after }))
    }

    /// A field Go's struct requires, of `tag`: the next element's content.
    /// Nothing left, or another tag, is `Malformed` (Go's "sequence
    /// truncated" and "tags don't match").
    pub(crate) fn field(&mut self, tag: Tag) -> Result<&'a [u8], Malformed> {
        match self.optional(tag)? {
            Some(content) => Ok(content),
            None => Err(Malformed),
        }
    }

    /// An `optional` field of `tag`: the next element's content, or
    /// `None` when nothing is left or the next element carries another
    /// tag, which is then left unread.
    pub(crate) fn optional(&mut self, tag: Tag) -> Result<Option<&'a [u8]>, Malformed> {
        if self.data.is_empty() {
            return Ok(None);
        }
        let Some(element) = self.next(tag)? else {
            return Ok(None);
        };
        self.data = element.after;
        Ok(Some(element.content))
    }

    /// An `optional` field of Go's `RawValue` type, which takes any
    /// element: the next element whole, header included (`FullBytes`),
    /// or `None` when nothing is left.
    pub(crate) fn optional_any(&mut self) -> Result<Option<&'a [u8]>, Malformed> {
        if self.data.is_empty() {
            return Ok(None);
        }
        let header = header(self.data)?;
        let end = header.size.checked_add(header.len).ok_or(Malformed)?;
        let (element, after) = self.data.split_at_checked(end).ok_or(Malformed)?;
        self.data = after;
        Ok(Some(element))
    }

    /// An `optional,explicit,tag:number` field of `tag`, as Go's
    /// `parseField` reads one (`encoding/asn1/asn1.go:780-815`): the
    /// content of the element inside the wrapper.
    ///
    /// The wrapper is the next element's header when it is
    /// context-specific, numbered `number`, and constructed or empty.
    /// When the next element is not such a wrapper, or the element inside
    /// it carries another tag, the field is absent and both are left
    /// unread.  A next header that ends the input, or a wrapper that is
    /// empty, is `Malformed`, as is an inner element whose header does not
    /// read or whose content runs past the end.  The element inside is
    /// read from the bytes after the wrapper's header, whatever length the
    /// wrapper gives.
    pub(crate) fn optional_explicit(
        &mut self,
        number: u32,
        tag: Tag,
    ) -> Result<Option<&'a [u8]>, Malformed> {
        if self.data.is_empty() {
            return Ok(None);
        }
        let wrapper = header(self.data)?;
        let inner = self.data.get(wrapper.size..).ok_or(Malformed)?;
        if inner.is_empty() {
            return Err(Malformed);
        }
        let is_wrapper = wrapper.tag.class == CONTEXT_SPECIFIC
            && wrapper.tag.number == number
            && (wrapper.len == 0 || wrapper.tag.constructed);
        if !is_wrapper {
            return Ok(None);
        }
        if wrapper.len == 0 {
            return Err(Malformed);
        }
        let inner = Reader::new(inner);
        let Some(element) = inner.next(tag)? else {
            return Ok(None);
        };
        self.data = element.after;
        Ok(Some(element.content))
    }
}

/// Go's `checkInteger` (`encoding/asn1/asn1.go:79-92`): whether an
/// INTEGER's content is DER's, at least one byte and no byte more than
/// its sign needs.
pub(crate) fn integer_ok(content: &[u8]) -> bool {
    match content {
        [] => false,
        [0x00, next, ..] => next & 0x80 != 0,
        [0xff, next, ..] => next & 0x80 == 0,
        _ => true,
    }
}

/// Go's `parseInt64` (`encoding/asn1/asn1.go:94-115`), which an `int`
/// field takes on a 64-bit platform: the value of an INTEGER of at most
/// eight bytes.
pub(crate) fn int64(content: &[u8]) -> Result<i64, Malformed> {
    if !integer_ok(content) {
        return Err(Malformed);
    }
    let negative = content.first().is_some_and(|first| first & 0x80 != 0);
    let mut bytes = [if negative { 0xff } else { 0x00 }; 8];
    let start = bytes.len().checked_sub(content.len()).ok_or(Malformed)?;
    bytes
        .get_mut(start..)
        .ok_or(Malformed)?
        .copy_from_slice(content);
    Ok(i64::from_be_bytes(bytes))
}

/// Go's `parseObjectIdentifier` (`encoding/asn1/asn1.go:250-286`):
/// whether an OBJECT IDENTIFIER's content is at least one byte of
/// base-128 numbers Go reads.  Each number has one encoding Go reads, so
/// two identifiers that read are equal exactly when their bytes are.
pub(crate) fn object_identifier_ok(content: &[u8]) -> bool {
    let mut rest = content;
    if rest.is_empty() {
        return false;
    }
    while !rest.is_empty() {
        match base128(rest).ok().and_then(|(_, used)| rest.get(used..)) {
            Some(tail) => rest = tail,
            None => return false,
        }
    }
    true
}

/// Go's `parseBitString` (`encoding/asn1/asn1.go:196-212`): whether a BIT
/// STRING's content reads: a count of unused bits, at most seven and none
/// in a string with no bits, then the bits, whose unused ones are zero.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "a shift of at most seven, checked first"
)]
pub(crate) fn bit_string_ok(content: &[u8]) -> bool {
    let Some((&unused, bits)) = content.split_first() else {
        return false;
    };
    unused <= 7
        && (unused == 0 || !bits.is_empty())
        && bits
            .last()
            .is_none_or(|last| last & ((1u8 << unused) - 1) == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header's tag, length and size as the reader takes them.
    fn read(data: &[u8]) -> Option<(Tag, usize, usize)> {
        header(data)
            .ok()
            .map(|header| (header.tag, header.len, header.size))
    }

    /// Lengths in the short form, and in the long form only as DER and
    /// Go write them: no indefinite length, no leading zero octet, nothing
    /// under 128, nothing from 2^31 up.  A header that stops short is
    /// refused, and the length is not held to the bytes that follow.
    #[test]
    fn a_length_reads_as_go_reads_it() {
        assert_eq!(read(&[0x04, 0x00]), Some((OCTET_STRING, 0, 2)));
        assert_eq!(read(&[0x04, 0x7f]), Some((OCTET_STRING, 127, 2)));
        assert_eq!(read(&[0x04, 0x81, 0x80]), Some((OCTET_STRING, 128, 3)));
        assert_eq!(
            read(&[0x04, 0x84, 0x7f, 0xff, 0xff, 0xff]),
            Some((OCTET_STRING, 0x7fff_ffff, 6))
        );
        assert_eq!(
            read(&[0x04, 0x82, 0x01, 0x00]),
            Some((OCTET_STRING, 256, 4))
        );
        for refused in [
            &[0x04][..],
            &[0x04, 0x80],
            &[0x04, 0x81],
            &[0x04, 0x81, 0x7f],
            &[0x04, 0x82, 0x00, 0x80],
            &[0x04, 0x84, 0x80, 0x00, 0x00, 0x00],
            &[0x04, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00],
            &[],
        ] {
            assert_eq!(read(refused), None, "{refused:02x?}");
        }
    }

    /// Tag numbers: the low form up to 30, the high form only from 31 up,
    /// in base 128 Go reads; the class and the constructed bit kept.
    #[test]
    fn a_tag_reads_as_go_reads_it() {
        let context = |constructed, number| Tag {
            class: CONTEXT_SPECIFIC,
            constructed,
            number,
        };
        assert_eq!(read(&[0xa0, 0x00]).map(|r| r.0), Some(context(true, 0)));
        assert_eq!(read(&[0x81, 0x00]).map(|r| r.0), Some(context(false, 1)));
        assert_eq!(read(&[0x30, 0x00]).map(|r| r.0), Some(SEQUENCE));
        assert_eq!(read(&[0x9f, 0x1f, 0x00]), Some((context(false, 31), 0, 3)));
        assert_eq!(
            read(&[0xbf, 0x81, 0x00, 0x00]),
            Some((context(true, 128), 0, 4))
        );
        for refused in [
            &[0x9f, 0x1e, 0x00][..],
            &[0x9f, 0x80, 0x1f, 0x00],
            &[0x9f, 0x81],
            &[0x9f, 0x88, 0x80, 0x80, 0x80, 0x00, 0x00],
            &[0x9f],
        ] {
            assert_eq!(read(refused), None, "{refused:02x?}");
        }
    }

    /// Go's integer rules: minimal, not empty, and eight bytes at most for
    /// a 64-bit Go's `int`, with the sign extended.
    #[test]
    fn integers_read_as_go_reads_them() {
        assert!(integer_ok(&[0x00]));
        assert!(integer_ok(&[0x00, 0x80]));
        assert!(integer_ok(&[0xff, 0x7f]));
        assert!(!integer_ok(&[]));
        assert!(!integer_ok(&[0x00, 0x7f]));
        assert!(!integer_ok(&[0xff, 0x80]));
        assert_eq!(int64(&[0x01]), Ok(1));
        assert_eq!(int64(&[0xff]), Ok(-1));
        assert_eq!(int64(&[0x00, 0xff]), Ok(255));
        assert_eq!(int64(&[0x80, 0, 0, 0, 0, 0, 0, 0]), Ok(i64::MIN));
        assert_eq!(int64(&[0x01, 0, 0, 0, 0, 0, 0, 0, 0]), Err(Malformed));
        assert_eq!(int64(&[0x00, 0x01]), Err(Malformed));
    }

    /// An OBJECT IDENTIFIER reads when each number is base 128 Go reads,
    /// and a BIT STRING when its unused bits are at most seven, zero, and
    /// not in a string with no bits.
    #[test]
    fn identifiers_and_bit_strings_read_as_go_reads_them() {
        assert!(object_identifier_ok(&[0x2b, 0x81, 0x04, 0x00, 0x22]));
        assert!(object_identifier_ok(&[0x87, 0xff, 0xff, 0xff, 0x7f]));
        for refused in [
            &[][..],
            &[0x80, 0x01],
            &[0x2b, 0x81],
            &[0x88, 0x80, 0x80, 0x80, 0x00],
            &[0x81, 0x81, 0x81, 0x81, 0x81, 0x01],
        ] {
            assert!(!object_identifier_ok(refused), "{refused:02x?}");
        }
        assert!(bit_string_ok(&[0x00]));
        assert!(bit_string_ok(&[0x00, 0xff]));
        assert!(bit_string_ok(&[0x07, 0x80]));
        for refused in [
            &[][..],
            &[0x01],
            &[0x08, 0x00],
            &[0x01, 0x01],
            &[0x07, 0xc0],
        ] {
            assert!(!bit_string_ok(refused), "{refused:02x?}");
        }
    }

    /// Fields in order, an optional one absent where the next element
    /// carries another tag and left for the field after it, and the bytes
    /// after the last field never looked at.
    #[test]
    fn fields_read_in_order() {
        let data = [0x02, 0x01, 0x05, 0x04, 0x01, 0xaa, 0x05, 0x00, 0xff];
        let mut fields = Reader::new(&data);
        assert_eq!(fields.field(INTEGER), Ok(&[0x05][..]));
        assert_eq!(fields.optional(INTEGER), Ok(None));
        assert_eq!(fields.field(OCTET_STRING), Ok(&[0xaa][..]));
        assert_eq!(fields.optional_any(), Ok(Some(&[0x05, 0x00][..])));
        assert_eq!(fields.rest(), &[0xff]);
        assert_eq!(fields.optional(INTEGER), Err(Malformed));
        assert_eq!(Reader::new(&[]).field(INTEGER), Err(Malformed));
        assert_eq!(
            Reader::new(&[0x02, 0x02, 0x01]).field(INTEGER),
            Err(Malformed)
        );
        // Another tag is absent before its length is held to the input.
        assert_eq!(Reader::new(&[0x04, 0x7f]).optional(INTEGER), Ok(None));
    }

    /// An explicitly tagged field: the element inside a constructed
    /// wrapper of its number, the wrapper's own length unchecked; absent
    /// for a wrapper of another number or class, a primitive one, or one
    /// holding another tag; refused for an empty wrapper, a header that
    /// ends the input, or an inner element that does not fit.
    #[test]
    fn explicit_fields_read_as_go_reads_them() {
        let oid = [0x06, 0x01, 0x2a];
        let explicit = |data: &[u8]| {
            let mut fields = Reader::new(data);
            fields
                .optional_explicit(0, OBJECT_IDENTIFIER)
                .map(|content| (content.map(<[u8]>::to_vec), fields.rest().to_vec()))
        };
        let present = |wrapper: &[u8]| [wrapper, &oid[..], &[0x05, 0x00]].concat();
        for wrapper in [&[0xa0, 0x03][..], &[0xa0, 0x01], &[0xa0, 0x7f]] {
            assert_eq!(
                explicit(&present(wrapper)),
                Ok((Some(vec![0x2a]), vec![0x05, 0x00])),
                "{wrapper:02x?}"
            );
        }
        for absent in [
            present(&[0xa1, 0x03]),
            present(&[0x80, 0x03]),
            present(&[0xe0, 0x03]),
            [&[0xa0, 0x03, 0x02, 0x01, 0x01][..], &[0x05, 0x00]].concat(),
            vec![0x05, 0x00, 0x05, 0x00],
        ] {
            assert_eq!(
                explicit(&absent),
                Ok((None, absent.clone())),
                "{absent:02x?}"
            );
        }
        for refused in [
            vec![0x05, 0x00],
            vec![0xa0, 0x03],
            vec![0xa0, 0x00, 0x05, 0x00],
            vec![0x80, 0x00, 0x05, 0x00],
            vec![0xa0, 0x03, 0x06, 0x05, 0x2a],
            vec![0xff],
        ] {
            assert_eq!(explicit(&refused), Err(Malformed), "{refused:02x?}");
        }
    }
}
