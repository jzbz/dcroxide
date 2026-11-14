// SPDX-License-Identifier: ISC
//! A DER reader with the rules of Go's `encoding/asn1`, as `asn1.Unmarshal`
//! applies them to the private-key structures of `crypto/x509`
//! (`pkcs1.go`, `pkcs8.go`, `sec1.go`), for [`crate::keys`].  Line
//! citations are to Go 1.27.3.
//!
//! Go reads a key field by field into a struct, and is lenient in a few
//! places a key written by another tool can differ from one Go writes.
//! This reader is lenient in the same places and no others:
//!
//! * A SEQUENCE read into a struct may hold bytes after its last field,
//!   which are never looked at (`encoding/asn1/asn1.go:994-997`), and
//!   bytes after a top-level element are handed back to the caller
//!   (`:1172-1182`), which for PKCS#8 and SEC 1 ignores them.
//! * An optional field is absent when nothing is left, or when the next
//!   element carries another tag, which is then left for the field after
//!   it (`:722-728`, `:889-898`).  The next element's identifier and
//!   length must still read, or the whole structure fails.
//! * An optional field in an explicit tag (SEC 1's `[0]` and `[1]`) is
//!   absent too when the wrapper is primitive, or is there but the element
//!   inside it has another tag, and the wrapper's own length is never
//!   checked against that element (`:789-824`).  Where such a field is
//!   read, an element whose identifier and length end the SEQUENCE fails
//!   it, whatever its tag, and so does an empty wrapper (`:794-796`,
//!   `:806-809`).
//!
//! Everything else is DER as Go reads it: a tag number in the high-tag
//! form only from 31 up and written minimally (`:569-581`); a definite
//! length, in the long form only from 128 up, without leading zero
//! octets and below 2^31 (`:588-625`); INTEGERs minimally encoded
//! (`:80-93`); each OBJECT IDENTIFIER and BIT STRING well formed
//! (`:197-213`, `:251-332`); and a SEQUENCE OF whose elements' headers
//! are all checked before any element is read (`:633-688`).  Every length
//! is checked against the bytes before it is used, so no input reaches
//! past its end.
//!
//! Where Go's `Unmarshal` fails, this reader fails with Go's error value
//! ([`Asn1Error`]), checked in Go's order, so that a key refused for its
//! structure gets the text Go gives for it.  The texts name tags,
//! lengths, offsets and type names, never the bytes read.

use core::fmt;

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

/// A field Go's struct requires: the tag its element must carry, and the
/// name Go's reflection gives the field's type (`reflect.Type.Name`),
/// which ends Go's text for an element of another tag
/// (`encoding/asn1/asn1.go:896`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct Field {
    /// The tag the field's element carries.
    tag: Tag,
    /// The name of the field's Go type: empty for an unnamed type, a
    /// pointer or a slice.
    go_name: &'static str,
}

impl Field {
    /// A field of a Go struct type named `go_name`, read from a SEQUENCE.
    pub(crate) const fn structure(go_name: &'static str) -> Field {
        Field {
            tag: SEQUENCE,
            go_name,
        }
    }
}

/// An `int` field.
pub(crate) const INT: Field = Field {
    tag: INTEGER,
    go_name: "int",
};
/// A `*big.Int` field, whose type has no name.
pub(crate) const BIG_INT: Field = Field {
    tag: INTEGER,
    go_name: "",
};
/// A `[]byte` field, whose type has no name.
pub(crate) const BYTES: Field = Field {
    tag: OCTET_STRING,
    go_name: "",
};
/// An `asn1.ObjectIdentifier` field.
pub(crate) const OID: Field = Field {
    tag: OBJECT_IDENTIFIER,
    go_name: "ObjectIdentifier",
};

/// Go's `%+v` of the field parameters in a "tags don't match" text.
///
/// Go prints the parameters of the field whose element carries another
/// tag (`encoding/asn1/asn1.go:896`), and only for a field that is not
/// optional, since an optional one is then absent (`:892-894`).  Every
/// field this reader reports that way is untagged and has no
/// parameters: the optional ones (PKCS#1's CRT values and additional
/// primes, SEC 1's `[0]` and `[1]`) are absent instead, `RawValue` takes
/// any tag, and a SEQUENCE OF's element of another tag is Go's "sequence
/// tag mismatch" before any element is read (`:660-662`).  So the
/// parameters printed are always the zero value, and no `tag` pointer,
/// which would print an address, ever appears.
const ZERO_PARAMETERS: &str = "{optional:false explicit:false application:false private:false \
                               defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false \
                               omitEmpty:false}";

/// Why a structure does not read as Go reads it: the error value Go's
/// `asn1.Unmarshal` returns, which prints as Go prints it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Asn1Error {
    /// Go's `StructuralError` (`encoding/asn1/asn1.go:39-44`).
    Structural(&'static str),
    /// Go's `SyntaxError` (`:46-51`).
    Syntax(&'static str),
    /// Go's `StructuralError` for a required field whose element carries
    /// another tag (`:896`).
    TagsDontMatch {
        /// The universal tag number the field takes.
        expected: u32,
        /// The element's identifier as read.
        found: Tag,
        /// The element's length as read, which may run past the input:
        /// the tag is compared first.
        len: usize,
        /// The field's Go type name.
        go_name: &'static str,
        /// The offset just past the element's header, counted from the
        /// start of the bytes the field was read from: the content of the
        /// SEQUENCE holding it, or the whole input at the top level.
        offset: usize,
    },
}

impl fmt::Display for Asn1Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Asn1Error::Structural(text) => write!(f, "asn1: structure error: {text}"),
            Asn1Error::Syntax(text) => write!(f, "asn1: syntax error: {text}"),
            Asn1Error::TagsDontMatch {
                expected,
                found,
                len,
                go_name,
                offset,
            } => write!(
                f,
                "asn1: structure error: tags don't match ({expected} vs {{class:{} tag:{} \
                 length:{len} isCompound:{}}}) {ZERO_PARAMETERS} {go_name} @{offset}",
                found.class, found.number, found.constructed
            ),
        }
    }
}

/// Go's "truncated tag or length" (`encoding/asn1/asn1.go:583`, `:601`).
const TRUNCATED_HEADER: Asn1Error = Asn1Error::Syntax("truncated tag or length");
/// Go's "data truncated" (`encoding/asn1/asn1.go:900-903`).
const DATA_TRUNCATED: Asn1Error = Asn1Error::Syntax("data truncated");

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

/// Go's `parseTagAndLength` (`encoding/asn1/asn1.go:555-628`) at the
/// start of `data`, which every caller holds to at least one byte, as Go's
/// callers do (`:557-561`).
#[allow(
    clippy::arithmetic_side_effects,
    reason = "a header is at most a few bytes, and the length is held below 2^31 before each shift"
)]
fn header(data: &[u8]) -> Result<Header, Asn1Error> {
    let (&identifier, rest) = data.split_first().ok_or(TRUNCATED_HEADER)?;
    let mut number = u32::from(identifier & 0x1f);
    let mut rest = rest;
    let mut size = 1;
    if number == 0x1f {
        // The high-tag form, used only for numbers from 31 up.
        let (value, used) = base128(rest)?;
        if value < 0x1f {
            return Err(Asn1Error::Syntax("non-minimal tag"));
        }
        number = value;
        rest = rest.get(used..).ok_or(TRUNCATED_HEADER)?;
        size += used;
    }
    let (&first, mut rest) = rest.split_first().ok_or(TRUNCATED_HEADER)?;
    size += 1;
    let len = if first & 0x80 == 0 {
        usize::from(first)
    } else {
        // The long form: no indefinite length, no leading zero octet, a
        // value below 2^31 and at least 128, as Go checks it octet by
        // octet.
        let count = usize::from(first & 0x7f);
        if count == 0 {
            return Err(Asn1Error::Syntax("indefinite length found (not DER)"));
        }
        let mut len = 0usize;
        for _ in 0..count {
            let (&octet, tail) = rest.split_first().ok_or(TRUNCATED_HEADER)?;
            rest = tail;
            if len >= 1 << 23 {
                return Err(Asn1Error::Structural("length too large"));
            }
            len = (len << 8) | usize::from(octet);
            if len == 0 {
                return Err(Asn1Error::Structural("superfluous leading zeros in length"));
            }
        }
        if len < 0x80 {
            return Err(Asn1Error::Structural("non-minimal length"));
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

/// Go's "base 128 integer too large" (`encoding/asn1/asn1.go:308`, `:325`).
const BASE128_TOO_LARGE: Asn1Error = Asn1Error::Structural("base 128 integer too large");

/// Go's `parseBase128Int` (`encoding/asn1/asn1.go:299-332`): the value of
/// the base-128 number at the start of `data` and its length in bytes.
/// At most five groups, the first not `0x80`, the value at most
/// `i32::MAX`, and a last group that ends it.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "at most five seven-bit groups are shifted into a u64"
)]
fn base128(data: &[u8]) -> Result<(u32, usize), Asn1Error> {
    let mut value = 0u64;
    for (index, &group) in data.iter().enumerate() {
        if index == 5 {
            return Err(BASE128_TOO_LARGE);
        }
        if index == 0 && group == 0x80 {
            return Err(Asn1Error::Syntax("integer is not minimally encoded"));
        }
        value = (value << 7) | u64::from(group & 0x7f);
        if group & 0x80 == 0 {
            return match u32::try_from(value) {
                Ok(value) if value <= i32::MAX.unsigned_abs() => Ok((value, index + 1)),
                _ => Err(BASE128_TOO_LARGE),
            };
        }
    }
    Err(Asn1Error::Syntax("truncated base 128 integer"))
}

/// An element read for a field: its content, and the bytes after it.
struct Element<'a> {
    /// The element's content.
    content: &'a [u8],
    /// What follows the element.
    after: &'a [u8],
}

/// The next element, as a field of one tag finds it.
enum Next<'a> {
    /// The element carries the tag, and its content fits.
    Match(Element<'a>),
    /// The element carries another tag: its header, its length not held
    /// to the input.
    Other(Header),
}

/// The fields of one of Go's structures, read in order from a
/// SEQUENCE's content, or the one element of a top-level `Unmarshal`.
pub(crate) struct Reader<'a> {
    /// What is not read yet.
    data: &'a [u8],
    /// The length of the bytes the reader was made over, which Go counts
    /// offsets from.
    len: usize,
}

impl<'a> Reader<'a> {
    /// A reader over `data`.
    pub(crate) fn new(data: &'a [u8]) -> Reader<'a> {
        Reader {
            data,
            len: data.len(),
        }
    }

    /// What is not read yet: after a top-level element, what Go's
    /// `Unmarshal` returns as `rest`.
    pub(crate) fn rest(&self) -> &'a [u8] {
        self.data
    }

    /// The offset of what is not read yet.
    fn offset(&self) -> usize {
        self.len.saturating_sub(self.data.len())
    }

    /// The next element's header, and its content when it carries `tag`:
    /// an error for an element whose header does not read or, carrying
    /// `tag`, whose content runs past the end (Go's "data truncated").
    fn next(&self, tag: Tag) -> Result<Next<'a>, Asn1Error> {
        let header = header(self.data)?;
        if header.tag != tag {
            return Ok(Next::Other(header));
        }
        let body = self.data.get(header.size..).ok_or(DATA_TRUNCATED)?;
        let (content, after) = body.split_at_checked(header.len).ok_or(DATA_TRUNCATED)?;
        Ok(Next::Match(Element { content, after }))
    }

    /// A field Go's struct requires: the next element's content.  Nothing
    /// left is Go's "sequence truncated" (`encoding/asn1/asn1.go:722-728`),
    /// and another tag its "tags don't match" (`:889-898`).
    pub(crate) fn field(&mut self, field: Field) -> Result<&'a [u8], Asn1Error> {
        if self.data.is_empty() {
            return Err(Asn1Error::Syntax("sequence truncated"));
        }
        match self.next(field.tag)? {
            Next::Match(element) => {
                self.data = element.after;
                Ok(element.content)
            }
            Next::Other(header) => Err(Asn1Error::TagsDontMatch {
                expected: field.tag.number,
                found: header.tag,
                len: header.len,
                go_name: field.go_name,
                offset: self.offset().saturating_add(header.size),
            }),
        }
    }

    /// An `optional` field of `tag`: the next element's content, or
    /// `None` when nothing is left or the next element carries another
    /// tag, which is then left unread.
    pub(crate) fn optional(&mut self, tag: Tag) -> Result<Option<&'a [u8]>, Asn1Error> {
        if self.data.is_empty() {
            return Ok(None);
        }
        let Next::Match(element) = self.next(tag)? else {
            return Ok(None);
        };
        self.data = element.after;
        Ok(Some(element.content))
    }

    /// An `optional` field of Go's `RawValue` type, which takes any
    /// element: the next element whole, header included (`FullBytes`),
    /// or `None` when nothing is left.
    pub(crate) fn optional_any(&mut self) -> Result<Option<&'a [u8]>, Asn1Error> {
        if self.data.is_empty() {
            return Ok(None);
        }
        let header = header(self.data)?;
        let end = header.size.checked_add(header.len).ok_or(DATA_TRUNCATED)?;
        let (element, after) = self.data.split_at_checked(end).ok_or(DATA_TRUNCATED)?;
        self.data = after;
        Ok(Some(element))
    }

    /// An `optional,explicit,tag:number` field of `tag`, as Go's
    /// `parseField` reads one (`encoding/asn1/asn1.go:789-824`): the
    /// content of the element inside the wrapper.
    ///
    /// The wrapper is the next element's header when it is
    /// context-specific, numbered `number`, and constructed or empty.
    /// When the next element is not such a wrapper, or the element inside
    /// it carries another tag, the field is absent and both are left
    /// unread.  A next header that ends the input is Go's "explicit tag
    /// has no child", and a wrapper that is empty its "zero length
    /// explicit tag was not an asn1.Flag"; an inner element whose header
    /// does not read or whose content runs past the end fails too.  The
    /// element inside is read from the bytes after the wrapper's header,
    /// whatever length the wrapper gives.
    pub(crate) fn optional_explicit(
        &mut self,
        number: u32,
        tag: Tag,
    ) -> Result<Option<&'a [u8]>, Asn1Error> {
        if self.data.is_empty() {
            return Ok(None);
        }
        let wrapper = header(self.data)?;
        let inner = self.data.get(wrapper.size..).ok_or(TRUNCATED_HEADER)?;
        if inner.is_empty() {
            return Err(Asn1Error::Structural("explicit tag has no child"));
        }
        let is_wrapper = wrapper.tag.class == CONTEXT_SPECIFIC
            && wrapper.tag.number == number
            && (wrapper.len == 0 || wrapper.tag.constructed);
        if !is_wrapper {
            return Ok(None);
        }
        if wrapper.len == 0 {
            return Err(Asn1Error::Structural(
                "zero length explicit tag was not an asn1.Flag",
            ));
        }
        let inner = Reader::new(inner);
        let Next::Match(element) = inner.next(tag)? else {
            return Ok(None);
        };
        self.data = element.after;
        Ok(Some(element.content))
    }
}

/// The first pass of Go's `parseSequenceOf`
/// (`encoding/asn1/asn1.go:642-670`) over a SEQUENCE OF's `content`:
/// every element's header reads, carries `elem`'s class, form and number,
/// and fits, all before any element is read.  An element of another tag
/// is Go's "sequence tag mismatch" and one that does not fit its
/// "truncated sequence", even when an element before it would fail to
/// read.
pub(crate) fn sequence_of(content: &[u8], elem: Tag) -> Result<(), Asn1Error> {
    let mut rest = content;
    while !rest.is_empty() {
        let header = header(rest)?;
        if header.tag != elem {
            return Err(Asn1Error::Structural("sequence tag mismatch"));
        }
        rest = rest
            .get(header.size..)
            .and_then(|body| body.get(header.len..))
            .ok_or(Asn1Error::Syntax("truncated sequence"))?;
    }
    Ok(())
}

/// Go's `checkInteger` (`encoding/asn1/asn1.go:80-93`), which a
/// `*big.Int` field takes: an INTEGER's content is DER's, at least one
/// byte and no byte more than its sign needs.
pub(crate) fn integer(content: &[u8]) -> Result<(), Asn1Error> {
    match content {
        [] => Err(Asn1Error::Structural("empty integer")),
        [0x00, next, ..] if next & 0x80 == 0 => {
            Err(Asn1Error::Structural("integer not minimally-encoded"))
        }
        [0xff, next, ..] if next & 0x80 != 0 => {
            Err(Asn1Error::Structural("integer not minimally-encoded"))
        }
        _ => Ok(()),
    }
}

/// Go's `parseInt64` (`encoding/asn1/asn1.go:95-116`), which an `int`
/// field takes on a 64-bit platform: the value of an INTEGER of at most
/// eight bytes.
pub(crate) fn int64(content: &[u8]) -> Result<i64, Asn1Error> {
    integer(content)?;
    let too_large = Asn1Error::Structural("integer too large");
    let negative = content.first().is_some_and(|first| first & 0x80 != 0);
    let mut bytes = [if negative { 0xff } else { 0x00 }; 8];
    let start = bytes.len().checked_sub(content.len()).ok_or(too_large)?;
    if let Some(tail) = bytes.get_mut(start..) {
        tail.copy_from_slice(content);
    }
    Ok(i64::from_be_bytes(bytes))
}

/// Go's `parseObjectIdentifier` (`encoding/asn1/asn1.go:251-287`): an
/// OBJECT IDENTIFIER's content is at least one byte of base-128 numbers
/// Go reads.  Each number has one encoding Go reads, so two identifiers
/// that read are equal exactly when their bytes are.
pub(crate) fn object_identifier(content: &[u8]) -> Result<(), Asn1Error> {
    if content.is_empty() {
        return Err(Asn1Error::Syntax("zero length OBJECT IDENTIFIER"));
    }
    let mut rest = content;
    while !rest.is_empty() {
        let (_, used) = base128(rest)?;
        rest = rest.get(used..).unwrap_or_default();
    }
    Ok(())
}

/// An OBJECT IDENTIFIER's content that [`object_identifier`] reads, which
/// prints as Go's `ObjectIdentifier.String` prints the identifier Go reads
/// from it (`encoding/asn1/asn1.go:233-245`, `:265-275`): the first
/// number as two arcs, its fortieths and the rest below 80 and 2 and the
/// rest from 80 up, then each number after it, joined with dots.
pub(crate) struct Dotted<'a>(pub(crate) &'a [u8]);

impl fmt::Display for Dotted<'_> {
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "Go's split of the first number, at least 80 where 80 is taken from it"
    )]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut rest = self.0;
        let mut first = true;
        while let Ok((value, used)) = base128(rest) {
            if first {
                if value < 80 {
                    write!(f, "{}.{}", value / 40, value % 40)?;
                } else {
                    write!(f, "2.{}", value - 80)?;
                }
                first = false;
            } else {
                write!(f, ".{value}")?;
            }
            rest = rest.get(used..).unwrap_or_default();
        }
        Ok(())
    }
}

/// Go's `parseBitString` (`encoding/asn1/asn1.go:197-213`): a BIT
/// STRING's content reads: a count of unused bits, at most seven and none
/// in a string with no bits, then the bits, whose unused ones are zero.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "a shift of at most seven, checked first"
)]
pub(crate) fn bit_string(content: &[u8]) -> Result<(), Asn1Error> {
    let Some((&unused, bits)) = content.split_first() else {
        return Err(Asn1Error::Syntax("zero length BIT STRING"));
    };
    let reads = unused <= 7
        && (unused == 0 || !bits.is_empty())
        && bits
            .last()
            .is_none_or(|last| last & ((1u8 << unused) - 1) == 0);
    if reads {
        Ok(())
    } else {
        Err(Asn1Error::Syntax("invalid padding bits in BIT STRING"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header's tag, length and size as the reader takes them, or the
    /// text of its error.
    fn read(data: &[u8]) -> Result<(Tag, usize, usize), String> {
        header(data)
            .map(|header| (header.tag, header.len, header.size))
            .map_err(|error| error.to_string())
    }

    /// The text of an error, or of none.
    fn text<T>(result: Result<T, Asn1Error>) -> String {
        result
            .err()
            .map_or_else(String::new, |error| error.to_string())
    }

    /// Lengths in the short form, and in the long form only as DER and
    /// Go write them: no indefinite length, no leading zero octet, nothing
    /// under 128, nothing from 2^31 up, each refused with Go's text.  A
    /// header that stops short is refused, and the length is not held to
    /// the bytes that follow.
    #[test]
    fn a_length_reads_as_go_reads_it() {
        assert_eq!(read(&[0x04, 0x00]), Ok((OCTET_STRING, 0, 2)));
        assert_eq!(read(&[0x04, 0x7f]), Ok((OCTET_STRING, 127, 2)));
        assert_eq!(read(&[0x04, 0x81, 0x80]), Ok((OCTET_STRING, 128, 3)));
        assert_eq!(
            read(&[0x04, 0x84, 0x7f, 0xff, 0xff, 0xff]),
            Ok((OCTET_STRING, 0x7fff_ffff, 6))
        );
        assert_eq!(read(&[0x04, 0x82, 0x01, 0x00]), Ok((OCTET_STRING, 256, 4)));
        for (refused, want) in [
            (&[0x04][..], "asn1: syntax error: truncated tag or length"),
            (
                &[0x04, 0x80],
                "asn1: syntax error: indefinite length found (not DER)",
            ),
            (&[0x04, 0x81], "asn1: syntax error: truncated tag or length"),
            (
                &[0x04, 0x81, 0x7f],
                "asn1: structure error: non-minimal length",
            ),
            (
                &[0x04, 0x82, 0x00, 0x80],
                "asn1: structure error: superfluous leading zeros in length",
            ),
            (
                &[0x04, 0x84, 0x80, 0x00, 0x00, 0x00],
                "asn1: structure error: length too large",
            ),
            (
                &[0x04, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00],
                "asn1: structure error: length too large",
            ),
        ] {
            assert_eq!(read(refused), Err(want.to_owned()), "{refused:02x?}");
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
        let tag = |data: &[u8]| read(data).map(|read| read.0);
        assert_eq!(tag(&[0xa0, 0x00]), Ok(context(true, 0)));
        assert_eq!(tag(&[0x81, 0x00]), Ok(context(false, 1)));
        assert_eq!(tag(&[0x30, 0x00]), Ok(SEQUENCE));
        assert_eq!(read(&[0x9f, 0x1f, 0x00]), Ok((context(false, 31), 0, 3)));
        assert_eq!(
            read(&[0xbf, 0x81, 0x00, 0x00]),
            Ok((context(true, 128), 0, 4))
        );
        assert_eq!(
            read(&[0x9f, 0x87, 0xff, 0xff, 0xff, 0x7f, 0x00]),
            Ok((context(false, 0x7fff_ffff), 0, 7))
        );
        for (refused, want) in [
            (
                &[0x9f, 0x1e, 0x00][..],
                "asn1: syntax error: non-minimal tag",
            ),
            (
                &[0x9f, 0x80, 0x1f, 0x00],
                "asn1: syntax error: integer is not minimally encoded",
            ),
            (
                &[0x9f, 0x81],
                "asn1: syntax error: truncated base 128 integer",
            ),
            (
                &[0x9f, 0x88, 0x80, 0x80, 0x80, 0x00, 0x00],
                "asn1: structure error: base 128 integer too large",
            ),
            (
                &[0x9f, 0x81, 0x81, 0x81, 0x81, 0x81, 0x01],
                "asn1: structure error: base 128 integer too large",
            ),
            (&[0x9f], "asn1: syntax error: truncated base 128 integer"),
            (&[0x9f, 0x1f], "asn1: syntax error: truncated tag or length"),
        ] {
            assert_eq!(read(refused), Err(want.to_owned()), "{refused:02x?}");
        }
    }

    /// Go's integer rules: minimal, not empty, and eight bytes at most for
    /// a 64-bit Go's `int`, with the sign extended.
    #[test]
    fn integers_read_as_go_reads_them() {
        for content in [&[0x00][..], &[0x00, 0x80], &[0xff, 0x7f], &[0xff]] {
            assert_eq!(integer(content), Ok(()), "{content:02x?}");
        }
        assert_eq!(text(integer(&[])), "asn1: structure error: empty integer");
        for content in [&[0x00, 0x7f][..], &[0xff, 0x80]] {
            assert_eq!(
                text(integer(content)),
                "asn1: structure error: integer not minimally-encoded"
            );
        }
        assert_eq!(int64(&[0x01]), Ok(1));
        assert_eq!(int64(&[0xff]), Ok(-1));
        assert_eq!(int64(&[0x00, 0xff]), Ok(255));
        assert_eq!(int64(&[0x80, 0, 0, 0, 0, 0, 0, 0]), Ok(i64::MIN));
        assert_eq!(
            text(int64(&[0x01, 0, 0, 0, 0, 0, 0, 0, 0])),
            "asn1: structure error: integer too large"
        );
        assert_eq!(
            text(int64(&[0x00, 0x01])),
            "asn1: structure error: integer not minimally-encoded"
        );
    }

    /// An OBJECT IDENTIFIER reads when each number is base 128 Go reads,
    /// and prints as Go prints it; a BIT STRING reads when its unused bits
    /// are at most seven, zero, and not in a string with no bits.
    #[test]
    fn identifiers_and_bit_strings_read_as_go_reads_them() {
        for (content, dotted) in [
            (&[0x2b, 0x81, 0x04, 0x00, 0x22][..], "1.3.132.0.34"),
            (&[0x87, 0xff, 0xff, 0xff, 0x7f], "2.2147483567"),
            (&[0x27], "0.39"),
            (&[0x28], "1.0"),
            (&[0x4f], "1.39"),
            (&[0x50], "2.0"),
            (&[0x7f], "2.47"),
            (&[0x88, 0x37, 0x01], "2.999.1"),
        ] {
            assert_eq!(object_identifier(content), Ok(()), "{content:02x?}");
            assert_eq!(Dotted(content).to_string(), dotted, "{content:02x?}");
        }
        for (content, want) in [
            (&[][..], "asn1: syntax error: zero length OBJECT IDENTIFIER"),
            (
                &[0x80, 0x01],
                "asn1: syntax error: integer is not minimally encoded",
            ),
            (
                &[0x2b, 0x80, 0x01],
                "asn1: syntax error: integer is not minimally encoded",
            ),
            (
                &[0x2b, 0x81],
                "asn1: syntax error: truncated base 128 integer",
            ),
            (
                &[0x88, 0x80, 0x80, 0x80, 0x00],
                "asn1: structure error: base 128 integer too large",
            ),
            (
                &[0x81, 0x81, 0x81, 0x81, 0x81, 0x01],
                "asn1: structure error: base 128 integer too large",
            ),
        ] {
            assert_eq!(text(object_identifier(content)), want, "{content:02x?}");
        }
        for content in [&[0x00][..], &[0x00, 0xff], &[0x07, 0x80]] {
            assert_eq!(bit_string(content), Ok(()), "{content:02x?}");
        }
        assert_eq!(
            text(bit_string(&[])),
            "asn1: syntax error: zero length BIT STRING"
        );
        for content in [&[0x01][..], &[0x08, 0x00], &[0x01, 0x01], &[0x07, 0xc0]] {
            assert_eq!(
                text(bit_string(content)),
                "asn1: syntax error: invalid padding bits in BIT STRING",
                "{content:02x?}"
            );
        }
    }

    /// Fields in order, an optional one absent where the next element
    /// carries another tag and left for the field after it, and the bytes
    /// after the last field never looked at; a required field missing is
    /// Go's "sequence truncated", and one too long its "data truncated".
    #[test]
    fn fields_read_in_order() {
        let data = [0x02, 0x01, 0x05, 0x04, 0x01, 0xaa, 0x05, 0x00, 0xff];
        let mut fields = Reader::new(&data);
        assert_eq!(fields.field(INT), Ok(&[0x05][..]));
        assert_eq!(fields.optional(INTEGER), Ok(None));
        assert_eq!(fields.field(BYTES), Ok(&[0xaa][..]));
        assert_eq!(fields.optional_any(), Ok(Some(&[0x05, 0x00][..])));
        assert_eq!(fields.rest(), &[0xff]);
        assert_eq!(
            text(fields.optional(INTEGER)),
            "asn1: syntax error: truncated base 128 integer"
        );
        assert_eq!(
            text(Reader::new(&[]).field(INT)),
            "asn1: syntax error: sequence truncated"
        );
        assert_eq!(
            text(Reader::new(&[0x02, 0x02, 0x01]).field(INT)),
            "asn1: syntax error: data truncated"
        );
        assert_eq!(
            text(Reader::new(&[0x05, 0x03]).optional_any()),
            "asn1: syntax error: data truncated"
        );
        // Another tag is absent before its length is held to the input.
        assert_eq!(Reader::new(&[0x04, 0x7f]).optional(INTEGER), Ok(None));
    }

    /// A required field of another tag: Go's text, with the header as
    /// read (its length not held to the input), the zero parameters, the
    /// field's type name, two spaces where the type has none, and the
    /// offset past the header counted from the start of the bytes the
    /// reader was made over.  The parameters are a constant, Go's zero
    /// value as it prints it, because no field reported this way has any
    /// ([`ZERO_PARAMETERS`] says why).
    #[test]
    fn a_field_of_another_tag_reads_as_go_reports_it() {
        let data = [0x02, 0x01, 0x00, 0x31, 0x7f];
        let mut fields = Reader::new(&data);
        assert_eq!(fields.field(INT), Ok(&[0x00][..]));
        assert_eq!(
            text(fields.field(Field::structure("AlgorithmIdentifier"))),
            format!(
                "asn1: structure error: tags don't match (16 vs {{class:0 tag:17 length:127 \
                 isCompound:true}}) {ZERO_PARAMETERS} AlgorithmIdentifier @5"
            )
        );
        assert_eq!(
            text(Reader::new(&[0xbf, 0x81, 0x00, 0x00]).field(BYTES)),
            format!(
                "asn1: structure error: tags don't match (4 vs {{class:2 tag:128 length:0 \
                 isCompound:true}}) {ZERO_PARAMETERS}  @4"
            )
        );
        assert_eq!(
            text(Reader::new(&[0x22, 0x00]).field(BIG_INT)),
            format!(
                "asn1: structure error: tags don't match (2 vs {{class:0 tag:2 length:0 \
                 isCompound:true}}) {ZERO_PARAMETERS}  @2"
            )
        );
        assert_eq!(
            text(Reader::new(&[0x04, 0x00]).field(OID)),
            format!(
                "asn1: structure error: tags don't match (6 vs {{class:0 tag:4 length:0 \
                 isCompound:false}}) {ZERO_PARAMETERS} ObjectIdentifier @2"
            )
        );
        assert_eq!(
            ZERO_PARAMETERS,
            "{optional:false explicit:false application:false private:false defaultValue:<nil> \
             tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false}"
        );
    }

    /// An explicitly tagged field: the element inside a constructed
    /// wrapper of its number, the wrapper's own length unchecked; absent
    /// for a wrapper of another number or class, a primitive one, or one
    /// holding another tag; refused, with Go's text, for an empty wrapper,
    /// a header that ends the input, or an inner element that does not
    /// fit.
    #[test]
    fn explicit_fields_read_as_go_reads_them() {
        let oid = [0x06, 0x01, 0x2a];
        let explicit = |data: &[u8]| {
            let mut fields = Reader::new(data);
            fields
                .optional_explicit(0, OBJECT_IDENTIFIER)
                .map(|content| (content.map(<[u8]>::to_vec), fields.rest().to_vec()))
                .map_err(|error| error.to_string())
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
        let no_child = "asn1: structure error: explicit tag has no child";
        for (refused, want) in [
            (vec![0x05, 0x00], no_child),
            (vec![0xa0, 0x03], no_child),
            (
                vec![0xa0, 0x00, 0x05, 0x00],
                "asn1: structure error: zero length explicit tag was not an asn1.Flag",
            ),
            (
                vec![0x80, 0x00, 0x05, 0x00],
                "asn1: structure error: zero length explicit tag was not an asn1.Flag",
            ),
            (
                vec![0xa0, 0x03, 0x06, 0x05, 0x2a],
                "asn1: syntax error: data truncated",
            ),
            (vec![0xff], "asn1: syntax error: truncated base 128 integer"),
            (
                vec![0xa0, 0x03, 0x06, 0x80],
                "asn1: syntax error: indefinite length found (not DER)",
            ),
        ] {
            assert_eq!(explicit(&refused), Err(want.to_owned()), "{refused:02x?}");
        }
    }

    /// A SEQUENCE OF: every element's header checked before any element
    /// is read, so an element of another tag, or one that does not fit,
    /// is reported ahead of an element before it that would not read.
    #[test]
    fn a_sequence_of_checks_every_header_first() {
        let int = [0x02, 0x01, 0x01];
        let element = [&[0x30, 0x03][..], &int].concat();
        assert_eq!(sequence_of(&[], SEQUENCE), Ok(()));
        assert_eq!(
            sequence_of(&[element.clone(), element].concat(), SEQUENCE),
            Ok(())
        );
        for (content, want) in [
            (int.to_vec(), "asn1: structure error: sequence tag mismatch"),
            (
                vec![0x30, 0x05, 0x02],
                "asn1: syntax error: truncated sequence",
            ),
            (
                vec![0x30, 0x02, 0x02, 0x00, 0x02, 0x01, 0x01],
                "asn1: structure error: sequence tag mismatch",
            ),
            (
                vec![0x30, 0x80],
                "asn1: syntax error: indefinite length found (not DER)",
            ),
            (
                vec![0x10, 0x00],
                "asn1: structure error: sequence tag mismatch",
            ),
        ] {
            assert_eq!(
                text(sequence_of(&content, SEQUENCE)),
                want,
                "{content:02x?}"
            );
        }
    }
}
