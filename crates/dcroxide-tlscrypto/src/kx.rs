// SPDX-License-Identifier: ISC
//! Key exchange: X25519 on `curve25519-dalek`'s Montgomery ladder, and
//! P-256, P-384 and P-521 on the arithmetic of the RustCrypto curve
//! crates, each a rustls `SupportedKxGroup` under the name ring's provider
//! gives it (`rustls-0.23.46/src/crypto/ring/kx.rs`), drawing its
//! ephemeral key from the kernel ([`kernel_fill`]) and refusing the shares
//! Go's `crypto/ecdh` refuses:
//!
//! * X25519 takes any 32 bytes as the peer's share, read as RFC 7748 §5
//!   reads a u-coordinate, its top bit ignored and a value at or above p
//!   reduced (`crypto/ecdh/x25519.go:69-80`), and refuses an all-zero
//!   shared secret, which a share of small order gives (`:82-89`).
//! * The NIST curves take only the uncompressed SEC 1 encoding: `0x04`,
//!   then both coordinates at the field's length, each below p, of a point
//!   on the curve.  The empty share, the point at infinity's one-byte
//!   encoding and the compressed and hybrid forms are refused before the
//!   curve is looked at (`crypto/ecdh/nist.go:120-125`,
//!   `crypto/internal/fips140/ecdh/ecdh.go:216-231`).  The shared secret
//!   is the whole x-coordinate of the product, leading zeros kept, as
//!   RFC 8446 §7.4.2 and Go take it.
//!
//! ring's groups make the same checks (`rustls-0.23.46/src/crypto/ring/
//! kx.rs:92`, `:111-116`, and ring's own all-zero check,
//! `ring-0.17.14/src/ec/curve25519/x25519.rs:158-162`), so where both
//! offer a group they agree on every share: `tests/ring_parity.rs` holds
//! them to that, and
//! `tests/go_differential.rs` holds all four groups to Go's verdicts.  A
//! refused share is rustls's `InvalidKeyShare`, which rustls answers with
//! an `illegal_parameter` alert, as Go answers its own.
//!
//! The NIST curves' exchange is written once, over [`NistCurve`], which a
//! macro implements on each curve's own crate, so the crates' trait bounds
//! stay out of the TLS logic.  No group takes an `ecdh` feature: it would
//! bring `hkdf` for what is one scalar multiplication.

use core::fmt;
use core::marker::PhantomData;

use curve25519_dalek::montgomery::MontgomeryPoint;
use rustls::crypto::{ActiveKeyExchange, GetRandomFailed, SharedSecret, SupportedKxGroup};
use rustls::ffdhe_groups::FfdheGroup;
use rustls::{Error, NamedGroup, PeerMisbehaved};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use crate::rand::kernel_fill;

/// ECDHE over Curve25519 (RFC 7748): the first group ring's provider
/// offers, and the first Go's offers after its post-quantum hybrids
/// (`crypto/tls/defaults.go:29-32`).
pub static X25519: &dyn SupportedKxGroup = &X25519Group;

/// ECDHE over secp256r1 (NIST P-256).
pub static SECP256R1: &dyn SupportedKxGroup = &NistGroup::<p256::NistP256>(PhantomData);

/// ECDHE over secp384r1 (NIST P-384).
pub static SECP384R1: &dyn SupportedKxGroup = &NistGroup::<p384::NistP384>(PhantomData);

/// ECDHE over secp521r1 (NIST P-521), which Go's server offers by default
/// (`crypto/tls/defaults.go:29-32`) and ring's provider does not
/// (`rustls-0.23.46/src/crypto/ring/mod.rs:180-181`).
pub static SECP521R1: &dyn SupportedKxGroup = &NistGroup::<p521::NistP521>(PhantomData);

/// The error for a share the group refuses.
fn invalid_share() -> Error {
    PeerMisbehaved::InvalidKeyShare.into()
}

/// The [`SupportedKxGroup`] behind [`X25519`].
struct X25519Group;

impl fmt::Debug for X25519Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name().fmt(f)
    }
}

impl SupportedKxGroup for X25519Group {
    /// An exchange with a fresh ephemeral key from the kernel
    /// ([`x25519_ephemeral_secret`]).
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let secret = x25519_ephemeral_secret(kernel_fill)?;
        Ok(Box::new(X25519KeyExchange::new(secret)))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

/// A fresh X25519 ephemeral key: 32 bytes `fill` draws, clamped where
/// they are used, as Go's `GenerateKey` reads them
/// (`crypto/ecdh/x25519.go:37-47`).  `fill` is [`kernel_fill`] but in the
/// tests, which stand in for it to fail a draw.
fn x25519_ephemeral_secret(
    fill: impl FnOnce(&mut [u8]) -> Result<(), GetRandomFailed>,
) -> Result<Zeroizing<[u8; 32]>, GetRandomFailed> {
    let mut secret = Zeroizing::new([0; 32]);
    fill(secret.as_mut_slice())?;
    Ok(secret)
}

/// One X25519 exchange in progress.
struct X25519KeyExchange {
    /// The ephemeral secret as drawn, unclamped; wiped on drop.
    secret: Zeroizing<[u8; 32]>,
    /// The public key: the u-coordinate of the clamped secret times the
    /// base point.
    pub_key: [u8; 32],
}

impl X25519KeyExchange {
    /// The exchange for an ephemeral secret.
    fn new(secret: Zeroizing<[u8; 32]>) -> X25519KeyExchange {
        let pub_key = MontgomeryPoint::mul_base_clamped(*secret).to_bytes();
        X25519KeyExchange { secret, pub_key }
    }
}

impl ActiveKeyExchange for X25519KeyExchange {
    /// The shared secret with the peer's share: the u-coordinate of the
    /// clamped secret times the share's point, refused when it is all
    /// zeros.  The check is made in constant time, as Go's `isZero` and
    /// ring's `verify_slices_are_equal` make it.
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let peer = <[u8; 32]>::try_from(peer_pub_key).map_err(|_| invalid_share())?;
        let mut shared = MontgomeryPoint(peer).mul_clamped(*self.secret);
        let all_zero = shared.as_bytes().ct_eq(&[0; 32]);
        let secret = SharedSecret::from(&shared.as_bytes()[..]);
        shared.zeroize();
        if bool::from(all_zero) {
            return Err(invalid_share());
        }
        Ok(secret)
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

/// A NIST curve as the key exchange takes it: its TLS name, its field's
/// length, the mask Go applies to a drawn scalar's first byte, and the
/// three operations on the curve crate's types.  The `nist_curve!` macro
/// writes it for each curve.
trait NistCurve: 'static + Send + Sync {
    /// The curve's name in `supported_groups` and `key_share`.
    const NAME: NamedGroup;
    /// The length of a field element, and of a scalar: 32, 48 or 66.
    const FIELD_LEN: usize;
    /// The length of an uncompressed point: the tag and two coordinates.
    const POINT_LEN: usize = 1 + 2 * Self::FIELD_LEN;
    /// What Go keeps of a drawn scalar's first byte: all of it, but for
    /// P-521, whose order's top byte is `0x01`
    /// (`crypto/internal/fips140/ecdh/ecdh.go:154-158`).
    const TOP_MASK: u8;
    /// A scalar in `[1, n)`, wiped by [`Zeroize`].
    type Secret: Zeroize + Send + Sync;

    /// The scalar `bytes` encode big-endian, at [`Self::FIELD_LEN`]
    /// bytes, or `None` when it is zero, at or above the order, or of
    /// another length.
    fn secret(bytes: &[u8]) -> Option<Self::Secret>;

    /// The uncompressed SEC 1 encoding of the secret times the generator.
    fn public(secret: &Self::Secret) -> Vec<u8>;

    /// The x-coordinate of the secret times the point `peer` encodes, at
    /// the field's length, or `None` when `peer` is not the uncompressed
    /// encoding of a point on the curve.
    fn shared_x(secret: &Self::Secret, peer: &[u8]) -> Option<Vec<u8>>;
}

/// [`NistCurve`] for the curve type `$curve` of the crate `$krate`.
macro_rules! nist_curve {
    ($krate:ident :: $curve:ident, $name:ident, $field_len:literal, $top_mask:literal) => {
        impl NistCurve for $krate::$curve {
            const NAME: NamedGroup = NamedGroup::$name;
            const FIELD_LEN: usize = $field_len;
            const TOP_MASK: u8 = $top_mask;
            type Secret = $krate::NonZeroScalar;

            fn secret(bytes: &[u8]) -> Option<Self::Secret> {
                let mut repr = $krate::FieldBytes::try_from(bytes).ok()?;
                let secret = $krate::NonZeroScalar::from_repr(repr).into_option();
                repr.zeroize();
                secret
            }

            fn public(secret: &Self::Secret) -> Vec<u8> {
                use $krate::elliptic_curve::sec1::ToSec1Point;
                $krate::PublicKey::from_secret_scalar(secret)
                    .to_sec1_point(false)
                    .as_bytes()
                    .to_vec()
            }

            fn shared_x(secret: &Self::Secret, peer: &[u8]) -> Option<Vec<u8>> {
                use $krate::elliptic_curve::group::Group;
                use $krate::elliptic_curve::point::AffineCoordinates;
                // `from_sec1_bytes` checks the length the tag implies, that
                // each coordinate is below p and that the point is on the
                // curve (`primeorder-0.14.0/src/affine.rs:100-108`).
                let peer = $krate::PublicKey::from_sec1_bytes(peer).ok()?;
                #[allow(
                    clippy::arithmetic_side_effects,
                    reason = "scalar multiplication of a curve point, which cannot overflow"
                )]
                let product = peer.to_projective() * **secret;
                // A point of the prime-order group times a scalar in
                // [1, n) is never the identity; checked anyway, as Go's
                // `BytesX` checks it.
                if bool::from(product.is_identity()) {
                    return None;
                }
                Some(product.to_affine().x().to_vec())
            }
        }
    };
}

nist_curve!(p256::NistP256, secp256r1, 32, 0xff);
nist_curve!(p384::NistP384, secp384r1, 48, 0xff);
nist_curve!(p521::NistP521, secp521r1, 66, 0x01);

/// The [`SupportedKxGroup`] for the NIST curve `C`.
struct NistGroup<C>(PhantomData<fn() -> C>);

impl<C: NistCurve> fmt::Debug for NistGroup<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        C::NAME.fmt(f)
    }
}

impl<C: NistCurve> SupportedKxGroup for NistGroup<C> {
    /// An exchange with a fresh ephemeral scalar from the kernel
    /// ([`ephemeral_secret`]).
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let secret = ephemeral_secret::<C>(kernel_fill)?;
        Ok(Box::new(NistKeyExchange::<C>::new(secret)))
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn name(&self) -> NamedGroup {
        C::NAME
    }
}

/// The longest scalar: P-521's 66 bytes.
const MAX_FIELD_LEN: usize = 66;

/// A fresh ephemeral scalar for `C`, drawn as Go's `GenerateKey` draws one
/// (`crypto/internal/fips140/ecdh/ecdh.go:139-163`, which `crypto/tls`
/// reaches through `crypto/ecdh` with `Config.rand`): the field's length
/// in bytes from `fill`, read by [`secret_from_draw`], tried until they
/// are a scalar in `[1, n)`.  The order is so close to a power of two on
/// each curve that a draw is almost never repeated.  `fill` is
/// [`kernel_fill`] but in the tests, which stand in for it to give the
/// draws the loop refuses, and to fail one.
fn ephemeral_secret<C: NistCurve>(
    mut fill: impl FnMut(&mut [u8]) -> Result<(), GetRandomFailed>,
) -> Result<C::Secret, GetRandomFailed> {
    const { assert!(C::FIELD_LEN <= MAX_FIELD_LEN) };
    let mut drawn = Zeroizing::new([0; MAX_FIELD_LEN]);
    let bytes = &mut drawn[..C::FIELD_LEN];
    loop {
        fill(bytes)?;
        if let Some(secret) = secret_from_draw::<C>(bytes) {
            return Ok(secret);
        }
    }
}

/// The scalar a draw of the field's length gives, read as Go reads one,
/// or `None` when it must be drawn again.  Go XORs `0x42` into the second
/// byte, which leaves a uniform draw uniform and turns a draw of zeros
/// into a scalar rather than a refusal, so a source that wrote nothing
/// would give a key instead of a loop that never ends
/// (`crypto/internal/fips140/ecdh/ecdh.go:149-152`); and it masks P-521's
/// first byte to the order's one bit (`:154-158`).
fn secret_from_draw<C: NistCurve>(bytes: &mut [u8]) -> Option<C::Secret> {
    if let Some(second) = bytes.get_mut(1) {
        *second ^= 0x42;
    }
    if let Some(top) = bytes.first_mut() {
        *top &= C::TOP_MASK;
    }
    C::secret(bytes)
}

/// One exchange on the NIST curve `C` in progress.
struct NistKeyExchange<C: NistCurve> {
    /// The ephemeral scalar, wiped when the exchange is dropped.
    secret: C::Secret,
    /// Its public key, as the key share carries it.
    pub_key: Vec<u8>,
}

impl<C: NistCurve> NistKeyExchange<C> {
    /// The exchange for an ephemeral scalar.
    fn new(secret: C::Secret) -> NistKeyExchange<C> {
        let pub_key = C::public(&secret);
        NistKeyExchange { secret, pub_key }
    }
}

impl<C: NistCurve> Drop for NistKeyExchange<C> {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl<C: NistCurve> ActiveKeyExchange for NistKeyExchange<C> {
    /// The shared secret with the peer's share, which must be the
    /// uncompressed encoding of a point on the curve.  The tag and the
    /// length are checked here, first, as Go checks them; the point's
    /// coordinates and the curve in [`NistCurve::shared_x`].
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != C::POINT_LEN || peer_pub_key.first() != Some(&0x04) {
            return Err(invalid_share());
        }
        C::shared_x(&self.secret, peer_pub_key)
            .map(SharedSecret::from)
            .ok_or_else(invalid_share)
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn ffdhe_group(&self) -> Option<FfdheGroup<'static>> {
        None
    }

    fn group(&self) -> NamedGroup {
        C::NAME
    }
}

/// The exchange `group` would start with `secret` as its ephemeral key,
/// for tests that need a fixed one: X25519's 32 bytes as drawn, or a
/// NIST curve's scalar at the field's length.  `None` for a scalar the
/// curve refuses, or a group this crate does not implement.
#[cfg(test)]
pub(crate) fn exchange_with(
    group: NamedGroup,
    secret: &[u8],
) -> Option<Box<dyn ActiveKeyExchange>> {
    fn nist<C: NistCurve>(secret: &[u8]) -> Option<Box<dyn ActiveKeyExchange>> {
        Some(Box::new(NistKeyExchange::<C>::new(C::secret(secret)?)))
    }
    match group {
        NamedGroup::X25519 => Some(Box::new(X25519KeyExchange::new(Zeroizing::new(
            <[u8; 32]>::try_from(secret).ok()?,
        )))),
        NamedGroup::secp256r1 => nist::<p256::NistP256>(secret),
        NamedGroup::secp384r1 => nist::<p384::NistP384>(secret),
        NamedGroup::secp521r1 => nist::<p521::NistP521>(secret),
        _ => None,
    }
}

#[cfg(test)]
// Test-harness arithmetic over bounded lengths.
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use dcroxide_testutil::unhex;
    use rustls::ProtocolVersion;

    use super::*;

    /// The four groups, with the length of a share and of a secret on each.
    const GROUPS: [(&dyn SupportedKxGroup, usize, usize); 4] = [
        (X25519, 32, 32),
        (SECP256R1, 65, 32),
        (SECP384R1, 97, 48),
        (SECP521R1, 133, 66),
    ];

    /// The X25519 function of RFC 7748 §5, through the exchange.
    fn x25519(scalar: &[u8], u: &[u8]) -> Vec<u8> {
        exchange_with(NamedGroup::X25519, scalar)
            .expect("32 bytes")
            .complete(u)
            .expect("a share of large order")
            .secret_bytes()
            .to_vec()
    }

    /// RFC 7748 §5.2's two test vectors of the X25519 function, the second
    /// with the u-coordinate's top bit set, which the function ignores.
    #[test]
    fn x25519_answers_rfc_7748_section_5_2() {
        for (scalar, u, out) in [
            (
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
                "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
                "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
            ),
            (
                "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
                "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
                "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
            ),
        ] {
            assert_eq!(x25519(&unhex(scalar), &unhex(u)), unhex(out), "{scalar}");
        }
    }

    /// RFC 7748 §5.2's iterated vector, after one and after 1,000
    /// iterations: the scalar and the u-coordinate both start as the base
    /// point's 9, and each round's output is the next round's scalar and
    /// its scalar the next u.  The 1,000,000-iteration value is left out
    /// for its run time.
    #[test]
    fn x25519_answers_rfc_7748_iterated() {
        let mut k = [0; 32];
        k[0] = 9;
        let mut u = k;
        for round in 1..=1_000 {
            let out = x25519(&k, &u);
            u = k;
            k = <[u8; 32]>::try_from(out).expect("32 bytes");
            if round == 1 {
                assert_eq!(
                    k.to_vec(),
                    unhex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
                );
            }
        }
        assert_eq!(
            k.to_vec(),
            unhex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
        );
    }

    /// RFC 7748 §6.1's Diffie-Hellman example: each side's public key, and
    /// the secret each agrees with the other's.
    #[test]
    fn x25519_answers_rfc_7748_section_6_1() {
        let alice = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
        let alice_pub = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
        let bob = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
        let bob_pub = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
        let shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
        for (secret, public, peer) in [(alice, alice_pub, bob_pub), (bob, bob_pub, alice_pub)] {
            let exchange = exchange_with(NamedGroup::X25519, &unhex(secret)).expect("32 bytes");
            assert_eq!(exchange.pub_key(), unhex(public));
            assert_eq!(
                exchange
                    .complete(&unhex(peer))
                    .expect("agreed")
                    .secret_bytes(),
                unhex(shared)
            );
        }
    }

    /// The P-521 vector Go's `crypto/ecdh` tests against
    /// (`crypto/ecdh/ecdh_test.go`), from NIST's CAVS 14.1 ECC CDH
    /// Primitive (SP 800-56A) set, with the two leading zero bytes the
    /// published field elements carry removed, as Go removes them.
    const CAVS_PRIVATE: &str = "017eecc07ab4b329068fba65e56a1f8890aa935e57134ae0ffcce802735151f4eac6564f6ee9974c5e6887a1fefee5743ae2241bfeb95d5ce31ddcb6f9edb4d6fc47";
    const CAVS_PUBLIC: &str = "0400602f9d0cf9e526b29e22381c203c48a886c2b0673033366314f1ffbcba240ba42f4ef38a76174635f91e6b4ed34275eb01c8467d05ca80315bf1a7bbd945f550a501b7c85f26f5d4b2d7355cf6b02117659943762b6d1db5ab4f1dbc44ce7b2946eb6c7de342962893fd387d1b73d7a8672d1f236961170b7eb3579953ee5cdc88cd2d";
    const CAVS_PEER: &str = "0400685a48e86c79f0f0875f7bc18d25eb5fc8c0b07e5da4f4370f3a9490340854334b1e1b87fa395464c60626124a4e70d0f785601d37c09870ebf176666877a2046d01ba52c56fc8776d9e8f5db4f0cc27636d0b741bbe05400697942e80b739884a83bde99e0f6716939e632bc8986fa18dccd443a348b6c3e522497955a4f3c302f676";
    const CAVS_SHARED: &str = "005fc70477c3e63bc3954bd0df3ea0d1f41ee21746ed95fc5e1fdf90930d5e136672d72cc770742d1711c3c3a4c334a0ad9759436a4d3c5bf6e74b9578fac148c831";

    /// The key share and the shared secret match the NIST vector, the
    /// secret's leading zero byte kept.
    #[test]
    fn p521_key_exchange_matches_the_nist_cdh_vector() {
        let exchange =
            exchange_with(NamedGroup::secp521r1, &unhex(CAVS_PRIVATE)).expect("the vector's key");
        assert_eq!(exchange.pub_key(), unhex(CAVS_PUBLIC), "the key share");
        assert_eq!(exchange.group(), NamedGroup::secp521r1);
        let shared = exchange
            .complete(&unhex(CAVS_PEER))
            .expect("the vector's peer key is valid");
        assert_eq!(shared.secret_bytes(), unhex(CAVS_SHARED).as_slice());
    }

    /// For each group, two fresh exchanges draw different keys, each key
    /// share has the group's encoding, and the two agree on a secret of
    /// the group's length.
    #[test]
    fn fresh_exchanges_agree() {
        for (group, share_len, secret_len) in GROUPS {
            let name = group.name();
            let ours = group.start().expect("start ours");
            let theirs = group.start().expect("start theirs");
            assert_eq!(ours.group(), name);
            for share in [ours.pub_key(), theirs.pub_key()] {
                assert_eq!(share.len(), share_len, "{name:?}");
                if name != NamedGroup::X25519 {
                    assert_eq!(share.first(), Some(&0x04), "{name:?}: uncompressed");
                }
            }
            assert_ne!(ours.pub_key(), theirs.pub_key(), "{name:?}: fresh keys");
            let (ours_pub, theirs_pub) = (ours.pub_key().to_vec(), theirs.pub_key().to_vec());
            let a = ours.complete(&theirs_pub).expect("ours completes");
            let b = theirs.complete(&ours_pub).expect("theirs completes");
            assert_eq!(a.secret_bytes(), b.secret_bytes(), "{name:?}");
            assert_eq!(a.secret_bytes().len(), secret_len, "{name:?}");
        }
    }

    /// Whether `exchange` refuses `share` as an invalid key share.
    fn refuses(exchange: Box<dyn ActiveKeyExchange>, share: &[u8]) -> bool {
        matches!(
            exchange.complete(share),
            Err(Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare))
        )
    }

    /// On each NIST curve the compressed form of a valid share, the hybrid
    /// form, the share off the curve, one byte short or long, the
    /// identity's encoding and nothing at all are each refused as an
    /// invalid key share, and the share itself is taken.
    #[test]
    fn the_nist_groups_refuse_all_but_an_uncompressed_point() {
        for (group, _, _) in &GROUPS[1..] {
            let name = group.name();
            let valid = group.start().expect("a peer").pub_key().to_vec();
            let field_len = (valid.len() - 1) / 2;
            let y_is_odd = valid.last().expect("a share") & 1;
            let compressed = [&[0x02 | y_is_odd], &valid[1..=field_len]].concat();
            let hybrid = [&[0x06 | y_is_odd], &valid[1..]].concat();
            let mut off_curve = valid.clone();
            *off_curve.last_mut().expect("a share") ^= 1;
            let long = [&valid[..], &[0]].concat();
            let short = valid[..valid.len() - 1].to_vec();
            for (label, share) in [
                ("compressed", compressed),
                ("hybrid", hybrid),
                ("off the curve", off_curve),
                ("short", short),
                ("long", long),
                ("identity", vec![0x00]),
                ("empty", Vec::new()),
            ] {
                let exchange = group.start().expect("ours");
                assert!(refuses(exchange, &share), "{name:?}, {label}");
            }
            let exchange = group.start().expect("ours");
            assert!(exchange.complete(&valid).is_ok(), "{name:?}: the share");
        }
    }

    /// X25519 takes any 32 bytes but refuses a share of small order, whose
    /// secret is all zeros: the u-coordinates of small order on the curve
    /// and its twist (0, 1, p - 1 and the curve's two of order eight), 0
    /// and 1 written as p and p + 1, and each with the ignored top bit set.
    /// A share of any other length is refused too.
    #[test]
    fn x25519_refuses_small_order_shares_and_other_lengths() {
        let small_order = [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ];
        for u in small_order {
            let mut share = unhex(u);
            for top in [0, 0x80] {
                share[31] = (share[31] & 0x7f) | top;
                let exchange = X25519.start().expect("ours");
                assert!(refuses(exchange, &share), "{share:02x?}");
            }
        }
        let peer = X25519.start().expect("a peer").pub_key().to_vec();
        for share in [Vec::new(), peer[..31].to_vec(), [&peer[..], &[0]].concat()] {
            assert!(
                refuses(X25519.start().expect("ours"), &share),
                "{share:02x?}"
            );
        }
    }

    /// Each curve's order, big-endian at the field's length.
    const P256_ORDER: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";
    const P384_ORDER: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";
    const P521_ORDER: &str = "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409";

    /// `value` plus `delta`, big-endian at its own length.
    fn plus(value: &[u8], delta: i8) -> Vec<u8> {
        let mut out = value.to_vec();
        let mut carry = i16::from(delta);
        for byte in out.iter_mut().rev() {
            let sum = i16::from(*byte) + carry;
            *byte = sum.rem_euclid(256) as u8;
            carry = sum.div_euclid(256);
        }
        out
    }

    /// The scalars a curve takes are exactly `[1, n)` at the field's
    /// length.
    #[test]
    fn a_scalar_is_taken_only_in_range() {
        fn check<C: NistCurve>(order: &str) {
            let n = unhex(order);
            let zero = vec![0; n.len()];
            let takes = |bytes: &[u8]| C::secret(bytes).is_some();
            assert!(!takes(&zero), "{:?}: zero", C::NAME);
            assert!(takes(&plus(&zero, 1)), "{:?}: one", C::NAME);
            assert!(takes(&plus(&n, -1)), "{:?}: n - 1", C::NAME);
            assert!(!takes(&n), "{:?}: n", C::NAME);
            assert!(!takes(&plus(&n, 1)), "{:?}: n + 1", C::NAME);
            assert!(!takes(&vec![0xff; n.len()]), "{:?}: all ones", C::NAME);
            assert!(!takes(&n[1..]), "{:?}: a byte short", C::NAME);
            assert!(
                !takes(&[&[0][..], &plus(&zero, 1)].concat()),
                "{:?}: a byte long",
                C::NAME
            );
        }
        check::<p256::NistP256>(P256_ORDER);
        check::<p384::NistP384>(P384_ORDER);
        check::<p521::NistP521>(P521_ORDER);
    }

    /// A draw is read as Go reads it: `0x42` XORed into its second byte,
    /// so a draw of zeros is a scalar, and P-521's first byte cut to its
    /// last bit, the rest of its first byte kept on P-256 and P-384.
    /// The bytes as read stay in the buffer, and the order itself, as
    /// read, is refused.
    #[test]
    fn a_draw_is_read_as_go_reads_it() {
        fn check<C: NistCurve>(order: &str) {
            let n = unhex(order);
            for fill in [0x00, 0xff] {
                let mut draw = vec![fill; n.len()];
                assert!(
                    secret_from_draw::<C>(&mut draw).is_some(),
                    "{:?}: {fill:#04x}",
                    C::NAME
                );
                let mut read = vec![fill; n.len()];
                read[0] &= C::TOP_MASK;
                read[1] ^= 0x42;
                assert_eq!(draw, read, "{:?}: {fill:#04x}", C::NAME);
            }
            let mut draw = n.clone();
            draw[0] |= !C::TOP_MASK;
            draw[1] ^= 0x42;
            assert!(
                secret_from_draw::<C>(&mut draw).is_none(),
                "{:?}: n",
                C::NAME
            );
            assert_eq!(draw, n, "{:?}: n as read", C::NAME);
        }
        check::<p256::NistP256>(P256_ORDER);
        check::<p384::NistP384>(P384_ORDER);
        check::<p521::NistP521>(P521_ORDER);
    }

    /// The draw loop draws again until a draw reads as a scalar in
    /// `[1, n)`, as Go's does: here one that reads as n, then one that
    /// reads as zero, then one that reads as `0x01` repeated, whose scalar
    /// it returns.  The kernel is stood in for, since it gives a draw the
    /// loop refuses about once in 2^32 on P-256 and far more rarely on
    /// P-384 and P-521.
    #[test]
    fn a_draw_out_of_range_is_drawn_again() {
        fn check<C: NistCurve>(order: &str) {
            let n = unhex(order);
            // What the loop must be handed to read `value`: `0x42` XORed
            // into the second byte, and the bits above P-521's order set,
            // which the read clears.
            let draw_of = |value: &[u8]| {
                let mut draw = value.to_vec();
                draw[0] |= !C::TOP_MASK;
                draw[1] ^= 0x42;
                draw
            };
            let ones = vec![1; n.len()];
            let mut draws = [draw_of(&n), draw_of(&vec![0; n.len()]), draw_of(&ones)].into_iter();
            let secret = ephemeral_secret::<C>(|buf| {
                buf.copy_from_slice(&draws.next().expect("at most three draws"));
                Ok(())
            })
            .unwrap_or_else(|_| panic!("{:?}: the third draw is a scalar", C::NAME));
            assert!(draws.next().is_none(), "{:?}: three draws", C::NAME);
            let want = C::secret(&ones).expect("below the order");
            assert_eq!(C::public(&secret), C::public(&want), "{:?}", C::NAME);
        }
        check::<p256::NistP256>(P256_ORDER);
        check::<p384::NistP384>(P384_ORDER);
        check::<p521::NistP521>(P521_ORDER);
    }

    /// A draw that fails fails the start on each group, with rustls's
    /// `GetRandomFailed`, at the first draw: no key is made from a buffer
    /// the draw did not write.
    #[test]
    fn a_failed_draw_fails_the_start() {
        fn check<C: NistCurve>() {
            let mut draws = 0;
            let drawn = ephemeral_secret::<C>(|_| {
                draws += 1;
                Err(GetRandomFailed)
            });
            assert!(matches!(drawn, Err(GetRandomFailed)), "{:?}", C::NAME);
            assert_eq!(draws, 1, "{:?}", C::NAME);
        }
        assert!(matches!(
            x25519_ephemeral_secret(|_| Err(GetRandomFailed)),
            Err(GetRandomFailed)
        ));
        check::<p256::NistP256>();
        check::<p384::NistP384>();
        check::<p521::NistP521>();
    }

    /// Each group names itself as ring's does, in `Debug` too, offers no
    /// finite-field group, claims no FIPS validation and serves both TLS
    /// versions; P-521 included, which ring lacks.
    #[test]
    fn each_group_names_itself_as_rings_do() {
        for ((group, _, _), (name, debug)) in GROUPS.into_iter().zip([
            (NamedGroup::X25519, "X25519"),
            (NamedGroup::secp256r1, "secp256r1"),
            (NamedGroup::secp384r1, "secp384r1"),
            (NamedGroup::secp521r1, "secp521r1"),
        ]) {
            assert_eq!(group.name(), name);
            assert_eq!(format!("{group:?}"), debug);
            assert!(group.ffdhe_group().is_none(), "{debug}");
            assert!(!group.fips(), "{debug}");
            for version in [ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3] {
                assert!(group.usable_for_version(version), "{debug}, {version:?}");
            }
            let exchange = group.start().expect("started");
            assert_eq!(exchange.group(), name);
            assert!(exchange.ffdhe_group().is_none(), "{debug}");
        }
    }
}
