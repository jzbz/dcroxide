//! Replay of dcrd's own `--maxpeers` / `--maxsameip` arithmetic.
//!
//! `tests/data/srvtargetout_vectors.txt` was dumped by an in-package Go
//! test run against the parity pin (036b7090) whose expressions are
//! copied verbatim from `server.go` and `internal/connmgr/connmanager.go`,
//! so each row is dcrd's own arithmetic rather than a second opinion
//! about it.  Neither dcrd nor this port validates the two flags, so
//! every value below -- including the negatives and the ones past
//! `2^32` -- is reachable from the command line.
//!
//! The point of the file is QK-0014: dcrd derives an outbound target
//! from `--maxpeers` TWICE, in signed and unsigned space, and the two
//! disagree in opposite directions depending on the input.  A port that
//! computes it once, however carefully, is wrong for one of them.

use dcroxide_node::{max_peers_is_startable, netsync_max_outbound_peers, server_target_outbound};

/// dcrd `internal/connmgr/connmanager.go:2299-2302`: connmgr.New's own
/// clamp, applied to whatever target the server handed it.  Replayed
/// here because it is what makes the server-level value observable.
fn connmgr_effective_target(target_outbound: u32, max_normal_conns: u32) -> u32 {
    const CONNMGR_DEFAULT_TARGET_OUTBOUND: u32 = 8;
    let mut t = target_outbound;
    if t == 0 {
        t = CONNMGR_DEFAULT_TARGET_OUTBOUND;
    }
    t.min(max_normal_conns)
}

/// dcrd `server.go:1016-1021`: the mix-capable want and the rejection
/// predicate it feeds, both `uint32` arithmetic that WRAPS upstream.
/// `wrapping_add` is deliberate -- Rust would trap in a debug build
/// where Go silently wraps, and trapping is the divergence.
fn mix_capable(target_outbound: u32, num_outbound: u32) -> (u32, bool) {
    const DEFAULT_WANT_MIX_CAPABLE_OUTBOUND: u32 = 3;
    let mut want = DEFAULT_WANT_MIX_CAPABLE_OUTBOUND;
    if target_outbound < want {
        want = target_outbound;
    }
    (want, num_outbound.wrapping_add(want) >= target_outbound)
}

#[test]
fn target_outbound_arithmetic_matches_dcrd() {
    let text = include_str!("data/srvtargetout_vectors.txt");
    let mut rows = 0usize;
    let (mut tout, mut tsip, mut tmix, mut mpchan) = (0usize, 0usize, 0usize, 0usize);

    for (lineno, line) in text.lines().enumerate() {
        let lineno = lineno + 1;
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split('|').collect();
        rows += 1;
        match f[0] {
            // tout|maxpeers|server|netsync|maxnormal|effective|majority|wantmix
            "tout" => {
                assert_eq!(f.len(), 8, "line {lineno}: field count");
                let max_peers: i64 = f[1].parse().expect("maxpeers");
                let want_server: u32 = f[2].parse().expect("server target");
                let want_netsync: u64 = f[3].parse().expect("netsync target");
                let want_normal: u32 = f[4].parse().expect("max normal conns");
                let want_effective: u32 = f[5].parse().expect("effective target");
                let want_majority: u32 = f[6].parse().expect("majority");
                let want_want_mix: u32 = f[7].parse().expect("want mix capable");

                let server = server_target_outbound(max_peers);
                assert_eq!(server, want_server, "line {lineno}: server target");

                let netsync = netsync_max_outbound_peers(max_peers);
                assert_eq!(netsync, want_netsync, "line {lineno}: netsync target");

                // dcrd `server.go:4283`: a truncating cast, not a clamp.
                let normal = max_peers as u32;
                assert_eq!(normal, want_normal, "line {lineno}: max normal conns");

                assert_eq!(
                    connmgr_effective_target(server, normal),
                    want_effective,
                    "line {lineno}: effective connmgr target",
                );

                // dcrd `server.go:2582`.  The server target is bounded by 8,
                // so this can never overflow -- checked arithmetic, so the
                // test fails loudly rather than wrapping if that ever stops
                // being true.
                // Spelled as dcrd spells it, not as `div_ceil`: the point
                // of the row is that this is the upstream expression.
                #[allow(clippy::manual_div_ceil)]
                let majority = ((server * 60) + 99) / 100;
                assert_eq!(majority, want_majority, "line {lineno}: majority");

                let (want_mix, _) = mix_capable(server, 0);
                assert_eq!(want_mix, want_want_mix, "line {lineno}: want mix capable");
                tout += 1;
            }
            // tsip|maxsameip|maxconnsperhost
            "tsip" => {
                assert_eq!(f.len(), 3, "line {lineno}: field count");
                let max_same_ip: i64 = f[1].parse().expect("maxsameip");
                let want: u32 = f[2].parse().expect("max conns per host");
                // dcrd `server.go:4284`.
                assert_eq!(max_same_ip as u32, want, "line {lineno}: conns per host");
                tsip += 1;
            }
            // tmix|target|numoutbound|want|needsmore
            "tmix" => {
                assert_eq!(f.len(), 5, "line {lineno}: field count");
                let target: u32 = f[1].parse().expect("target");
                let num_outbound: u32 = f[2].parse().expect("num outbound");
                let want_want: u32 = f[3].parse().expect("want");
                let want_needs: bool = f[4].parse().expect("needs more");
                let (want, needs) = mix_capable(target, num_outbound);
                assert_eq!(want, want_want, "line {lineno}: want mix capable");
                assert_eq!(needs, want_needs, "line {lineno}: needs more mix capable");
                tmix += 1;
            }
            // mpchan|maxpeers|outcome -- what dcrd's newServer does with
            // `make(chan relayMsg, cfg.MaxPeers)` at `server.go:3931-3932`,
            // 200 lines before either target is computed.  `panic:` is Go's
            // `makechan: size out of range`, `fatal` an unrecoverable
            // out-of-memory death, `ok:<cap>:<cap>` an allocation that
            // succeeded.  The port allocates nothing here, so these rows
            // record the SPECIFICATION's behaviour rather than the port's;
            // the assertion below is about which inputs dcrd survives.
            "mpchan" => {
                assert_eq!(f.len(), 3, "line {lineno}: field count");
                let max_peers: i64 = f[1].parse().expect("maxpeers");
                let outcome = f[2];
                let survives = outcome.starts_with("ok:");
                assert_eq!(
                    survives,
                    (0..=125).contains(&max_peers),
                    "line {lineno}: dcrd survivability for --maxpeers={max_peers}",
                );
                // The port refuses exactly where dcrd's `makechan` rejects
                // the capacity itself, which is both disjuncts of one `if`
                // (`runtime/chan.go:87`) -- the negative one, and the one
                // past `maxAlloc-hchanSize`.  A `fatal` row is the band
                // between them, where the capacity is accepted and the
                // allocation is what fails; that threshold is the host's
                // rather than the flag's, so those are expected NOT to be
                // refused.  This assertion carried an `&& max_peers < 0`
                // guard that exempted the one `panic:` row sitting on a
                // positive value, which is how the divergence stayed
                // invisible while its counterexample sat in the fixture.
                assert_eq!(
                    max_peers_is_startable(max_peers),
                    !outcome.starts_with("panic:"),
                    "line {lineno}: startability for --maxpeers={max_peers}",
                );
                if survives {
                    assert!(
                        max_peers_is_startable(max_peers),
                        "line {lineno}: dcrd starts here, so the port must too",
                    );
                    // The capacity is the flag, unaltered.
                    assert_eq!(
                        outcome,
                        format!("ok:{max_peers}:{max_peers}"),
                        "line {lineno}: channel capacity",
                    );
                    // Everywhere dcrd survives, the two targets agree -- which
                    // is exactly why the disagreement went unnoticed upstream.
                    assert_eq!(
                        u64::from(server_target_outbound(max_peers)),
                        netsync_max_outbound_peers(max_peers),
                        "line {lineno}: the two targets must agree wherever dcrd lives",
                    );
                }
                mpchan += 1;
            }
            other => panic!("line {lineno}: unknown row kind {other:?}"),
        }
    }

    assert_eq!(rows, 71, "vector count");
    assert_eq!((tout, tsip, tmix, mpchan), (19, 7, 24, 21), "row kinds");
}

/// The whole point of QK-0014, stated as an assertion rather than as
/// prose: for `--maxpeers=-1` dcrd's two targets are 8 and `u64::MAX`,
/// and for `--maxpeers=2^32` they are 0 and 8.  They disagree in
/// opposite directions, so neither can be derived from the other.
#[test]
fn the_two_targets_disagree_in_both_directions() {
    assert_eq!(server_target_outbound(-1), 8);
    assert_eq!(netsync_max_outbound_peers(-1), u64::MAX);

    assert_eq!(server_target_outbound(4_294_967_296), 0);
    assert_eq!(netsync_max_outbound_peers(4_294_967_296), 8);

    // And they agree everywhere a sane operator would ever look, which
    // is why computing only one of them survives review.
    for max_peers in [0i64, 1, 7, 8, 9, 125, 1000] {
        assert_eq!(
            u64::from(server_target_outbound(max_peers)),
            netsync_max_outbound_peers(max_peers),
            "the two targets should agree for --maxpeers={max_peers}",
        );
    }
}
