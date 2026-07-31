// SPDX-License-Identifier: ISC
//! Differential test: the full canonical parameter dump of all four
//! networks, byte for byte, against the identical dump emitted by dcrd's
//! own `chaincfg` (module v3.3.0, as pinned by release-v2.1.5) through the
//! oracle. This covers every `Params` field including the serialized
//! genesis block, the complete deployment/vote/choice definitions, and a
//! BLAKE-256 commitment to the full block-one ledgers.

use dcroxide_chaincfg::{mainnet_params, regnet_params, simnet_params, testnet3_params};
use dcroxide_testutil::{oracle_or_skip, unhex};

#[test]
fn params_dumps_match_dcrd() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };

    let networks = [
        ("mainnet", mainnet_params()),
        ("testnet3", testnet3_params()),
        ("simnet", simnet_params()),
        ("regnet", regnet_params()),
    ];
    for (name, params) in networks {
        let theirs_hex = oracle.call_ok("chaincfg_dump", name.as_bytes());
        let theirs = String::from_utf8(unhex(&theirs_hex)).expect("oracle dump is UTF-8");

        // dcrd adopted the dcr-seed.jz.bz mainnet seeder in `b9b64533`,
        // so it is no longer a dcroxide addition and this exclusion is
        // now pure pin skew: the oracle links `chaincfg/v3 v3.3.0`,
        // which predates that commit, so dcrd's dump still lacks the
        // entry while ours carries it.
        //
        // DELETE the filter below when the oracle's chaincfg dependency
        // moves past `b9b64533` — at that point dcrd's dump gains the
        // seeder, the filter strips it from ours alone, and this test
        // starts failing on a line that is actually in agreement.
        if name == "mainnet" {
            assert!(
                params.seeders.contains(&"dcr-seed.jz.bz"),
                "mainnet params must carry the seeder"
            );
        }
        let ours: String = params
            .dump()
            .lines()
            .filter(|line| *line != "seeder=dcr-seed.jz.bz")
            .map(|line| format!("{line}\n"))
            .collect();
        if ours != theirs {
            // Report the first differing line rather than two huge blobs.
            for (i, (a, b)) in ours.lines().zip(theirs.lines()).enumerate() {
                assert_eq!(a, b, "{name}: dump line {} differs (ours vs dcrd)", i + 1);
            }
            panic!(
                "{name}: dump line count differs: ours {} vs dcrd {}",
                ours.lines().count(),
                theirs.lines().count(),
            );
        }
    }
}
