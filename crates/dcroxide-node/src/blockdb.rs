// SPDX-License-Identifier: ISC
//! The flat-file blockchain dump behind `--dumpblockchain` (dcrd
//! `blockdb.go`'s `dumpBlockChain`): every main-chain block after the
//! genesis as a `<network u32><length u32><serialized block>` record,
//! little-endian, which is the same format [`crate::addblock`] reads
//! back.

// Heights and record lengths are bounded by the chain itself.
#![allow(clippy::arithmetic_side_effects)]

use std::io::Write;
use std::time::Instant;

use dcroxide_wire::MsgBlock;

use crate::progresslog::ProgressLogger;

/// Write the main chain to `path` (dcrd `dumpBlockChain`).
///
/// `log` receives `(subsystem, line)`: dcrd emits the opening line and
/// the progress lines under DCRD and the closing line under SRVR
/// (`blockdb.go:191-249`), so the caller can route them the same way.
///
/// The genesis block is excluded, matching dcrd's loop from height 1.
pub fn dump_block_chain(
    net: u32,
    path: &str,
    tip_height: i64,
    block_by_height: &dyn Fn(i64) -> Option<MsgBlock>,
    log: &mut dyn FnMut(&str, String),
) -> Result<(), String> {
    log(
        "DCRD",
        format!("Writing the blockchain to flat file {path:?}.  This might take a while..."),
    );

    let mut progress = ProgressLogger::new("Wrote");
    let mut file = std::fs::File::create(path).map_err(|e| e.to_string())?;
    let net = net.to_le_bytes();

    for height in 1..=tip_height {
        // `Chain::block_by_height` collapses "not on the main chain"
        // and "block data unavailable" into one `None`, where dcrd
        // separates `errNotInMainChainByHeight` from a database error.
        // dcrd's not-in-chain text is the closer of the two, and this
        // is unreachable for 1..=tip on a node that does not prune.
        let block =
            block_by_height(height).ok_or_else(|| format!("no block at height {height} exists"))?;
        let serialized = block.serialize();

        file.write_all(&net).map_err(|e| e.to_string())?;
        file.write_all(&(serialized.len() as u32).to_le_bytes())
            .map_err(|e| e.to_string())?;
        file.write_all(&serialized).map_err(|e| e.to_string())?;

        let h = block.header.height;
        let force = i64::from(h) >= tip_height;
        let pct = if tip_height == 0 {
            0.0
        } else {
            f64::from(h) / tip_height as f64 * 100.0
        };
        if let Some(line) = progress.log_block_progress_at(
            block.transactions.len() as u64,
            count_stake(&block, dcroxide_stake::TxType::SStx),
            count_stake(&block, dcroxide_stake::TxType::SSGen),
            count_stake(&block, dcroxide_stake::TxType::SSRtx),
            h,
            force,
            pct,
            Instant::now(),
        ) {
            log("DCRD", line);
        }
    }

    log(
        "SRVR",
        format!("Successfully dumped the blockchain ({tip_height} blocks) to {path}."),
    );
    Ok(())
}

/// The number of stake transactions of the given type in the block.
fn count_stake(block: &MsgBlock, want: dcroxide_stake::TxType) -> u64 {
    block
        .stransactions
        .iter()
        .filter(|tx| dcroxide_stake::determine_tx_type(tx) == want)
        .count() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each record is the network, the length, then the block, all
    /// little-endian, and the genesis is excluded.
    #[test]
    fn records_carry_the_network_length_and_block() {
        let params = dcroxide_chaincfg::regnet_params();
        let block = params.genesis_block.clone();
        let serialized = block.serialize();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("blocks.dat");
        let path_str = path.to_str().expect("path");

        let mut lines: Vec<(String, String)> = Vec::new();
        dump_block_chain(
            params.net.0,
            path_str,
            2,
            &|_h| Some(block.clone()),
            &mut |sub, line| lines.push((sub.to_string(), line)),
        )
        .expect("dump");

        let raw = std::fs::read(&path).expect("read back");
        assert_eq!(
            raw.len(),
            2 * (8 + serialized.len()),
            "two records, each 4+4 bytes of header plus the block"
        );
        for rec in raw.chunks(8 + serialized.len()) {
            assert_eq!(&rec[0..4], &params.net.0.to_le_bytes(), "network");
            assert_eq!(
                u32::from_le_bytes(rec[4..8].try_into().expect("len")) as usize,
                serialized.len(),
                "length"
            );
            let (round, _) = MsgBlock::from_bytes(&rec[8..]).expect("round trip");
            assert_eq!(round.header.block_hash(), block.header.block_hash());
        }

        assert_eq!(lines.first().expect("opening line").0, "DCRD");
        let last = lines.last().expect("closing line");
        assert_eq!(last.0, "SRVR");
        assert!(
            last.1
                .contains("Successfully dumped the blockchain (2 blocks)"),
            "closing line: {}",
            last.1
        );
    }

    /// A height the chain cannot serve stops the dump with dcrd's text.
    #[test]
    fn a_missing_height_is_reported() {
        let params = dcroxide_chaincfg::regnet_params();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("blocks.dat");
        let err = dump_block_chain(
            params.net.0,
            path.to_str().expect("path"),
            3,
            &|h| {
                if h == 1 {
                    Some(params.genesis_block.clone())
                } else {
                    None
                }
            },
            &mut |_, _| {},
        )
        .expect_err("a missing height must stop the dump");
        assert_eq!(err, "no block at height 2 exists");
    }
}
