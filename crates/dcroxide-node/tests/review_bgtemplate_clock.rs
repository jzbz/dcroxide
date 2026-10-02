// SPDX-License-Identifier: ISC
//! The background template generator's is-current gate reads the
//! server's median-adjusted time, as dcrd's does: the generator's
//! `IsCurrent` is `s.syncManager.IsCurrent`, which asks the chain, and
//! the chain's `isCurrent` compares the tip against
//! `b.timeSource.AdjustedTime()`.  The port used to pass the wall clock,
//! so a node whose peers put the network clock behind its own could
//! refuse to build templates (and to set the shared is-current flag)
//! while dcrd would, and the reverse when they put it ahead.
//!
//! The median time source is process-wide, so this binary holds a single
//! test that owns it.

// Test-harness arithmetic over bounded values.
#![allow(clippy::arithmetic_side_effects)]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dcroxide_blockchain::process::Chain;
use dcroxide_database::{Database, Options};
use dcroxide_mining::cpuminer::{SpeedStats, solve_block};
use dcroxide_mining::{BlkTmplGenerator, ExtraNonces, MiningPolicy};
use dcroxide_node::bgtemplate::{NodeRpcBlockTemplater, start_generator};
use dcroxide_node::mediantime::{adjusted_time_unix, server_time_source};
use dcroxide_node::mining::{NodeTemplateChain, NodeTemplateTxSource};
use dcroxide_rpc::server::RpcBlockTemplater;

/// A fresh regnet chain holding only the genesis block.
///
/// The test mines its own extension block over genesis rather than over
/// a prefix of dcrd's `fullblocktests.Generate` battery: the battery's
/// first block is stamped with its generation time, so a battery prefix
/// has a median time at that moment, and the extension block -- which
/// must be more than a day older than the wall clock -- could not land
/// after it until a day after each regeneration.  The regnet genesis
/// timestamp (2018-10-03) is older than any stamp the test chooses.
fn regnet_chain() -> (tempfile::TempDir, Arc<Mutex<Chain>>) {
    let params = dcroxide_chaincfg::regnet_params();
    let dir = tempfile::tempdir().expect("temp dir");
    let opts = Options::new(dir.path().join("blocks"), params.net.0);
    let db = Database::create(&opts).expect("create database");
    let chain = Arc::new(Mutex::new(
        Chain::open(db, &params, params.assume_valid, false, 0).expect("open chain"),
    ));
    (dir, chain)
}

/// A regnet premine pay-to-pubkey-hash payout used as the mining
/// address.
fn mining_address() -> dcroxide_txscript::stdaddr::Address {
    let params = dcroxide_chaincfg::regnet_params();
    dcroxide_txscript::stdaddr::decode_address("RsKrWb7Vny1jnzL1sDLgKTAteh9RZcRr5g6", &params)
        .expect("mining address")
}

/// The mining policy the daemon builds from its configuration.
fn mining_policy() -> MiningPolicy {
    let params = dcroxide_chaincfg::regnet_params();
    MiningPolicy {
        block_max_size: params.maximum_block_sizes[0] as u32,
        tx_min_free_fee: 10000,
        aggressive_mining: true,
    }
}

/// The wall clock as unix seconds.
fn wall_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs() as i64
}

#[test]
fn the_generator_gate_reads_the_median_adjusted_time() {
    const DAY_SECS: i64 = 24 * 60 * 60;
    let params = dcroxide_chaincfg::regnet_params();

    // Five peers report clocks 69 minutes behind this one, inside dcrd's
    // 70-minute cap, so the median moves the adjusted time 69 minutes
    // into the past.
    let behind = 69 * 60;
    let wall = wall_now();
    for i in 0..5 {
        server_time_source().add_time_sample(&format!("10.0.0.{i}:9108"), wall - behind);
    }
    let offset = server_time_source().offset_secs();
    assert!(
        (-behind - 2..=-behind).contains(&offset),
        "the median offset applies: {offset}"
    );

    // Extend the genesis chain with a block stamped 23h40m before the
    // adjusted time: within a day of the adjusted time, so current by
    // dcrd's rule, but more than a day before the wall clock.  dcrd's
    // `MiningTimeOffset` moves the template timestamp into the past by
    // that many seconds, from the later of the adjusted time and one
    // second after the tip's median time; genesis keeps that the
    // adjusted time.
    let (_dir, chain) = regnet_chain();
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &params,
        false,
        100,
        10000,
        false,
        false,
    );
    let mut builder = BlkTmplGenerator::new(
        mining_policy(),
        &params,
        NodeTemplateChain::new(Arc::clone(&chain), params.clone()),
        NodeTemplateTxSource::new(Arc::clone(&tx_pool)),
        23 * 60 * 60 + 40 * 60,
    );
    let address = mining_address();
    let mut block = builder
        .new_block_template(
            Some(&address),
            &ExtraNonces {
                coinbase: 1,
                treasury: 2,
            },
        )
        .expect("template")
        .expect("a template over genesis")
        .block;
    drop(builder);
    let is_blake3_pow_active = chain
        .lock()
        .expect("chain")
        .is_blake3_pow_agenda_active(&block.header.prev_block, &params)
        .expect("agenda state");
    assert!(
        solve_block(
            &mut block.header,
            &SpeedStats::default(),
            is_blake3_pow_active,
            0,
            &mut |_| {},
            &mut || false,
            &mut || 0,
        ),
        "the regnet proof of work solves"
    );
    let (_, errs) =
        chain
            .lock()
            .expect("chain")
            .process_block(&block, adjusted_time_unix(), &params);
    assert!(errs.is_empty(), "the mined block must accept: {errs:?}");

    // The precondition: current at the adjusted time, stale at the wall
    // clock, with a wide margin either side.
    let tip_time = i64::from(block.header.timestamp);
    let wall = wall_now();
    assert!(
        tip_time < wall - DAY_SECS - 10 * 60,
        "stale by the wall clock"
    );
    assert!(
        tip_time > adjusted_time_unix() - DAY_SECS + 10 * 60,
        "current by the adjusted time"
    );
    {
        let chain = chain.lock().expect("chain");
        assert!(
            !chain.is_current_at(wall),
            "the chain is stale at the wall clock"
        );
        assert!(
            chain.is_current_at(adjusted_time_unix()),
            "the chain is current at the adjusted time"
        );
    }

    // A generator that may not mine unsynced waits for the netsync gate,
    // which opens only when the chain is current at the adjusted time.
    let policy = mining_policy();
    let generator = start_generator(
        Arc::clone(&chain),
        Arc::clone(&tx_pool),
        params.clone(),
        vec![mining_address()],
        policy.clone(),
        0,
        false,
        dcroxide_node::sync::SyncGate::unsynced(),
        None,
        None,
    );
    let templater = NodeRpcBlockTemplater::new(
        generator.current_handle(),
        generator.subscribers_handle(),
        generator.sink(),
        Arc::clone(&chain),
        Arc::clone(&tx_pool),
        params.clone(),
        policy,
        0,
    );

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match templater.current_template() {
            Ok(Some(template)) => {
                assert_eq!(
                    template.header.height, 2,
                    "the generator builds on the new tip"
                );
                break;
            }
            Ok(None) => {}
            Err(err) => panic!("template errored: {err}"),
        }
        assert!(
            Instant::now() < deadline,
            "the generator must treat the chain as current at the median-adjusted time"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    generator.shutdown();
}
