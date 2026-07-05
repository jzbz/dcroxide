// SPDX-License-Identifier: ISC
//! Differential tests: our standalone consensus functions vs dcrd's
//! blockchain/standalone, live through the oracle, over random merkle
//! trees, transactions, compact difficulty bits (including negative and
//! beyond-256-bit encodings), ASERT parameters across all four
//! networks, the full subsidy surface against the real chain parameters,
//! treasury spend windows, and both proof-of-work header hashes.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_chaincfg::{Params, mainnet_params, regnet_params, simnet_params, testnet3_params};
use dcroxide_chainhash::Hash;
use dcroxide_standalone as standalone;
use dcroxide_testutil::{Oracle, SplitMix64, hex, oracle_or_skip, unhex};
use dcroxide_wire::{BlockHeader, MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};
use standalone::{BigInt, SubsidyCache, SubsidyParams, SubsidySplitVariant};

fn dump(oracle: &mut Oracle, cmd: &str, req: &[u8]) -> String {
    let result = oracle.call_ok(cmd, req);
    String::from_utf8(unhex(&result)).expect("dump is UTF-8")
}

fn ok_or_kind(r: Result<(), standalone::RuleError>) -> String {
    match r {
        Ok(()) => "ok".to_string(),
        Err(e) => e.kind.kind_name().to_string(),
    }
}

fn random_hash(rng: &mut SplitMix64) -> Hash {
    let mut h = [0u8; 32];
    rng.fill(&mut h);
    Hash(h)
}

/// A hash biased toward small (PoW-satisfying) values.
fn biased_pow_hash(rng: &mut SplitMix64) -> Hash {
    let mut h = random_hash(rng);
    // The hash is little endian, so its most significant bytes are at
    // the end; zero a random count of them to bias the value low.
    let zeroed = rng.below(33) as usize;
    for b in &mut h.0[32 - zeroed..] {
        *b = 0;
    }
    h
}

fn random_tx(rng: &mut SplitMix64) -> MsgTx {
    let mut tx = MsgTx {
        ser_type: TxSerializeType::Full,
        version: rng.below(5) as u16,
        tx_in: Vec::new(),
        tx_out: Vec::new(),
        lock_time: rng.next_u64() as u32,
        expiry: rng.next_u64() as u32,
    };
    // Sometimes a coinbase/treasury-spend flavored null outpoint first
    // input, otherwise plain funding inputs; occasionally a duplicate.
    let coinbase_like = rng.below(2) == 0;
    let n_in = if coinbase_like {
        1
    } else {
        rng.below(3) as usize + 1
    };
    for i in 0..n_in {
        let (hash, index) = if coinbase_like {
            (Hash::ZERO, u32::MAX)
        } else if i > 0 && rng.below(5) == 0 {
            // Duplicate the previous outpoint to hit the sanity check.
            let prev = &tx.tx_in[i - 1].previous_out_point;
            (prev.hash, prev.index)
        } else {
            (random_hash(rng), rng.below(4) as u32)
        };
        let sig_len = rng.below(20) as usize;
        let sig_script = match rng.below(4) {
            0 => Vec::new(),
            // A TSpend-shaped ending to exercise the treasury-spend
            // heuristic in the coinbase identification.
            1 => {
                let mut s = rng.bytes(sig_len);
                s.push(0xc2);
                s
            }
            _ => rng.bytes(sig_len + 1),
        };
        tx.tx_in.push(TxIn {
            previous_out_point: OutPoint {
                hash,
                index,
                tree: (rng.below(3) as i8) - 1,
            },
            sequence: 0xffff_ffff,
            value_in: rng.below(1 << 40) as i64,
            block_height: 0,
            block_index: 0,
            signature_script: sig_script,
        });
    }
    for i in 0..(rng.below(3) as usize + 1) {
        let pk_script = match rng.below(6) {
            // Treasury-flavored scripts.
            0 => vec![0xc1],
            1 => {
                let mut s = vec![0x6a, 0x0c];
                s.extend(rng.bytes(12));
                s
            }
            2 => {
                let mut s = vec![0x6a, 0x20];
                s.extend(rng.bytes(32));
                s
            }
            3 => {
                let mut s = vec![0xc3];
                s.extend(rng.bytes(24));
                s
            }
            4 if i == 0 => Vec::new(),
            _ => {
                let n = rng.below(40) as usize + 1;
                rng.bytes(n)
            }
        };
        // Values biased around the sanity boundaries.
        let value = match rng.below(6) {
            0 => -(rng.below(1 << 30) as i64),
            1 => 21_000_000i64 * 100_000_000,
            2 => 21_000_000i64 * 100_000_000 + rng.below(1000) as i64,
            3 => 21_000_000i64 * 100_000_000 - rng.below(1000) as i64,
            _ => rng.below(1 << 40) as i64,
        };
        tx.tx_out.push(TxOut {
            value,
            version: 0,
            pk_script,
        });
    }
    tx
}

#[test]
fn merkle_differential() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("standalone-merkle-differential");

    const ROUNDS: usize = 300;
    for round in 0..ROUNDS {
        let n_leaves = rng.below(40) as usize;
        let leaves: Vec<Hash> = (0..n_leaves).map(|_| random_hash(&mut rng)).collect();
        // Occasionally out of range to hit the empty-proof path.
        let leaf_index = rng.below(n_leaves as u64 + 2) as u32;

        let mut ours = String::new();
        let root = standalone::calc_merkle_root(&leaves);
        ours.push_str(&format!("root={root}\n"));
        let proof = standalone::generate_inclusion_proof(&leaves, leaf_index);
        for h in &proof {
            ours.push_str(&format!("proof={h}\n"));
        }
        if (leaf_index as usize) < n_leaves {
            let verified = standalone::verify_inclusion_proof(
                &root,
                &leaves[leaf_index as usize],
                leaf_index,
                &proof,
            );
            ours.push_str(&format!("verified={verified}\n"));
        }

        let mut req = Vec::new();
        req.extend_from_slice(&leaf_index.to_be_bytes());
        req.extend_from_slice(&(n_leaves as u32).to_be_bytes());
        for leaf in &leaves {
            req.extend_from_slice(&leaf.0);
        }
        let theirs = dump(&mut oracle, "standalone_merkle", &req);

        assert_eq!(
            ours, theirs,
            "merkle divergence at round {round}: n={n_leaves} idx={leaf_index}"
        );
    }
}

#[test]
fn tx_merkle_differential() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("standalone-tx-merkle-differential");

    const ROUNDS: usize = 150;
    for round in 0..ROUNDS {
        let n_regular = rng.below(6) as usize;
        let n_stake = rng.below(6) as usize;
        let regular: Vec<MsgTx> = (0..n_regular).map(|_| random_tx(&mut rng)).collect();
        let stake: Vec<MsgTx> = (0..n_stake).map(|_| random_tx(&mut rng)).collect();

        let ours = format!(
            "regular={}\nstake={}\ncombined={}\n",
            standalone::calc_tx_tree_merkle_root(&regular),
            standalone::calc_tx_tree_merkle_root(&stake),
            standalone::calc_combined_tx_tree_merkle_root(&regular, &stake),
        );

        let mut req = Vec::new();
        req.extend_from_slice(&(n_regular as u16).to_be_bytes());
        for tx in regular.iter().chain(&stake) {
            let ser = tx.serialize();
            req.extend_from_slice(&(ser.len() as u32).to_be_bytes());
            req.extend_from_slice(&ser);
        }
        let theirs = dump(&mut oracle, "standalone_tx_merkle", &req);

        assert_eq!(
            ours, theirs,
            "tx merkle divergence at round {round}: regular={n_regular} stake={n_stake}"
        );
    }
}

/// Random compact difficulty bits, biased across exponents, sign, and
/// mantissa shapes, including encodings far beyond 256 bits.
fn random_bits(rng: &mut SplitMix64) -> u32 {
    match rng.below(4) {
        0 => rng.next_u64() as u32,
        1 => {
            // Realistic difficulty range.
            let exponent = rng.below(8) as u32 + 0x18;
            let mantissa = rng.below(1 << 23) as u32;
            exponent << 24 | mantissa
        }
        2 => {
            // Small/negative encodings.
            let exponent = rng.below(6) as u32;
            let sign = (rng.below(2) as u32) << 23;
            let mantissa = rng.below(1 << 23) as u32;
            exponent << 24 | sign | mantissa
        }
        _ => {
            // Huge exponents (values beyond 256 bits).
            let exponent = rng.below(256) as u32;
            let sign = u32::from(rng.below(4) == 0) << 23;
            let mantissa = rng.below(1 << 23) as u32;
            exponent << 24 | sign | mantissa
        }
    }
}

#[test]
fn pow_differential() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("standalone-pow-differential");

    let limits: Vec<BigInt> = [
        mainnet_params().pow_limit,
        testnet3_params().pow_limit,
        simnet_params().pow_limit,
        regnet_params().pow_limit,
    ]
    .iter()
    .map(|l| BigInt::from_bytes_be(standalone::Sign::Plus, &l.to_be_bytes()))
    .collect();

    const ROUNDS: usize = 400;
    for round in 0..ROUNDS {
        let bits = random_bits(&mut rng);
        let pow_limit = &limits[rng.below(limits.len() as u64) as usize];
        let pow_hash = biased_pow_hash(&mut rng);

        let target = standalone::compact_to_big(bits);
        let ours = format!(
            "target={}\ncompact={:08x}\nwork={}\nhashtobig={}\nrange={}\nhash={}\npow={}\n",
            standalone::big_to_string(&target),
            standalone::big_to_compact(&target),
            standalone::big_to_string(&standalone::calc_work(bits)),
            standalone::big_to_string(&standalone::hash_to_big(&pow_hash)),
            ok_or_kind(standalone::check_proof_of_work_range(bits, pow_limit)),
            ok_or_kind(standalone::check_proof_of_work_hash(&pow_hash, bits)),
            ok_or_kind(standalone::check_proof_of_work(&pow_hash, bits, pow_limit)),
        );

        let mut req = Vec::new();
        req.extend_from_slice(&bits.to_be_bytes());
        req.extend_from_slice(&big_to_be32(pow_limit));
        req.extend_from_slice(&pow_hash.0);
        let theirs = dump(&mut oracle, "standalone_pow", &req);

        assert_eq!(
            ours, theirs,
            "pow divergence at round {round}: bits={bits:08x}"
        );
    }
}

/// Serialize a non-negative big integer to exactly 32 big-endian bytes.
fn big_to_be32(n: &BigInt) -> [u8; 32] {
    let (_, bytes) = n.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

#[test]
fn asert_differential() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("standalone-asert-differential");

    let networks = [
        mainnet_params(),
        testnet3_params(),
        simnet_params(),
        regnet_params(),
    ];

    const ROUNDS: usize = 400;
    for round in 0..ROUNDS {
        let params = &networks[rng.below(networks.len() as u64) as usize];
        let pow_limit =
            BigInt::from_bytes_be(standalone::Sign::Plus, &params.pow_limit.to_be_bytes());
        let start_bits = params.work_diff_v2_blake3_start_bits;
        let target_secs = params.target_time_per_block_secs;
        let half_life = params.work_diff_v2_half_life_secs;

        // Height deltas across realistic and extreme schedules; time
        // deltas around the ideal schedule, up to many half lives off.
        let height_delta = rng.below(500_000) as i64;
        let ideal = height_delta * target_secs;
        let offset = rng.below((half_life * 40) as u64 + 1) as i64 - (half_life * 20);
        let time_delta = ideal.saturating_add(offset);

        let ours = format!(
            "{:08x}",
            standalone::calc_asert_diff(
                start_bits,
                &pow_limit,
                target_secs,
                time_delta,
                height_delta,
                half_life,
            )
        );

        let mut req = Vec::new();
        req.extend_from_slice(&start_bits.to_be_bytes());
        req.extend_from_slice(&big_to_be32(&pow_limit));
        req.extend_from_slice(&(target_secs as u64).to_be_bytes());
        req.extend_from_slice(&(time_delta as u64).to_be_bytes());
        req.extend_from_slice(&(height_delta as u64).to_be_bytes());
        req.extend_from_slice(&(half_life as u64).to_be_bytes());
        let theirs = oracle.call_ok("standalone_asert", &req);

        assert_eq!(
            ours, theirs,
            "ASERT divergence at round {round}: net={} Δh={height_delta} Δt={time_delta}",
            params.name,
        );
    }
}

/// Adapter exposing dcroxide-chaincfg parameters through the
/// SubsidyParams trait, mirroring how dcrd's chaincfg.Params satisfies
/// the Go interface.
struct ChainSubsidyParams(Params);

impl SubsidyParams for ChainSubsidyParams {
    fn block_one_subsidy(&self) -> i64 {
        self.0.block_one_subsidy()
    }
    fn base_subsidy_value(&self) -> i64 {
        self.0.base_subsidy
    }
    fn subsidy_reduction_multiplier(&self) -> i64 {
        self.0.mul_subsidy
    }
    fn subsidy_reduction_divisor(&self) -> i64 {
        self.0.div_subsidy
    }
    fn subsidy_reduction_interval_blocks(&self) -> i64 {
        self.0.subsidy_reduction_interval
    }
    fn work_subsidy_proportion(&self) -> u16 {
        self.0.work_reward_proportion
    }
    fn stake_subsidy_proportion(&self) -> u16 {
        self.0.stake_reward_proportion
    }
    fn treasury_subsidy_proportion(&self) -> u16 {
        self.0.block_tax_proportion
    }
    fn stake_validation_begin_height(&self) -> i64 {
        self.0.stake_validation_height
    }
    fn votes_per_block(&self) -> u16 {
        self.0.tickets_per_block
    }
}

#[test]
fn subsidy_differential() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("standalone-subsidy-differential");

    let nets = ["mainnet", "testnet3", "simnet", "regnet"];
    let mut caches: Vec<SubsidyCache<ChainSubsidyParams>> = vec![
        SubsidyCache::new(ChainSubsidyParams(mainnet_params())),
        SubsidyCache::new(ChainSubsidyParams(testnet3_params())),
        SubsidyCache::new(ChainSubsidyParams(simnet_params())),
        SubsidyCache::new(ChainSubsidyParams(regnet_params())),
    ];

    const ROUNDS: usize = 300;
    for round in 0..ROUNDS {
        let net_idx = rng.below(nets.len() as u64) as usize;
        let cache = &mut caches[net_idx];

        let interval = cache.params().subsidy_reduction_interval_blocks();
        let svh = cache.params().stake_validation_begin_height();
        let votes_per_block = cache.params().votes_per_block();
        let height: i64 = match rng.below(8) {
            0 => rng.below(3) as i64 - 1, // -1, 0, 1
            1 => svh + rng.below(5) as i64 - 2,
            2 => interval * rng.below(200) as i64 + rng.below(3) as i64 - 1,
            // Deep into the exhaustion range where the subsidy hits 0.
            3 => interval * (900 + rng.below(300) as i64),
            _ => rng.below(2_000_000) as i64,
        };
        let voters = rng.below(u64::from(votes_per_block) + 1) as u16;
        let variant_byte = rng.below(3) as u8;
        let variant = match variant_byte {
            1 => SubsidySplitVariant::Dcp0010,
            2 => SubsidySplitVariant::Dcp0012,
            _ => SubsidySplitVariant::Original,
        };

        let ours = format!(
            "full={}\nwork={}\nworkv2f={}\nworkv2t={}\nworkv3={}\nvote={}\nvotev2f={}\n\
             votev2t={}\nvotev3={}\ntreasuryf={}\ntreasuryt={}\n",
            cache.calc_block_subsidy(height),
            cache.calc_work_subsidy(height, voters),
            cache.calc_work_subsidy_v2(height, voters, false),
            cache.calc_work_subsidy_v2(height, voters, true),
            cache.calc_work_subsidy_v3(height, voters, variant),
            cache.calc_stake_vote_subsidy(height),
            cache.calc_stake_vote_subsidy_v2(height, false),
            cache.calc_stake_vote_subsidy_v2(height, true),
            cache.calc_stake_vote_subsidy_v3(height, variant),
            cache.calc_treasury_subsidy(height, voters, false),
            cache.calc_treasury_subsidy(height, voters, true),
        );

        let net = nets[net_idx];
        let mut req = Vec::new();
        req.push(net.len() as u8);
        req.extend_from_slice(net.as_bytes());
        req.extend_from_slice(&(height as u64).to_be_bytes());
        req.extend_from_slice(&voters.to_be_bytes());
        req.push(variant_byte);
        let theirs = dump(&mut oracle, "standalone_subsidy", &req);

        assert_eq!(
            ours, theirs,
            "subsidy divergence at round {round}: net={net} height={height} \
             voters={voters} variant={variant_byte}"
        );
    }
}

#[test]
fn treasury_differential() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("standalone-treasury-differential");

    const ROUNDS: usize = 400;
    for round in 0..ROUNDS {
        let tvi = rng.below(2000) + 1;
        let mul = rng.below(20);
        let height = rng.below(10_000_000) as i64;
        // Expiries around the valid shape: the exact valid expiry for
        // the height, plus off-by-one/two mutations and pure noise.
        let valid_expiry = standalone::calc_tspend_expiry(height, tvi, mul);
        let expiry = match rng.below(4) {
            0 => valid_expiry,
            1 => valid_expiry
                .wrapping_add(rng.below(5) as u32)
                .wrapping_sub(2),
            2 => (tvi * mul) as u32 + rng.below(5) as u32,
            _ => rng.next_u64() as u32 % 20_000_000,
        };

        let ours = {
            let istvi = standalone::is_treasury_vote_interval(height as u64, tvi);
            let (window, start, end) = match standalone::calc_tspend_window(expiry, tvi, mul) {
                Ok((s, e)) => ("ok".to_string(), s, e),
                Err(e) => (e.kind.kind_name().to_string(), 0, 0),
            };
            let inside = standalone::inside_tspend_window(height, expiry, tvi, mul);
            format!(
                "istvi={istvi}\nexpiry={valid_expiry}\nwindow={window} {start} {end}\n\
                 inside={inside}\n"
            )
        };

        let mut req = Vec::new();
        req.extend_from_slice(&(height as u64).to_be_bytes());
        req.extend_from_slice(&expiry.to_be_bytes());
        req.extend_from_slice(&tvi.to_be_bytes());
        req.extend_from_slice(&mul.to_be_bytes());
        let theirs = dump(&mut oracle, "standalone_treasury", &req);

        assert_eq!(
            ours, theirs,
            "treasury divergence at round {round}: height={height} expiry={expiry} \
             tvi={tvi} mul={mul}"
        );
    }
}

#[test]
fn tx_checks_differential() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("standalone-tx-differential");

    const ROUNDS: usize = 400;
    for round in 0..ROUNDS {
        let tx = random_tx(&mut rng);
        let ser = tx.serialize();
        let max_tx_size: u64 = match rng.below(3) {
            0 => ser.len() as u64,
            1 => (ser.len() as u64).saturating_sub(rng.below(4)),
            _ => 393_216,
        };

        let ours = format!(
            "coinbasepre={}\ncoinbasepost={}\ntreasurybase={}\nsanity={}\n",
            standalone::is_coin_base_tx(&tx, false),
            standalone::is_coin_base_tx(&tx, true),
            standalone::is_treasury_base(&tx),
            ok_or_kind(standalone::check_transaction_sanity(&tx, max_tx_size)),
        );

        let mut req = Vec::new();
        req.extend_from_slice(&max_tx_size.to_be_bytes());
        req.extend_from_slice(&ser);
        let theirs = dump(&mut oracle, "standalone_tx", &req);

        assert_eq!(
            ours,
            theirs,
            "tx checks divergence at round {round}: tx={}",
            hex(&ser)
        );
    }
}

#[test]
fn pow_hash_differential() {
    let Some(mut oracle) = oracle_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("standalone-powhash-differential");

    const ROUNDS: usize = 200;
    for round in 0..ROUNDS {
        let mut raw = [0u8; 180];
        rng.fill(&mut raw);
        let (header, _) = BlockHeader::from_bytes(&raw).expect("fixed-size header decodes");

        let ours = format!("v1={}\nv2={}\n", header.pow_hash_v1(), header.pow_hash_v2());
        let theirs = dump(&mut oracle, "blockheader_powhash", &raw);

        assert_eq!(ours, theirs, "pow hash divergence at round {round}");
    }
}

/// PowHashV1 is defined as the block hash itself; pin that relationship
/// on the mainnet genesis header without the oracle.
#[test]
fn genesis_pow_hash_v1_is_block_hash() {
    let params = mainnet_params();
    let header = &params.genesis_block.header;
    assert_eq!(header.pow_hash_v1(), params.genesis_hash);
    assert_eq!(header.block_hash(), params.genesis_hash);
}
