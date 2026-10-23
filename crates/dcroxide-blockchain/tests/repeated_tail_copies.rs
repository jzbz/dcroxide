// SPDX-License-Identifier: ISC
//! A copy of a valid block that keeps the block's header and repeats
//! the last nodes of an odd level of one of its merkle trees, then the
//! valid block itself, through the three ways a block reaches the
//! chain: `Chain::process_block`, `Chain::process_shared_block` and
//! `Chain::process_hashed_block`, the last with the block as the
//! reading thread hands it over, decoded from its bytes, with those
//! bytes kept as its record and its data sanity checked.
//!
//! A tree level with an odd number of nodes pairs its last node with
//! itself (dcrd `standalone/merkle.go:56-60`), so a tree with the last
//! nodes of such a level repeated has the root of the tree without
//! them: the shape of CVE-2012-2459.  The copy can be no valid block:
//! a block holds no transaction twice, and the copy's header names the
//! size of the block it was made from.  But dcrd at `382ff4dd`
//! counts the data commitment as proven once the merkle check passes
//! with the agenda state decided (`validate.go:2009-2034`), refuses the
//! copy in the data sanity checks for its size (`ErrWrongBlockSize`,
//! `:910-914`), and, the commitment being proven, marks the header as
//! having failed validation (`process.go:496-513`).  The valid block
//! for that header is then refused as known to be invalid
//! (`process.go:461-468`).  Any peer a block is asked of can answer
//! with such a copy.  That is dcrd's code as read: no such copy has
//! been sent to dcrd, and nothing here compares with it.
//!
//! The port refuses the copy with the same error before it counts the
//! commitment as proven, so nothing is marked and the valid block is
//! accepted when it arrives (PARITY.md, *The header's size and a proven
//! data commitment*).  That is pinned here with the header commitments
//! agenda decided inactive, decided active and undecided: in the last
//! dcrd proves nothing, so by its code it too accepts the block.  The
//! trees repeated are a stake tree of five ticket purchases and a
//! regular tree of three transactions, each with its last leaf
//! repeated, and a regular tree of six, whose first odd level is the
//! one above the leaves, so that its last two leaves are repeated.
//! Each case runs with the copy bringing the header into the index, and
//! with the header accepted first, as a sync that asks for headers
//! before blocks has it.
//!
//! The blocks are the battery's (`data/fullblock_vectors.txt`) main
//! chain up to height 17, and at height 18 its block `bse0`, which buys
//! five tickets, and that block with two and with five transactions
//! added to its regular tree, each spending the output of the one
//! before, the first an output of the coinbase of height 2 that no
//! ticket of `bse0` spends.  With the agenda forced active, every header
//! is made to commit as DCP0005 has it: its merkle root to both trees
//! and its stake root to the block's committed filter.

// Test-harness arithmetic over small counts.
#![allow(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::sync::Arc;

use dcroxide_blockchain::agendas::VOTE_ID_HEADER_COMMITMENTS;
use dcroxide_blockchain::blockindex::BlockStatus;
use dcroxide_blockchain::process::Chain;
use dcroxide_blockchain::validate::{DataSanityParams, calc_commitment_root_v1};
use dcroxide_blockchain::{HashedBlock, RuleError, RuleErrorKind};
use dcroxide_chaincfg::{Params, regnet_params};
use dcroxide_chainhash::Hash;
use dcroxide_database::BlockRecord;
use dcroxide_gcs::blockcf2::PrevScripter;
use dcroxide_standalone::{
    BigInt, Sign, calc_combined_tx_tree_merkle_root, calc_tx_tree_merkle_root, check_proof_of_work,
};
use dcroxide_testutil::unhex;
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TxIn, TxOut};

/// What the header commitments agenda query answers for the blocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Agenda {
    /// Decided inactive: the header's merkle root commits to the regular
    /// tree and its stake root to the stake tree.
    Inactive,
    /// Decided active: the header's merkle root commits to both trees
    /// and its stake root to the block's committed filter.
    Active,
    /// Not decidable from the block's position: either merkle commitment
    /// is allowed for now, and the data commitment is not proven.
    Undecided,
}

/// Regnet, with the header commitments agenda forced as the case asks
/// (dcrd's `forceDeploymentResult`).
fn regnet(agenda: Agenda) -> Params {
    let mut params = regnet_params();
    let choice = match agenda {
        Agenda::Inactive => "no",
        Agenda::Active => "yes",
        Agenda::Undecided => return params,
    };
    let mut found = false;
    for (_, deployments) in &mut params.deployments {
        for deployment in deployments.iter_mut() {
            if deployment.vote.id == VOTE_ID_HEADER_COMMITMENTS {
                deployment.forced_choice_id = choice;
                found = true;
            }
        }
    }
    assert!(found, "regnet has a header commitments deployment");
    params
}

/// The battery's main chain from height 1 to `bse0` at height 18, and
/// the current time `bse0`'s row is replayed at.
fn battery_to_bse0() -> (i64, Vec<MsgBlock>) {
    let (mut now, mut tip, mut blocks) = (0, regnet_params().genesis_hash, Vec::new());
    for line in include_str!("data/fullblock_vectors.txt").lines() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "now" => now = f[1].parse().expect("now"),
            "accept" if f[2] == "true" => {
                let (block, _) = MsgBlock::from_bytes(&unhex(f[4])).expect("block");
                assert_eq!(block.header.prev_block, tip, "{} extends the tip", f[1]);
                tip = block.header.block_hash();
                blocks.push(block);
                if f[1] == "bse0" {
                    assert_eq!(blocks.len(), 18);
                    return (now, blocks);
                }
            }
            _ => {}
        }
    }
    panic!("the battery accepts bse0");
}

/// Where an output is: its transaction's hash, its index and the tree
/// of its transaction.
type Place = ([u8; 32], u32, i8);

/// The script version and script of every output of the blocks added,
/// which is what a block's committed filter reads of the outputs its
/// inputs spend.
#[derive(Default)]
struct Scripts(BTreeMap<Place, (u16, Vec<u8>)>);

impl Scripts {
    fn add(&mut self, block: &MsgBlock) {
        for (tree, txs) in [(0, &block.transactions), (1, &block.stransactions)] {
            for tx in txs {
                let hash = tx.tx_hash();
                for (index, out) in tx.tx_out.iter().enumerate() {
                    self.0.insert(
                        (hash.0, index as u32, tree),
                        (out.version, out.pk_script.clone()),
                    );
                }
            }
        }
    }
}

impl PrevScripter for Scripts {
    fn prev_script(&self, out: &OutPoint) -> Option<(u16, &[u8])> {
        self.0
            .get(&(out.hash.0, out.index, out.tree))
            .map(|(version, script)| (*version, script.as_slice()))
    }
}

/// Grind the header's nonce from zero until both versions of its proof
/// of work hash meet its target, so that the header passes the
/// contextual check whichever version the agenda in force reads, and
/// the sanity checks, which take either.
fn grind(header: &mut BlockHeader, params: &Params) {
    let pow_limit = BigInt::from_bytes_be(Sign::Plus, &params.pow_limit.to_be_bytes());
    header.nonce = 0;
    while check_proof_of_work(&header.pow_hash_v1(), header.bits, &pow_limit).is_err()
        || check_proof_of_work(&header.pow_hash_v2(), header.bits, &pow_limit).is_err()
    {
        header.nonce += 1;
    }
}

/// Make the block's header extend `prev` and commit to the block the
/// way the agenda case reads the commitments, and to its size, then
/// grind it.  `scripts` holds the outputs of the blocks before it.
fn commit(block: &mut MsgBlock, prev: Hash, agenda: Agenda, scripts: &Scripts, params: &Params) {
    block.header.prev_block = prev;
    match agenda {
        Agenda::Inactive | Agenda::Undecided => {
            block.header.merkle_root = calc_tx_tree_merkle_root(&block.transactions);
            block.header.stake_root = calc_tx_tree_merkle_root(&block.stransactions);
        }
        Agenda::Active => {
            block.header.merkle_root =
                calc_combined_tx_tree_merkle_root(&block.transactions, &block.stransactions);
            let mut with_own = Scripts(scripts.0.clone());
            with_own.add(block);
            let filter = dcroxide_gcs::blockcf2::regular(block, &with_own).expect("a filter");
            block.header.stake_root = calc_commitment_root_v1(filter.hash());
        }
    }
    block.header.size = block.serialize_size() as u32;
    grind(&mut block.header, params);
}

/// The chain the blocks under test extend, from height 1 to 17, as the
/// agenda case reads the commitments: the battery's own blocks, or with
/// the agenda active the same blocks under headers that commit as
/// DCP0005 has them, each on the one before.  Also the outputs of those
/// blocks.
fn chain_to_17(battery: &[MsgBlock], agenda: Agenda, params: &Params) -> (Vec<MsgBlock>, Scripts) {
    let mut scripts = Scripts::default();
    let mut blocks = Vec::new();
    let mut prev = params.genesis_hash;
    for block in &battery[..17] {
        let mut block = block.clone();
        if agenda == Agenda::Active {
            commit(&mut block, prev, agenda, &scripts, params);
        }
        prev = block.header.block_hash();
        scripts.add(&block);
        blocks.push(block);
    }
    (blocks, scripts)
}

/// `count` transactions to follow the coinbase in the regular tree of a
/// block at height 18.  The first spends output 2 of `coinbase`, the
/// coinbase of height 2, an output to the script hash of `OP_TRUE` that
/// `bse0`'s tickets, spending that coinbase's outputs 3 to 7, leave
/// unspent; each after it spends the one output of the transaction
/// before it.  Each pays all it spends on to that script.
fn spends(coinbase: &MsgTx, count: usize) -> Vec<MsgTx> {
    let paid = &coinbase.tx_out[2];
    // The output spent, and where its transaction is: the fraud proof
    // an input carries.
    let mut spent = (
        OutPoint {
            hash: coinbase.tx_hash(),
            index: 2,
            tree: 0,
        },
        2,
        0,
    );
    let mut txs = Vec::new();
    for index in 1..=count {
        let (previous_out_point, block_height, block_index) = spent;
        let tx = MsgTx {
            version: 1,
            tx_in: vec![TxIn {
                previous_out_point,
                sequence: u32::MAX,
                value_in: paid.value,
                block_height,
                block_index,
                // A push of the redeem script, `OP_TRUE`.
                signature_script: vec![0x01, 0x51],
            }],
            tx_out: vec![TxOut {
                value: paid.value,
                version: 0,
                pk_script: paid.pk_script.clone(),
            }],
            ..MsgTx::default()
        };
        spent = (
            OutPoint {
                hash: tx.tx_hash(),
                index: 0,
                tree: 0,
            },
            18,
            index as u32,
        );
        txs.push(tx);
    }
    txs
}

/// Which of a block's trees a copy repeats the tail of.
#[derive(Clone, Copy, Debug)]
enum Tree {
    Regular,
    Stake,
}

/// The valid blocks at height 18, the tree of each that is repeated,
/// and how many leaves that tree has and how many of them its copy
/// repeats.
fn valid_blocks(battery: &[MsgBlock]) -> Vec<(&'static str, MsgBlock, Tree, (usize, usize))> {
    let bse0 = &battery[17];
    assert_eq!(bse0.header.height, 18);
    let coinbase_of_2 = &battery[1].transactions[0];
    let first_spent = OutPoint {
        hash: coinbase_of_2.tx_hash(),
        index: 2,
        tree: 0,
    };
    assert!(
        bse0.stransactions
            .iter()
            .all(|ticket| ticket.tx_in[0].previous_out_point != first_spent),
        "a ticket spends the output the regular spends start from"
    );
    let with_spends = |count: usize| {
        let mut block = bse0.clone();
        block.transactions.extend(spends(coinbase_of_2, count));
        block
    };
    use Tree::{Regular, Stake};
    vec![
        ("a stake tree of five", bse0.clone(), Stake, (5, 1)),
        ("a regular tree of three", with_spends(2), Regular, (3, 1)),
        ("a regular tree of six", with_spends(5), Regular, (6, 2)),
    ]
}

/// The tree with its last nodes repeated at the first level that has
/// an odd number of them, which has the root of the tree without the
/// repeats, and how many leaves are repeated.
fn with_repeated_tail(txs: &[MsgTx]) -> (Vec<MsgTx>, usize) {
    let (mut nodes, mut width) = (txs.len(), 1);
    while nodes > 0 && nodes % 2 == 0 {
        nodes /= 2;
        width *= 2;
    }
    assert!(
        nodes >= 3,
        "{} leaves have no odd level to repeat",
        txs.len()
    );
    let mut repeated = txs.to_vec();
    repeated.extend_from_slice(&txs[txs.len() - width..]);
    (repeated, width)
}

/// The block, keeping its header, with the tail of the tree repeated,
/// and how many leaves the tree has and how many of them are repeated.
fn copy_with_repeated_tail(block: &MsgBlock, tree: Tree) -> (MsgBlock, (usize, usize)) {
    let mut copy = block.clone();
    let txs = match tree {
        Tree::Regular => &mut copy.transactions,
        Tree::Stake => &mut copy.stransactions,
    };
    let leaves = txs.len();
    let (repeated, width) = with_repeated_tail(txs);
    *txs = repeated;
    assert_eq!(
        calc_tx_tree_merkle_root(&copy.transactions),
        calc_tx_tree_merkle_root(&block.transactions)
    );
    assert_eq!(
        calc_tx_tree_merkle_root(&copy.stransactions),
        calc_tx_tree_merkle_root(&block.stransactions)
    );
    assert!(copy.serialize_size() > block.serialize_size());
    (copy, (leaves, width))
}

/// The block as the reading thread hands it to the chain: decoded from
/// the bytes it arrived in, hashed, with those bytes kept as its record
/// for the block files and its data sanity checked with the chain's
/// values.
fn as_read(block: &MsgBlock, params: &Params) -> HashedBlock {
    const FRAME_HEADER: usize = 24;
    let raw = block.serialize();
    let (decoded, used) = MsgBlock::from_bytes(&raw).expect("decode");
    assert_eq!(used, raw.len());
    let mut hashed = HashedBlock::new(Arc::new(decoded));
    let mut buf = Vec::with_capacity(FRAME_HEADER + raw.len() + BlockRecord::SUFFIX_LEN);
    buf.resize(FRAME_HEADER, 0x5a);
    buf.extend_from_slice(&raw);
    assert!(hashed.keep_wire_bytes(buf, FRAME_HEADER, params.net.0));
    hashed.check_data_sanity(DataSanityParams::of(params));
    hashed
}

/// What a processing call reported, in a form that compares.
fn outcome(result: &(i64, Vec<RuleError>)) -> (i64, Vec<(RuleErrorKind, String)>) {
    (
        result.0,
        result
            .1
            .iter()
            .map(|err| (err.kind, err.description.clone()))
            .collect(),
    )
}

/// What the chain holds about the block and its header after a call.
#[derive(Debug, PartialEq, Eq)]
struct Kept {
    /// The status bits of the header's index entry, if it has one.
    status: Option<u8>,
    /// Whether the chain has the block's data.
    have_block: bool,
    /// The best block.
    tip: Hash,
}

fn kept(chain: &Chain, hash: &Hash) -> Kept {
    Kept {
        status: chain
            .index
            .lookup_node(hash)
            .map(|node| chain.store.node(node).status.0),
        have_block: chain.have_block(hash),
        tip: chain.store.node(chain.best_chain.tip().expect("tip")).hash,
    }
}

/// Three chains, one for each way a block arrives, fed the same blocks.
struct Three {
    params: Params,
    now: i64,
    borrowing: Chain,
    sharing: Chain,
    hashing: Chain,
}

impl Three {
    fn new(params: &Params, now: i64) -> Three {
        Three {
            borrowing: Chain::new(params, Hash::ZERO, false),
            sharing: Chain::new(params, Hash::ZERO, false),
            hashing: Chain::new(params, Hash::ZERO, false),
            params: params.clone(),
            now,
        }
    }

    /// Accept the header alone on the three chains, as a sync that asks
    /// for headers before blocks does.
    fn header(&mut self, what: &str, header: &BlockHeader) {
        for chain in [&mut self.borrowing, &mut self.sharing, &mut self.hashing] {
            chain
                .process_block_header(header, self.now, &self.params)
                .unwrap_or_else(|err| panic!("{what}: the header: {err:?}"));
        }
    }

    /// Process the block through the three entries, check that they
    /// report the same and leave the same behind, and return what they
    /// reported and left.  The chain handed the block as the reading
    /// thread hands it over hashes nothing and makes no data sanity
    /// check itself: it takes the hashes and the verdict the block
    /// brings.
    fn feed(
        &mut self,
        what: &str,
        block: &MsgBlock,
    ) -> ((i64, Vec<(RuleErrorKind, String)>), Kept) {
        let hash = block.header.block_hash();
        let shared = Arc::new(block.clone());
        let hashed = as_read(block, &self.params);
        let b = outcome(&self.borrowing.process_block(block, self.now, &self.params));
        let s = outcome(
            &self
                .sharing
                .process_shared_block(&shared, self.now, &self.params),
        );
        let h = outcome(
            &self
                .hashing
                .process_hashed_block(&hashed, self.now, &self.params),
        );
        assert_eq!(s, b, "{what}: shared");
        assert_eq!(h, b, "{what}: hashed");
        let counts = |chain: &Chain| (chain.arrivals_hashed, chain.arrivals_checked);
        assert_eq!(
            counts(&self.sharing),
            counts(&self.borrowing),
            "{what}: shared"
        );
        assert_eq!(counts(&self.hashing), (0, 0), "{what}: hashed");
        let left = kept(&self.borrowing, &hash);
        assert_eq!(kept(&self.sharing, &hash), left, "{what}: shared");
        assert_eq!(kept(&self.hashing, &hash), left, "{what}: hashed");
        (b, left)
    }
}

/// The copy is refused for its size and leaves its header unmarked,
/// through every entry, under each agenda case and whether or not the
/// header was accepted first, and the valid block that arrives next is
/// accepted.  A fresh chain accepts the valid block first, so the copy
/// is what the test is about.
#[test]
fn the_block_is_accepted_after_a_copy_of_it_with_a_repeated_merkle_tail() {
    let (now, battery) = battery_to_bse0();
    let mut copies = 0usize;
    for agenda in [Agenda::Inactive, Agenda::Active, Agenda::Undecided] {
        let params = regnet(agenda);
        let (chain, scripts) = chain_to_17(&battery, agenda, &params);
        let tip = chain[16].header.block_hash();
        for ((name, mut valid, tree, shape), header_first) in valid_blocks(&battery)
            .into_iter()
            .flat_map(|block| [(block.clone(), false), (block, true)])
        {
            // `bse0`'s own header commits to it as the agenda reads the
            // commitment before DCP0005; the blocks with spends added,
            // and every block under DCP0005, get a header made here.
            if agenda == Agenda::Active
                || valid.header.merkle_root != calc_tx_tree_merkle_root(&valid.transactions)
            {
                commit(&mut valid, tip, agenda, &scripts, &params);
            }
            let hash = valid.header.block_hash();
            let (copy, (leaves, repeated)) = copy_with_repeated_tail(&valid, tree);
            assert_eq!((leaves, repeated), shape, "{name}");
            assert_eq!(copy.header, valid.header);
            let what = format!(
                "{agenda:?}, {name}, {repeated} repeated{}",
                if header_first { ", header first" } else { "" }
            );
            let replayed = || {
                let mut three = Three::new(&params, now);
                for block in &chain {
                    let (result, _) = three.feed(&what, block);
                    assert_eq!(result, (0, Vec::new()), "{what}: an earlier block");
                }
                // Every block the other two chains were handed reached
                // their data sanity checks, so the hashing chain's count
                // of none says it took each block's verdict.
                assert_eq!(three.borrowing.arrivals_checked, chain.len() as u64);
                if header_first {
                    three.header(&what, &valid.header);
                }
                three
            };

            let (result, left) = replayed().feed(&what, &valid);
            assert_eq!(
                result,
                (0, Vec::new()),
                "{what}: the block on a fresh chain"
            );
            assert_eq!(left.tip, hash, "{what}");

            let mut three = replayed();
            let (result, left) = three.feed(&what, &copy);
            assert_eq!(
                result,
                (
                    0,
                    vec![(
                        RuleErrorKind::WrongBlockSize,
                        format!(
                            "serialized block is not size indicated in header - got {}, \
                             expected {}",
                            valid.header.size,
                            copy.serialize_size()
                        ),
                    )]
                ),
                "{what}: the copy"
            );
            let status = BlockStatus(left.status.expect("the header is indexed"));
            assert!(
                !status.known_invalid(),
                "{what}: the copy marked {status:?}"
            );
            assert!(!left.have_block, "{what}");
            assert_eq!(left.tip, tip, "{what}");

            let (result, left) = three.feed(&what, &valid);
            assert_eq!(result, (0, Vec::new()), "{what}: the block after the copy");
            assert!(left.have_block, "{what}");
            assert_eq!(left.tip, hash, "{what}");
            copies += 1;
        }
    }
    assert_eq!(
        copies,
        3 * 3 * 2,
        "three agenda cases of three blocks, each with and without its header first"
    );
}
