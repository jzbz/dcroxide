// SPDX-License-Identifier: ISC
//! A test chain and block builders for the exists-address tests.
//!
//! Included by path from `tests/existsaddr_v3.rs` and from the crate's
//! own `existsaddr` tests, so it names nothing of `dcroxide-indexers`:
//! each includer implements `ChainQueryer` for [`TestChain`] itself.

// Test-harness arithmetic over bounded heights and counts.
#![allow(clippy::arithmetic_side_effects, dead_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_txscript::stdaddr::{
    Address, new_address_pub_key_ecdsa_secp256k1_v0, new_address_pub_key_hash_ecdsa_secp256k1_v0,
    new_address_pub_key_hash_ed25519_v0, new_address_pub_key_hash_schnorr_secp256k1_v0,
    new_address_script_hash_v0_from_hash,
};
use dcroxide_wire::{BlockHeader, MsgBlock, MsgTx, OutPoint, TxIn, TxOut, TxSerializeType};

/// An address key: type byte plus hash160.
pub type Key = [u8; 21];

/// The main chain and every block ever removed from it.
pub struct TestChain {
    state: Mutex<ChainState>,
    pub params: &'static Params,
}

struct ChainState {
    best: (i64, Hash),
    by_height: HashMap<i64, Arc<MsgBlock>>,
    by_hash: HashMap<[u8; 32], Arc<MsgBlock>>,
    orphans: HashMap<[u8; 32], Arc<MsgBlock>>,
}

impl TestChain {
    /// A chain holding only `params`' genesis block.
    pub fn new(params: &'static Params) -> Arc<TestChain> {
        let genesis = Arc::new(params.genesis_block.clone());
        let hash = genesis.header.block_hash();
        let mut by_height = HashMap::new();
        let mut by_hash = HashMap::new();
        by_height.insert(0, Arc::clone(&genesis));
        by_hash.insert(hash.0, genesis);
        Arc::new(TestChain {
            state: Mutex::new(ChainState {
                best: (0, hash),
                by_height,
                by_hash,
                orphans: HashMap::new(),
            }),
            params,
        })
    }

    /// Extend the main chain with `block`.
    pub fn add(&self, block: &Arc<MsgBlock>) {
        let mut state = self.state.lock().expect("chain");
        assert_eq!(block.header.prev_block, state.best.1, "not on the tip");
        let height = i64::from(block.header.height);
        assert_eq!(height, state.best.0 + 1);
        let hash = block.header.block_hash();
        state.by_height.insert(height, Arc::clone(block));
        state.by_hash.insert(hash.0, Arc::clone(block));
        state.orphans.remove(&hash.0);
        state.best = (height, hash);
    }

    /// Remove the tip, keeping it fetchable by hash.
    pub fn remove_tip(&self) -> Arc<MsgBlock> {
        let mut state = self.state.lock().expect("chain");
        let (height, hash) = state.best;
        assert!(height > 0, "the genesis block stays");
        let block = state.by_height.remove(&height).expect("tip block");
        state.by_hash.remove(&hash.0);
        state.orphans.insert(hash.0, Arc::clone(&block));
        state.best = (height - 1, block.header.prev_block);
        block
    }

    /// The tip's height and hash.
    pub fn tip(&self) -> (i64, Hash) {
        self.state.lock().expect("chain").best
    }

    /// The main-chain block at `height`.
    pub fn at(&self, height: i64) -> Arc<MsgBlock> {
        Arc::clone(&self.state.lock().expect("chain").by_height[&height])
    }

    pub fn has(&self, hash: &Hash) -> bool {
        self.state
            .lock()
            .expect("chain")
            .by_hash
            .contains_key(&hash.0)
    }

    pub fn hash_at(&self, height: i64) -> Result<Hash, String> {
        self.state
            .lock()
            .expect("chain")
            .by_height
            .get(&height)
            .map(|b| b.header.block_hash())
            .ok_or_else(|| format!("no block at height {height}"))
    }

    pub fn get(&self, hash: &Hash) -> Result<Arc<MsgBlock>, String> {
        let state = self.state.lock().expect("chain");
        state
            .by_hash
            .get(&hash.0)
            .or_else(|| state.orphans.get(&hash.0))
            .cloned()
            .ok_or_else(|| format!("no block {hash}"))
    }
}

/// Implement `ChainQueryer` for [`TestChain`], given the includer's paths
/// to the trait and to the type.
macro_rules! impl_chain_queryer {
    ($trait:path, $ty:path) => {
        impl $trait for $ty {
            fn main_chain_has_block(&self, hash: &dcroxide_chainhash::Hash) -> bool {
                self.has(hash)
            }
            fn chain_params(&self) -> &dcroxide_chaincfg::Params {
                self.params
            }
            fn best(&self) -> (i64, dcroxide_chainhash::Hash) {
                self.tip()
            }
            fn block_header_by_hash(
                &self,
                hash: &dcroxide_chainhash::Hash,
            ) -> Result<dcroxide_wire::BlockHeader, String> {
                self.get(hash).map(|b| b.header)
            }
            fn block_hash_by_height(
                &self,
                height: i64,
            ) -> Result<dcroxide_chainhash::Hash, String> {
                self.hash_at(height)
            }
            fn block_height_by_hash(&self, hash: &dcroxide_chainhash::Hash) -> Result<i64, String> {
                self.get(hash).map(|b| i64::from(b.header.height))
            }
            fn block_by_hash(
                &self,
                hash: &dcroxide_chainhash::Hash,
            ) -> Result<std::sync::Arc<dcroxide_wire::MsgBlock>, String> {
                self.get(hash)
            }
            fn is_treasury_agenda_active(
                &self,
                _hash: &dcroxide_chainhash::Hash,
            ) -> Result<bool, String> {
                Ok(false)
            }
        }
    };
}

/// A block on `prev` holding `txs`; `salt` tells apart siblings.
pub fn block_on(prev: &MsgBlock, salt: u32, txs: Vec<MsgTx>) -> Arc<MsgBlock> {
    let (mut header, _) = BlockHeader::from_bytes(&[0u8; 180]).expect("header");
    header.prev_block = prev.header.block_hash();
    header.height = prev.header.height + 1;
    header.nonce = salt;
    Arc::new(MsgBlock {
        header,
        transactions: txs,
        stransactions: Vec::new(),
    })
}

/// A transaction paying one atom to each script.
pub fn tx_paying(scripts: &[Vec<u8>]) -> MsgTx {
    MsgTx {
        ser_type: TxSerializeType::Full,
        version: 1,
        tx_in: Vec::new(),
        tx_out: scripts
            .iter()
            .map(|s| TxOut {
                value: 1,
                version: 0,
                pk_script: s.clone(),
            })
            .collect(),
        lock_time: 0,
        expiry: 0,
    }
}

/// A transaction whose only input redeems a multisig script over
/// `pubkeys` (a one-of-n), so its keys are the pubkeys' hash160s.
pub fn tx_redeeming_multisig(pubkeys: &[[u8; 33]]) -> MsgTx {
    // OP_1 <pk>... OP_n OP_CHECKMULTISIG
    let mut redeem = vec![0x51];
    for pk in pubkeys {
        redeem.push(33);
        redeem.extend_from_slice(pk);
    }
    redeem.push(0x50 + pubkeys.len() as u8);
    redeem.push(0xae);
    // <sig> <redeem script>, each pushed canonically.
    let mut sig_script = vec![0x01, 0x30];
    if redeem.len() < 0x4c {
        sig_script.push(redeem.len() as u8);
    } else {
        sig_script.extend_from_slice(&[0x4c, redeem.len() as u8]);
    }
    sig_script.extend_from_slice(&redeem);
    MsgTx {
        ser_type: TxSerializeType::Full,
        version: 1,
        tx_in: vec![TxIn {
            previous_out_point: OutPoint {
                hash: Hash([9; 32]),
                index: 0,
                tree: 0,
            },
            sequence: u32::MAX,
            value_in: 0,
            block_height: 0,
            block_index: 0,
            signature_script: sig_script,
        }],
        tx_out: Vec::new(),
        lock_time: 0,
        expiry: 0,
    }
}

/// Compressed secp256k1 points G, 2G and 3G: valid public keys for
/// pay-to-pubkey outputs and multisig scripts.
pub const PUBKEYS: [[u8; 33]; 3] = [
    hex33("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
    hex33("02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
    hex33("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
];

const fn hex33(s: &str) -> [u8; 33] {
    let b = s.as_bytes();
    let mut out = [0u8; 33];
    let mut i = 0;
    while i < 33 {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("hex"),
    }
}

/// The address of a key's type: pay-to-pubkey-hash for types 0, 1 and 2
/// (secp256k1, Ed25519, secp256k1 Schnorr) and pay-to-script-hash for 3.
pub fn address_of(key: &Key, params: &Params) -> Address {
    let mut hash = [0u8; 20];
    hash.copy_from_slice(&key[1..]);
    match key[0] {
        0 => new_address_pub_key_hash_ecdsa_secp256k1_v0(&hash, params).expect("p2pkh"),
        1 => new_address_pub_key_hash_ed25519_v0(&hash, params).expect("ed25519"),
        2 => new_address_pub_key_hash_schnorr_secp256k1_v0(&hash, params).expect("schnorr"),
        3 => new_address_script_hash_v0_from_hash(&hash, params).expect("p2sh"),
        t => panic!("no address type {t}"),
    }
}

/// The output script paying a key's address.
pub fn script_of(key: &Key, params: &Params) -> Vec<u8> {
    address_of(key, params).payment_script().1
}

/// The pay-to-pubkey address of one of [`PUBKEYS`].
pub fn p2pk_address(pubkey: &[u8; 33], params: &Params) -> Address {
    new_address_pub_key_ecdsa_secp256k1_v0(*pubkey, params)
}

/// Scripts no key comes from: a null-data output and a non-standard one.
pub fn unsupported_scripts() -> Vec<Vec<u8>> {
    vec![vec![0x6a, 0x04, 1, 2, 3, 4], vec![0x51, 0x52, 0x93]]
}
