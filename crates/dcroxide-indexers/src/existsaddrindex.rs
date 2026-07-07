// SPDX-License-Identifier: ISC
//! The "ever seen" address index (dcrd indexers
//! `existsaddrindex.go`): every address ever seen in a block or in
//! the mempool, stored as bare keys with empty values and never
//! removed, plus a memory-only overlay for unconfirmed transactions.

use std::collections::HashSet;
use std::rc::Rc;

use dcroxide_chainhash::Hash;
use dcroxide_database::{Bucket, Database, Transaction};
use dcroxide_txscript::stdaddr::Address;
use dcroxide_txscript::stdscript;
use dcroxide_wire::{MsgBlock, MsgTx};

use crate::common::{
    ChainQueryer, Indexer, Interrupt, SyncWaiter, db_put_indexer_tip, drop_flat_index,
    notify_sync_subscribers, tip,
};
use crate::error::{ErrorKind, IdxError, indexer_error};
use crate::subscriber::{
    CONNECT_NTFN, DISCONNECT_NTFN, IndexNtfn, IndexSubscriber, IndexerHandle, NO_PREREQS,
    block_height,
};

/// The human-readable name for the index (dcrd
/// `existsAddressIndexName`).
pub const EXISTS_ADDRESS_INDEX_NAME: &str = "exists address index";

/// The current version of the exists address index (dcrd
/// `existsAddrIndexVersion`).
const EXISTS_ADDR_INDEX_VERSION: u32 = 2;

/// The number of bytes an address key consumes in the index: 1 byte
/// address type + 20 bytes hash160 (dcrd `addrKeySize`).
pub const ADDR_KEY_SIZE: usize = 1 + 20;

/// The address key type representing both pay-to-pubkey-hash and
/// pay-to-pubkey addresses (dcrd `addrKeyTypePubKeyHash`).
const ADDR_KEY_TYPE_PUB_KEY_HASH: u8 = 0;

/// The address key type for the Ed25519 pubkey-hash variants (dcrd
/// `addrKeyTypePubKeyHashEdwards`).
const ADDR_KEY_TYPE_PUB_KEY_HASH_EDWARDS: u8 = 1;

/// The address key type for the secp256k1-Schnorr pubkey-hash
/// variants (dcrd `addrKeyTypePubKeyHashSchnorr`).
const ADDR_KEY_TYPE_PUB_KEY_HASH_SCHNORR: u8 = 2;

/// The address key type for pay-to-script-hash addresses (dcrd
/// `addrKeyTypeScriptHash`).
const ADDR_KEY_TYPE_SCRIPT_HASH: u8 = 3;

/// The key of the ever seen address index and the db bucket used to
/// house it (dcrd `existsAddrIndexKey`).
pub const EXISTS_ADDR_INDEX_KEY: &[u8] = b"existsaddridx";

/// Convert known address types to an address index key (dcrd
/// `addrToKey`).
pub fn addr_to_key(addr: &Address) -> Result<[u8; ADDR_KEY_SIZE], IdxError> {
    // Convert public key addresses to public key hash variants.
    let folded;
    let addr = match addr.address_pub_key_hash() {
        Some(pkh) => {
            folded = pkh;
            &folded
        }
        None => addr,
    };

    let (key_type, hash) = match addr {
        Address::PubKeyHashEcdsaSecp256k1V0 { hash, .. } => (ADDR_KEY_TYPE_PUB_KEY_HASH, hash),
        Address::PubKeyHashEd25519V0 { hash, .. } => (ADDR_KEY_TYPE_PUB_KEY_HASH_EDWARDS, hash),
        Address::PubKeyHashSchnorrSecp256k1V0 { hash, .. } => {
            (ADDR_KEY_TYPE_PUB_KEY_HASH_SCHNORR, hash)
        }
        Address::ScriptHashV0 { hash, .. } => (ADDR_KEY_TYPE_SCRIPT_HASH, hash),
        _ => {
            return Err(indexer_error(
                ErrorKind::UnsupportedAddressType,
                "address type is not supported by the exists address index",
            ));
        }
    };
    let mut result = [0u8; ADDR_KEY_SIZE];
    result[0] = key_type;
    result[1..].copy_from_slice(hash);
    Ok(result)
}

/// The "ever seen" address index (dcrd `ExistsAddrIndex`).
pub struct ExistsAddrIndex {
    db: Rc<Database>,
    chain: Rc<dyn ChainQueryer>,

    // The memory-only index of addresses seen in unconfirmed
    // transactions (dcrd `mpExistsAddr`).
    mp_exists_addr: HashSet<[u8; ADDR_KEY_SIZE]>,

    subscribers: Vec<SyncWaiter>,
}

impl ExistsAddrIndex {
    /// Create the exists address index, subscribe it for updates, and
    /// initialize it (dcrd `NewExistsAddrIndex` +
    /// `ExistsAddrIndex.Init`).
    pub fn new(
        subscriber: &mut IndexSubscriber,
        db: Rc<Database>,
        chain: Rc<dyn ChainQueryer>,
    ) -> Result<Rc<core::cell::RefCell<ExistsAddrIndex>>, IdxError> {
        ExistsAddrIndex::new_with_prereq(subscriber, db, chain, NO_PREREQS)
    }

    /// [`new`](Self::new) with an explicit prerequisite subscription;
    /// dcrd always subscribes this index without one, but the update
    /// relay hierarchy is exercised through this hook.
    pub fn new_with_prereq(
        subscriber: &mut IndexSubscriber,
        db: Rc<Database>,
        chain: Rc<dyn ChainQueryer>,
        prereq: &str,
    ) -> Result<Rc<core::cell::RefCell<ExistsAddrIndex>>, IdxError> {
        let idx = Rc::new(core::cell::RefCell::new(ExistsAddrIndex {
            db,
            chain,
            mp_exists_addr: HashSet::new(),
            subscribers: Vec::new(),
        }));

        subscriber
            .subscribe(
                EXISTS_ADDRESS_INDEX_NAME,
                idx.clone() as IndexerHandle,
                prereq,
            )
            .map_err(IdxError::Other)?;

        // Init.
        let interrupt = subscriber.interrupt();
        if crate::common::interrupt_requested(&interrupt) {
            return Err(indexer_error(
                ErrorKind::InterruptRequested,
                crate::common::INTERRUPT_MSG,
            ));
        }
        {
            let genesis_hash = {
                let borrowed = idx.borrow();
                let params = borrowed.chain.chain_params();
                params.genesis_hash
            };
            let borrowed = idx.borrow();
            // Finish any drops that were previously interrupted.
            crate::common::finish_drop(&interrupt, &*borrowed)?;
            // Create the initial state for the index as needed.
            crate::common::create_index(&*borrowed, &genesis_hash)?;
            // Upgrade the index as needed.
            crate::common::upgrade_index(&interrupt, &*borrowed, &genesis_hash)?;
        }

        // Recover the exists address index and its dependents to the
        // main chain if needed.
        subscriber.recover_index(EXISTS_ADDRESS_INDEX_NAME)?;

        Ok(idx)
    }

    /// Whether the key exists in the provided bucket or the
    /// unconfirmed overlay (dcrd `existsAddress`).
    fn exists_address_bucket(&self, bucket: &Bucket<'_>, k: &[u8; ADDR_KEY_SIZE]) -> bool {
        if bucket.get(k).is_some() {
            return true;
        }
        self.mp_exists_addr.contains(k)
    }

    /// Whether or not an address has been seen before (dcrd
    /// `ExistsAddress`).
    pub fn exists_address(&self, addr: &Address) -> Result<bool, IdxError> {
        let k = addr_to_key(addr)?;

        let db_tx = self.db.begin(false)?;
        let exists = db_tx
            .metadata()
            .bucket(EXISTS_ADDR_INDEX_KEY)
            .is_some_and(|bucket| bucket.get(&k).is_some());
        db_tx.rollback()?;

        // Only check the in memory map if needed.
        if !exists {
            return Ok(self.mp_exists_addr.contains(&k));
        }
        Ok(exists)
    }

    /// Whether or not each address in a slice of addresses has been
    /// seen before (dcrd `ExistsAddresses`).
    pub fn exists_addresses(&self, addrs: &[Address]) -> Result<Vec<bool>, IdxError> {
        let mut addr_keys = Vec::with_capacity(addrs.len());
        for addr in addrs {
            addr_keys.push(addr_to_key(addr)?);
        }
        let mut exists = vec![false; addrs.len()];

        let db_tx = self.db.begin(false)?;
        for (i, key) in addr_keys.iter().enumerate() {
            exists[i] = db_tx
                .metadata()
                .bucket(EXISTS_ADDR_INDEX_KEY)
                .is_some_and(|bucket| bucket.get(key).is_some());
        }
        db_tx.rollback()?;

        for (i, key) in addr_keys.iter().enumerate() {
            if !exists[i] {
                exists[i] = self.mp_exists_addr.contains(key);
            }
        }

        Ok(exists)
    }

    /// Add all addresses associated with transactions in the provided
    /// block and flush the unconfirmed overlay (dcrd
    /// `ExistsAddrIndex.connectBlock`).
    fn connect_block(&mut self, db_tx: &Transaction, block: &MsgBlock) -> Result<(), IdxError> {
        // NOTE: The fact that the block can disapprove the regular
        // tree of the previous block is ignored for this index: the
        // primary purpose is to track whether or not addresses have
        // ever been seen, and even if they technically end up
        // becoming unused, they were still seen.

        let params = self.chain.chain_params();
        let mut used_addrs: HashSet<[u8; ADDR_KEY_SIZE]> = HashSet::new();
        for tx in block.transactions.iter().chain(block.stransactions.iter()) {
            let is_sstx = dcroxide_stake::is_sstx(tx);
            for tx_in in &tx.tx_in {
                // Note that the functions used here require v0
                // scripts.  This will ultimately need to be updated
                // to support new script versions.
                if !stdscript::is_multi_sig_sig_script_v0(&tx_in.signature_script) {
                    continue;
                }
                let Some(rs) =
                    stdscript::multi_sig_redeem_script_from_script_sig_v0(&tx_in.signature_script)
                else {
                    continue;
                };
                let (typ, addrs) = stdscript::extract_addrs_v0(&rs, params);
                if typ != stdscript::ScriptType::MultiSig {
                    // This should never happen, but be paranoid.
                    continue;
                }

                for addr in &addrs {
                    if let Ok(k) = addr_to_key(addr) {
                        used_addrs.insert(k);
                    }
                }
            }

            for tx_out in &tx.tx_out {
                let (script_type, mut addrs) =
                    stdscript::extract_addrs(tx_out.version, &tx_out.pk_script, params);
                if script_type == stdscript::ScriptType::NonStandard {
                    // Non-standard outputs are skipped.
                    continue;
                }

                if is_sstx
                    && script_type == stdscript::ScriptType::NullData
                    && let Ok(addr) =
                        dcroxide_stake::addr_from_sstx_pk_scr_commitment(&tx_out.pk_script, params)
                {
                    addrs.push(addr);
                }
                // Unsupported address types are ignored.

                for addr in &addrs {
                    // Ignore unsupported address types.
                    if let Ok(k) = addr_to_key(addr) {
                        used_addrs.insert(k);
                    }
                }
            }
        }

        // Write all the newly used addresses to the database,
        // skipping any keys that already exist.  Write any addresses
        // seen in mempool at this time, too, then reset the
        // unconfirmed map.
        for addr_key in self.mp_exists_addr.drain() {
            used_addrs.insert(addr_key);
        }

        let meta = db_tx.metadata();
        let exists_addr_idx_bucket = meta.bucket(EXISTS_ADDR_INDEX_KEY).ok_or_else(|| {
            crate::common::make_db_err(
                dcroxide_database::ErrorKind::BucketNotFound,
                format!(
                    "{} bucket not found",
                    String::from_utf8_lossy(EXISTS_ADDR_INDEX_KEY)
                ),
            )
        })?;
        let mut new_used_addrs: Vec<[u8; ADDR_KEY_SIZE]> = Vec::new();
        for addr_key in &used_addrs {
            if !self.exists_address_bucket(&exists_addr_idx_bucket, addr_key) {
                new_used_addrs.push(*addr_key);
            }
        }

        for addr_key in &new_used_addrs {
            // dcrd `dbPutExistsAddr`: keys only, empty values.
            exists_addr_idx_bucket.put(addr_key, &[])?;
        }

        // Update the current index tip.
        db_put_indexer_tip(
            db_tx,
            EXISTS_ADDR_INDEX_KEY,
            &block.header.block_hash(),
            block_height(block) as i32,
        )
    }

    /// Only update the index tip; the index never removes addresses,
    /// even in the case of a reorg (dcrd
    /// `ExistsAddrIndex.disconnectBlock`).
    fn disconnect_block(&mut self, db_tx: &Transaction, block: &MsgBlock) -> Result<(), IdxError> {
        // Update the current index tip.
        db_put_indexer_tip(
            db_tx,
            EXISTS_ADDR_INDEX_KEY,
            &block.header.prev_block,
            (block_height(block).saturating_sub(1)) as i32,
        )
    }

    /// Add all addresses related to the transaction to the
    /// unconfirmed (memory-only) exists address index (dcrd
    /// `AddUnconfirmedTx`).
    pub fn add_unconfirmed_tx(&mut self, tx: &MsgTx) {
        let params_addrs = {
            let params = self.chain.chain_params();
            let is_sstx = dcroxide_stake::is_sstx(tx);
            let mut keys: Vec<[u8; ADDR_KEY_SIZE]> = Vec::new();
            for tx_in in &tx.tx_in {
                // Note that the functions used here require v0
                // scripts.
                if !stdscript::is_multi_sig_sig_script_v0(&tx_in.signature_script) {
                    continue;
                }
                let Some(rs) =
                    stdscript::multi_sig_redeem_script_from_script_sig_v0(&tx_in.signature_script)
                else {
                    continue;
                };
                let (script_type, addrs) = stdscript::extract_addrs_v0(&rs, params);
                if script_type != stdscript::ScriptType::MultiSig {
                    // This should never happen, but be paranoid.
                    continue;
                }
                for addr in &addrs {
                    if let Ok(k) = addr_to_key(addr) {
                        keys.push(k);
                    }
                }
            }

            for tx_out in &tx.tx_out {
                let (script_type, mut addrs) =
                    stdscript::extract_addrs(tx_out.version, &tx_out.pk_script, params);
                if script_type == stdscript::ScriptType::NonStandard {
                    // Non-standard outputs are skipped.
                    continue;
                }

                if is_sstx
                    && script_type == stdscript::ScriptType::NullData
                    && let Ok(addr) =
                        dcroxide_stake::addr_from_sstx_pk_scr_commitment(&tx_out.pk_script, params)
                {
                    addrs.push(addr);
                }
                // Unsupported address types are ignored.

                for addr in &addrs {
                    // Ignore unsupported address types.
                    if let Ok(k) = addr_to_key(addr) {
                        keys.push(k);
                    }
                }
            }
            keys
        };
        for k in params_addrs {
            self.mp_exists_addr.insert(k);
        }
    }
}

impl Indexer for ExistsAddrIndex {
    fn key(&self) -> &'static [u8] {
        EXISTS_ADDR_INDEX_KEY
    }

    fn name(&self) -> &'static str {
        EXISTS_ADDRESS_INDEX_NAME
    }

    fn version(&self) -> u32 {
        EXISTS_ADDR_INDEX_VERSION
    }

    fn db(&self) -> Rc<Database> {
        self.db.clone()
    }

    fn queryer(&self) -> Rc<dyn ChainQueryer> {
        self.chain.clone()
    }

    fn tip(&self) -> Result<(i64, Hash), IdxError> {
        tip(&self.db, EXISTS_ADDR_INDEX_KEY)
    }

    fn create(&self, db_tx: &Transaction) -> Result<(), IdxError> {
        db_tx.metadata().create_bucket(EXISTS_ADDR_INDEX_KEY)?;
        Ok(())
    }

    fn process_notification(
        &mut self,
        db_tx: &Transaction,
        ntfn: &IndexNtfn,
    ) -> Result<(), IdxError> {
        match ntfn.ntfn_type {
            CONNECT_NTFN => self.connect_block(db_tx, &ntfn.block).map_err(|err| {
                indexer_error(
                    ErrorKind::ConnectBlock,
                    format!("{}: unable to connect block: {err}", self.name()),
                )
            }),
            DISCONNECT_NTFN => self.disconnect_block(db_tx, &ntfn.block).map_err(|err| {
                indexer_error(
                    ErrorKind::DisconnectBlock,
                    format!("{}: unable to disconnect block: {err}", self.name()),
                )
            }),
            other => Err(indexer_error(
                ErrorKind::InvalidNotificationType,
                format!(
                    "{}: unknown notification type received: {}",
                    self.name(),
                    other.0
                ),
            )),
        }
    }

    fn wait_for_sync(&mut self) -> SyncWaiter {
        let waiter: SyncWaiter = Rc::new(core::cell::Cell::new(false));
        self.subscribers.push(waiter.clone());
        waiter
    }

    fn notify_sync_subscribers(&mut self) {
        notify_sync_subscribers(&mut self.subscribers);
    }

    fn drop_index(&self, interrupt: &Interrupt, db: &Database) -> Result<(), IdxError> {
        drop_exists_addr_index(interrupt, db)
    }
}

/// Drop the exists address index from the provided database if it
/// exists (dcrd `DropExistsAddrIndex`).
pub fn drop_exists_addr_index(interrupt: &Interrupt, db: &Database) -> Result<(), IdxError> {
    drop_flat_index(interrupt, db, EXISTS_ADDR_INDEX_KEY)
}
