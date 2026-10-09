// SPDX-License-Identifier: ISC
//! The "ever seen" address index (dcrd indexers
//! `existsaddrindex.go`): every address ever seen in a block or in
//! the mempool, never removed, plus a memory-only overlay for
//! unconfirmed transactions.
//!
//! dcrd stores each address as a bare key with an empty value (layout 2,
//! index version 2).  This port stores the same set in layout 3, index
//! version 3: a memtable, a per-flush journal and sorted runs, written by
//! a flush participant inside the metadata flush ([`crate::existsaddr`],
//! ADR-0011).  The tip row, the subscriber, catch-up and recovery are
//! dcrd's, and so is every answer, with the exceptions recorded in
//! PARITY.md.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dcroxide_chainhash::Hash;
use dcroxide_database::{Database, FlushParticipant, Transaction};
use dcroxide_txscript::stdaddr::Address;
use dcroxide_txscript::stdscript;
use dcroxide_wire::{MsgBlock, MsgTx};

use crate::common::{
    ChainQueryer, Indexer, Interrupt, SyncWaiter, db_fetch_indexer_version, db_put_indexer_tip,
    drop_flat_index, notify_sync_subscribers, tip,
};
use crate::error::{ErrorKind, IdxError, indexer_error};
use crate::existsaddr::policy::Policy;
use crate::existsaddr::runs::{self, BASE, DELTA};
use crate::existsaddr::store::{self, AddrStore};
use crate::log::LogSink;
use crate::subscriber::{
    CONNECT_NTFN, DISCONNECT_NTFN, IndexNtfn, IndexSubscriber, IndexerHandle, NO_PREREQS,
    block_height,
};

/// The human-readable name for the index (dcrd
/// `existsAddressIndexName`).
pub const EXISTS_ADDRESS_INDEX_NAME: &str = "exists address index";

/// The current version of the exists address index.  dcrd's
/// `existsAddrIndexVersion` is 2, its one-row-per-address layout; 3 is
/// this port's layout 3, which dcrd does not have.  It is stored as dcrd
/// stores every index version, in the tips bucket's `v` row.
pub const EXISTS_ADDR_INDEX_VERSION: u32 = 3;

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

/// The memory-only index of addresses seen in unconfirmed transactions
/// (dcrd `mpExistsAddr`), behind its own lock.
///
/// dcrd guards this map with a dedicated `unconfirmedLock`
/// (`existsaddrindex.go` 292/451/572) and takes no index-wide lock to
/// answer a query, so a lookup never blocks the index writer.  The port
/// keeps `ExistsAddrIndex` itself behind one mutex because the daemon
/// shares it across threads, which would put every query in the writer's
/// way — so the overlay is split out here and reached through
/// [`ExistsAddrQuery`] instead.
type Unconfirmed = Arc<std::sync::RwLock<HashSet<[u8; ADDR_KEY_SIZE]>>>;

/// The "ever seen" address index (dcrd `ExistsAddrIndex`).
pub struct ExistsAddrIndex {
    db: Arc<Database>,
    chain: Arc<dyn ChainQueryer>,

    // The memory-only index of addresses seen in unconfirmed
    // transactions (dcrd `mpExistsAddr`).
    mp_exists_addr: Unconfirmed,

    // The layout-3 state: the memtable and the flush participant, which
    // the database holds too once it is registered.
    store: Arc<AddrStore>,

    // The bucket id the store was opened under, which prefixes every
    // row of the index; `NO_BUCKET` before the open and after a drop.
    bucket: Arc<AtomicU64>,

    subscribers: Vec<SyncWaiter>,
}

/// [`ExistsAddrIndex::bucket`] when no bucket is open.
const NO_BUCKET: u64 = u64::MAX;

/// Everything a lookup needs, detached from the index mutex: the shared
/// database handle, the unconfirmed overlay and the memtable (dcrd's
/// `idx.db` plus the map behind `unconfirmedLock`).
///
/// dcrd's `ExistsAddress`/`ExistsAddresses` read the database with no
/// index-wide lock held and take `unconfirmedLock` only for the overlay.
/// Obtaining one of these costs a few `Arc` clones, so a caller holding
/// `Arc<Mutex<ExistsAddrIndex>>` can release the index guard before doing
/// any database work and reach the same behaviour.  That matters because
/// the index writer takes this mutex *before* it opens its write
/// transaction (`subscriber.rs`, pinned by `b6_indexlock`): the writer's
/// semaphore is claimed last and never held while it waits here, so a
/// query that held the mutex across its database reads would stall the
/// indexer without stalling every other commit in the process.  The
/// other direction matters as much: the writer holds the mutex through
/// its wait for the database writer and a block's index work, so the
/// daemon's RPC seam takes one of these once, at startup, and never
/// waits on the writer to answer a lookup or report the tip.
///
/// **Lookup order.**  A key moves from the unconfirmed overlay to the
/// memtable in a connect's commit hook, and from the memtable to a run in
/// a flush.  Each move inserts into the next place before it removes
/// from the last, and the memtable is cleared only after the flush's
/// commit.  A lookup reads the three in that same order -- the overlay,
/// then the memtable, then a read transaction begun after both -- so it
/// never misses a key in mid-move.  dcrd reads the database first and
/// the overlay second, and its connect drains the overlay before its
/// write commits, so a lookup there can answer `false` for a mempool
/// address while its block is being indexed; this one answers `true`
/// (PARITY.md).
#[derive(Clone)]
pub struct ExistsAddrQuery {
    db: Arc<Database>,
    mp_exists_addr: Unconfirmed,
    store: Arc<AddrStore>,
    bucket: Arc<AtomicU64>,
}

impl ExistsAddrQuery {
    /// The current index tip (dcrd `ExistsAddrIndex.Tip`, which reads
    /// the tips bucket with no index-wide lock held).
    pub fn tip(&self) -> Result<(i64, Hash), IdxError> {
        tip(&self.db, EXISTS_ADDR_INDEX_KEY)
    }

    /// Whether or not an address has been seen before (dcrd
    /// `ExistsAddress`).
    ///
    /// A store read error is returned rather than read as absence, where
    /// dcrd's ffldb answers `false` (PARITY.md); the RPC handler turns it
    /// into "Could not query address: ...".
    pub fn exists_address(&self, addr: &Address) -> Result<bool, IdxError> {
        let k = addr_to_key(addr)?;
        Ok(self.lookup(&[k])?[0])
    }

    /// Whether or not each address in a slice of addresses has been
    /// seen before (dcrd `ExistsAddresses`).  Every address is converted
    /// first, so one unsupported address fails the whole call, as in
    /// dcrd.
    pub fn exists_addresses(&self, addrs: &[Address]) -> Result<Vec<bool>, IdxError> {
        let mut addr_keys = Vec::with_capacity(addrs.len());
        for addr in addrs {
            addr_keys.push(addr_to_key(addr)?);
        }
        self.lookup(&addr_keys)
    }

    /// The three lookup passes over `keys`, in the order keys move (see
    /// the type docs): one overlay pass, one memtable pass, and one read
    /// transaction for the keys still missing.
    fn lookup(&self, keys: &[[u8; ADDR_KEY_SIZE]]) -> Result<Vec<bool>, IdxError> {
        let mut exists = vec![false; keys.len()];
        #[cfg(test)]
        if self.store.faults.overlay_last.load(Ordering::SeqCst) {
            self.memtable_pass(keys, &mut exists);
            self.store_pass(keys, &mut exists)?;
            self.overlay_pass(keys, &mut exists);
            return Ok(exists);
        }
        self.overlay_pass(keys, &mut exists);
        self.memtable_pass(keys, &mut exists);
        self.store_pass(keys, &mut exists)?;
        Ok(exists)
    }

    /// The unconfirmed overlay, under one read guard for the whole slice
    /// as dcrd takes one `unconfirmedLock.RLock` around its loop.
    fn overlay_pass(&self, keys: &[[u8; ADDR_KEY_SIZE]], exists: &mut [bool]) {
        let overlay = self
            .mp_exists_addr
            .read()
            .expect("unconfirmed overlay lock poisoned");
        for (found, key) in exists.iter_mut().zip(keys) {
            *found = *found || overlay.contains(key);
        }
    }

    /// The memtable, a partition read lock per key.
    fn memtable_pass(&self, keys: &[[u8; ADDR_KEY_SIZE]], exists: &mut [bool]) {
        let part = self.store.partitioner();
        for (found, key) in exists.iter_mut().zip(keys) {
            *found = *found || self.store.mem.contains(part.of(key), key);
        }
    }

    /// The runs: one read transaction, begun after the other passes, and
    /// for each key still missing a probe of its partition's delta run,
    /// then its base run, each one chunk row.
    fn store_pass(
        &self,
        keys: &[[u8; ADDR_KEY_SIZE]],
        exists: &mut [bool],
    ) -> Result<(), IdxError> {
        if exists.iter().all(|&found| found) {
            return Ok(());
        }
        let Some(bucket) = bucket_id(&self.bucket) else {
            return Ok(());
        };
        let part = self.store.partitioner();
        let db_tx = self.db.begin(false)?;
        let res = (|| {
            for (found, key) in exists.iter_mut().zip(keys) {
                if !*found {
                    let p = part.of(key);
                    *found = runs::probe(&db_tx, &part, &bucket, p, key, DELTA)?
                        || runs::probe(&db_tx, &part, &bucket, p, key, BASE)?;
                }
            }
            Ok::<(), dcroxide_database::Error>(())
        })();
        db_tx.rollback()?;
        res?;
        Ok(())
    }
}

/// The open bucket id, if any.
fn bucket_id(bucket: &AtomicU64) -> Option<[u8; 4]> {
    let raw = bucket.load(Ordering::SeqCst);
    u32::try_from(raw).ok().map(u32::to_be_bytes)
}

/// The mempool's hook into the unconfirmed overlay, detached from the
/// index mutex (dcrd `ExistsAddrIndex.AddUnconfirmedTx`, which takes
/// `unconfirmedLock` and nothing else).
///
/// The mempool records every accepted transaction here while it holds
/// its own pool mutex.  Reached through `Arc<Mutex<ExistsAddrIndex>>`,
/// that record would wait for as long as the index writer holds the
/// index mutex — through its wait for the database writer and a whole
/// block's index work — and every caller queued on the pool mutex would
/// wait with it.  The overlay has its own lock, so the hook takes a
/// handle once and never touches the index mutex.
#[derive(Clone)]
pub struct ExistsAddrUnconfirmed {
    chain: Arc<dyn ChainQueryer>,
    mp_exists_addr: Unconfirmed,
}

impl ExistsAddrUnconfirmed {
    /// Add all addresses related to the transaction to the
    /// unconfirmed (memory-only) exists address index (dcrd
    /// `AddUnconfirmedTx`).
    pub fn add_unconfirmed_tx(&self, tx: &MsgTx) {
        let params = self.chain.chain_params();
        let is_sstx = dcroxide_stake::is_sstx(tx);
        let mut keys: Vec<[u8; ADDR_KEY_SIZE]> = Vec::new();
        for tx_in in &tx.tx_in {
            // Note that the functions used here require v0 scripts.
            if !stdscript::is_multi_sig_sig_script_v0(&tx_in.signature_script) {
                continue;
            }
            let Some(rs) =
                stdscript::multi_sig_redeem_script_from_script_sig_v0(&tx_in.signature_script)
            else {
                continue;
            };
            let (script_type, addrs) = stdscript::extract_addrs_v0(rs, params);
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

        let mut overlay = self
            .mp_exists_addr
            .write()
            .expect("unconfirmed overlay lock poisoned");
        for k in keys {
            overlay.insert(k);
        }
    }
}

impl ExistsAddrIndex {
    /// Create the exists address index, subscribe it for updates, and
    /// initialize it (dcrd `NewExistsAddrIndex` +
    /// `ExistsAddrIndex.Init`).
    pub fn new(
        subscriber: &mut IndexSubscriber,
        db: Arc<Database>,
        chain: Arc<dyn ChainQueryer>,
    ) -> Result<Arc<std::sync::Mutex<ExistsAddrIndex>>, IdxError> {
        ExistsAddrIndex::new_with_prereq(subscriber, db, chain, NO_PREREQS)
    }

    /// [`new`](Self::new) with an explicit prerequisite subscription;
    /// dcrd always subscribes this index without one, but the update
    /// relay hierarchy is exercised through this hook.
    pub fn new_with_prereq(
        subscriber: &mut IndexSubscriber,
        db: Arc<Database>,
        chain: Arc<dyn ChainQueryer>,
        prereq: &str,
    ) -> Result<Arc<std::sync::Mutex<ExistsAddrIndex>>, IdxError> {
        ExistsAddrIndex::new_with_policy(subscriber, db, chain, prereq, Policy::default())
    }

    /// [`new_with_prereq`](Self::new_with_prereq) with the memtable and
    /// merge tuning given: the daemon passes the defaults, or what the
    /// developer-only `DCROXIDE_EXISTSADDR_MEMTABLE_KEYS` sets, and tests
    /// pass [`Policy::tiny`].
    ///
    /// Initialization, in order: finish an interrupted drop; refuse an
    /// index of any version but this one's (there is no migration);
    /// create the index as needed; load the memtable from the journal;
    /// register the index as the database's flush participant; recover a
    /// tip that left the main chain.
    ///
    /// The index is the database's only flush participant, so one already
    /// registered is an earlier instance of this index on the same
    /// database, as a test re-creating the index makes.  It is retired:
    /// a flush journals what it holds, it is released, and this instance
    /// loads again.  It must not be fed notifications after that.
    pub fn new_with_policy(
        subscriber: &mut IndexSubscriber,
        db: Arc<Database>,
        chain: Arc<dyn ChainQueryer>,
        prereq: &str,
        policy: Policy,
    ) -> Result<Arc<std::sync::Mutex<ExistsAddrIndex>>, IdxError> {
        let idx = Arc::new(std::sync::Mutex::new(ExistsAddrIndex {
            db,
            chain,
            mp_exists_addr: Arc::new(std::sync::RwLock::new(HashSet::new())),
            store: Arc::new(AddrStore::new(policy)),
            bucket: Arc::new(AtomicU64::new(NO_BUCKET)),
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
        let log = subscriber.log().cloned();
        let log = log.as_ref();
        if crate::common::interrupt_requested(&interrupt) {
            return Err(indexer_error(
                ErrorKind::InterruptRequested,
                crate::common::INTERRUPT_MSG,
            ));
        }
        {
            let genesis_hash = {
                let borrowed = idx.lock().expect("indexer lock poisoned");
                let params = borrowed.chain.chain_params();
                params.genesis_hash
            };
            let borrowed = idx.lock().expect("indexer lock poisoned");
            // Finish any drops that were previously interrupted.
            crate::common::finish_drop(&interrupt, &*borrowed, log)?;
            // Refuse an index this build cannot read.
            borrowed.check_version()?;
            // Create the initial state for the index as needed.
            crate::common::create_index(&*borrowed, &genesis_hash)?;
            // Upgrade the index as needed.
            crate::common::upgrade_index(&interrupt, &*borrowed, &genesis_hash, log)?;
            // Load the memtable and hand the index's rows to the flush.
            borrowed.open_store()?;
        }

        // Recover the exists address index and its dependents to the
        // main chain if needed.
        subscriber.recover_index(EXISTS_ADDRESS_INDEX_NAME)?;

        Ok(idx)
    }

    /// Refuse an existing index whose version is not this build's.
    ///
    /// dcrd's `upgradeIndex` comment intends a drop and rebuild for an
    /// old version; this port refuses instead, so that a rebuild from
    /// genesis is never silent, and names the two flags that do it.
    fn check_version(&self) -> Result<(), IdxError> {
        let db_tx = self.db.begin(false)?;
        let res = (|| {
            let has_tip = db_tx
                .metadata()
                .bucket(crate::common::INDEX_TIPS_BUCKET_NAME)
                .is_some_and(|bucket| bucket.get(EXISTS_ADDR_INDEX_KEY).is_some());
            if !has_tip {
                return Ok(None);
            }
            db_fetch_indexer_version(&db_tx, EXISTS_ADDR_INDEX_KEY).map(Some)
        })();
        db_tx.rollback()?;
        let found = match res? {
            None | Some(Some(EXISTS_ADDR_INDEX_VERSION)) => return Ok(()),
            Some(Some(version)) => format!("on-disk version {version}"),
            Some(None) => "on-disk index, which has no version row,".to_string(),
        };
        Err(IdxError::Other(format!(
            "{EXISTS_ADDRESS_INDEX_NAME}: {found} is not supported by this build; run once with \
             --noexistsaddrindex --dropexistsaddrindex, then restart to rebuild it from genesis"
        )))
    }

    /// Load the store from the journal and register it as the database's
    /// flush participant, under the bucket's id.
    fn open_store(&self) -> Result<(), IdxError> {
        let bucket = self.load_store()?;
        let participant = || Arc::clone(&self.store) as Arc<dyn FlushParticipant>;
        match self.db.set_flush_participant(&bucket, participant()) {
            Ok(()) => {}
            Err(err) if err.kind == dcroxide_database::ErrorKind::DriverSpecific => {
                // An earlier instance of this index (see
                // `new_with_policy`): journal what it holds, release it,
                // and read the journal again.
                self.db.flush()?;
                drop(self.db.clear_flush_participant());
                let again = self.load_store()?;
                debug_assert_eq!(again, bucket);
                self.db.set_flush_participant(&bucket, participant())?;
            }
            Err(err) => return Err(err.into()),
        }
        self.bucket
            .store(u64::from(u32::from_be_bytes(bucket)), Ordering::SeqCst);
        Ok(())
    }

    /// Read the meta row and the journal into the store; returns the
    /// bucket's id.
    fn load_store(&self) -> Result<[u8; 4], IdxError> {
        let db_tx = self.db.begin(false)?;
        let res = (|| {
            let meta = db_tx.metadata();
            let bucket = meta.bucket(EXISTS_ADDR_INDEX_KEY).ok_or_else(|| {
                crate::common::make_db_err(
                    dcroxide_database::ErrorKind::BucketNotFound,
                    format!(
                        "{} bucket not found",
                        String::from_utf8_lossy(EXISTS_ADDR_INDEX_KEY)
                    ),
                )
            })?;
            let loaded = store::load(&db_tx, &bucket)?;
            Ok::<_, IdxError>((bucket.raw_id(), loaded))
        })();
        db_tx.rollback()?;
        let (bucket, loaded) = res?;
        self.store.install(loaded)?;
        Ok(bucket)
    }

    /// A lookup handle that does not borrow the index (dcrd's queries
    /// take no index-wide lock).
    ///
    /// Callers holding `Arc<Mutex<ExistsAddrIndex>>` should take this,
    /// drop the index guard, and only then query — see
    /// [`ExistsAddrQuery`] for why the guard must not span the database
    /// reads.
    pub fn query(&self) -> ExistsAddrQuery {
        ExistsAddrQuery {
            db: Arc::clone(&self.db),
            mp_exists_addr: Arc::clone(&self.mp_exists_addr),
            store: Arc::clone(&self.store),
            bucket: Arc::clone(&self.bucket),
        }
    }

    /// Every key the index holds, sorted, each once: the memtable plus
    /// both runs of every partition.  Reads every run row, so it is for
    /// tests and diagnostics, never a lookup; the indexer vectors compare
    /// it with dcrd's bucket rows.
    #[doc(hidden)]
    pub fn logical_keys(&self) -> Result<Vec<[u8; ADDR_KEY_SIZE]>, IdxError> {
        // Memory first, then a read transaction begun after it: a key a
        // flush moves from one to the other in between is in the runs.
        let mut keys = self.store.mem.snapshot();
        if let Some(bucket) = bucket_id(&self.bucket) {
            let part = self.store.partitioner();
            let db_tx = self.db.begin(false)?;
            let runs = store::run_keys(&db_tx, &part, &bucket);
            db_tx.rollback()?;
            keys.extend(runs?);
        }
        keys.sort_unstable();
        keys.dedup();
        Ok(keys)
    }

    /// The memtable's keys, sorted: what a restart must rebuild from the
    /// journal.  For tests.
    #[doc(hidden)]
    pub fn memtable_keys(&self) -> Vec<[u8; ADDR_KEY_SIZE]> {
        self.store.mem.snapshot()
    }

    /// The mempool's handle on the unconfirmed overlay, which does not
    /// borrow the index (dcrd's `AddUnconfirmedTx` takes no index-wide
    /// lock); see [`ExistsAddrUnconfirmed`].
    pub fn unconfirmed(&self) -> ExistsAddrUnconfirmed {
        ExistsAddrUnconfirmed {
            chain: Arc::clone(&self.chain),
            mp_exists_addr: Arc::clone(&self.mp_exists_addr),
        }
    }

    /// Whether or not an address has been seen before (dcrd
    /// `ExistsAddress`).
    pub fn exists_address(&self, addr: &Address) -> Result<bool, IdxError> {
        self.query().exists_address(addr)
    }

    /// Whether or not each address in a slice of addresses has been
    /// seen before (dcrd `ExistsAddresses`).
    pub fn exists_addresses(&self, addrs: &[Address]) -> Result<Vec<bool>, IdxError> {
        self.query().exists_addresses(addrs)
    }

    /// Add all addresses associated with transactions in the provided
    /// block and flush the unconfirmed overlay (dcrd
    /// `ExistsAddrIndex.connectBlock`).
    ///
    /// The address extraction and the tip row are dcrd's.  The keys do
    /// not go through the transaction: they are handed to the memtable by
    /// an `on_commit` hook, which runs once the commit's own flush has
    /// succeeded and before the tip row is published.  So no flush can
    /// journal them without their tip row or persist the tip row without
    /// them, a reader that sees the tip finds them, and a commit that
    /// fails hands nothing over.  The block's candidates are filtered
    /// against the memtable only, with no store read; a key already in a
    /// run is merged away as a duplicate later.
    ///
    /// dcrd drains the unconfirmed overlay into the block's keys.  This
    /// copies it, and the hook removes exactly the copied keys after
    /// inserting them, so a key is always in one place a lookup reads;
    /// keys added after the copy stay for the next connect, as they stay
    /// in dcrd's fresh map, and a rolled-back connect leaves the overlay
    /// as it was.
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
                let (typ, addrs) = stdscript::extract_addrs_v0(rs, params);
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

        // Hand all the newly used addresses to the memtable, skipping any
        // it already holds, along with any addresses seen in mempool at
        // this time; the hook then removes those from the unconfirmed
        // map.
        let copied: Vec<[u8; ADDR_KEY_SIZE]> = self
            .mp_exists_addr
            .read()
            .expect("unconfirmed overlay lock poisoned")
            .iter()
            .copied()
            .collect();
        used_addrs.extend(copied.iter().copied());
        let part = self.store.partitioner();
        let mut candidates: Vec<(u8, [u8; ADDR_KEY_SIZE])> = used_addrs
            .into_iter()
            .map(|k| (part.of(&k), k))
            .filter(|(p, k)| !self.store.mem.contains(*p, k))
            .collect();
        // By partition, so the hook takes each partition's lock once and
        // hashes nothing under the writer semaphore.
        candidates.sort_unstable();

        let meta = db_tx.metadata();
        meta.bucket(EXISTS_ADDR_INDEX_KEY).ok_or_else(|| {
            crate::common::make_db_err(
                dcroxide_database::ErrorKind::BucketNotFound,
                format!(
                    "{} bucket not found",
                    String::from_utf8_lossy(EXISTS_ADDR_INDEX_KEY)
                ),
            )
        })?;

        // Update the current index tip.
        db_put_indexer_tip(
            db_tx,
            EXISTS_ADDR_INDEX_KEY,
            &block.header.block_hash(),
            block_height(block) as i32,
        )?;

        let store = Arc::clone(&self.store);
        let overlay = Arc::clone(&self.mp_exists_addr);
        let hand_over = move || {
            // The commit's own flush may have merged some candidates'
            // partitions since they were filtered; the insert checks
            // again.
            store.mem.insert_candidates(&candidates);
            let mut overlay = overlay.write().expect("unconfirmed overlay lock poisoned");
            for key in &copied {
                overlay.remove(key);
            }
        };
        #[cfg(test)]
        if self.store.faults.hook_after_publish.load(Ordering::SeqCst) {
            self.store
                .faults
                .deferred
                .lock()
                .expect("deferred hooks")
                .push(Box::new(hand_over));
            return Ok(());
        }
        db_tx.on_commit(hand_over)?;
        Ok(())
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
    pub fn add_unconfirmed_tx(&self, tx: &MsgTx) {
        self.unconfirmed().add_unconfirmed_tx(tx);
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

    fn db(&self) -> Arc<Database> {
        self.db.clone()
    }

    fn queryer(&self) -> Arc<dyn ChainQueryer> {
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
        let waiter: SyncWaiter = Arc::new(core::sync::atomic::AtomicBool::new(false));
        self.subscribers.push(waiter.clone());
        waiter
    }

    fn notify_sync_subscribers(&mut self) {
        notify_sync_subscribers(&mut self.subscribers);
    }

    fn has_sync_subscribers(&self) -> bool {
        !self.subscribers.is_empty()
    }

    fn drop_index(
        &self,
        interrupt: &Interrupt,
        db: &Database,
        log: Option<&LogSink>,
    ) -> Result<(), IdxError> {
        // Detach first, so no flush the drop's deletions trigger writes
        // the index's rows back, and forget the memory, so this handle's
        // lookups stop answering from it.
        drop(db.clear_flush_participant());
        self.bucket.store(NO_BUCKET, Ordering::SeqCst);
        self.store.reset();
        drop_exists_addr_index(interrupt, db, log)
    }
}

#[cfg(test)]
impl ExistsAddrIndex {
    /// The store, for the in-crate tests and their fault switches.
    pub(crate) fn store(&self) -> &Arc<AddrStore> {
        &self.store
    }

    /// Run the hand-overs `Faults::hook_after_publish` deferred.
    pub(crate) fn run_deferred(&self) {
        let deferred =
            std::mem::take(&mut *self.store.faults.deferred.lock().expect("deferred hooks"));
        for hand_over in deferred {
            hand_over();
        }
    }
}

/// Drop the exists address index from the provided database if it
/// exists (dcrd `DropExistsAddrIndex`), logging its progress to `log`
/// as dcrd logs it to the package logger (see [`LogSink`]).
///
/// Any registered flush participant -- a live instance of this index --
/// is released first, or the flushes the drop's deletions trigger would
/// write its rows back, and the database would refuse the deletions
/// themselves.  The walk is dcrd's flat drop over every row, so it serves
/// either layout, and its "Deleted N keys" lines count rows: for layout 3
/// those are meta, journal and run rows, modelled at 0.4-0.5 million on
/// mainnet, not the 49-68 million addresses they hold (PARITY.md).
pub fn drop_exists_addr_index(
    interrupt: &Interrupt,
    db: &Database,
    log: Option<&LogSink>,
) -> Result<(), IdxError> {
    drop(db.clear_flush_participant());
    drop_flat_index(
        interrupt,
        db,
        EXISTS_ADDR_INDEX_KEY,
        EXISTS_ADDRESS_INDEX_NAME,
        log,
    )
}
