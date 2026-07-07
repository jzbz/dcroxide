// SPDX-License-Identifier: ISC
//! An in-memory pool of mixing messages for full nodes that relay
//! these messages and mixing wallets that send and receive them (dcrd
//! `mixing/mixpool`), including the misbehavior observer.
//!
//! dcrd guards the pool with mutexes, delivers `Receive` results by
//! blocking on a broadcast channel, and runs background expiry and
//! observer goroutines; this port is synchronous with identical state
//! transitions: `receive` collects what is currently accepted
//! (matching dcrd's pre-cancelled-context path, which is also what
//! the observer uses), and the scheduled expiry latch is exposed for
//! the daemon to drive.  The clock is injectable so expiration
//! behavior is fully deterministic under test.

// Bounded pool arithmetic mirrors Go; genuinely wrapping math uses
// explicit wrapping operations.
#![allow(clippy::arithmetic_side_effects)]

use core::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use dcroxide_chaincfg::Params;
use dcroxide_chainhash::Hash;
use dcroxide_containers::lru;
use dcroxide_txscript::stdaddr::hash160;
use dcroxide_txscript::stdscript;
use dcroxide_wire::{
    MixVect, MsgMixCiphertexts, MsgMixConfirm, MsgMixDCNet, MsgMixFactoredPoly, MsgMixKeyExchange,
    MsgMixPairReq, MsgMixSecrets, MsgMixSlotReserve, MsgTx, OutPoint, ServiceFlag,
    var_int_serialize_size,
};

use crate::signatures::MixMessage;
use crate::{
    MAX_MCOUNT, MAX_MIX_AMOUNT, MAX_MIX_TX_SERIALIZE_SIZE, MAX_MTOT, MAX_PEERS, MIN_PEERS,
    SCRIPT_CLASS_P2PKH_V0, max_expiry, validate_secp256k1_p2pkh, validate_session,
    verify_signed_message,
};

const MINCONF: i64 = 1;
const FEE_RATE: i64 = 10_000; // 0.0001e8
const MAX_RELAY_FEE_MULTIPLIER: i64 = 10_000; // 1e4
const EARLY_KE_DURATION_NANOS: i64 = 5_000_000_000; // 5 seconds

/// The maximum number of orphans allowed in the orphan pool at one
/// time (dcrd `maxOrphans`).
pub const MAX_ORPHANS: usize = 250;

/// The maximum number of orphans to keep in the pool after a forced
/// eviction occurs: 75% of the overall max limit (dcrd
/// `maxPostEvictionOrphans`).
pub const MAX_POST_EVICTION_ORPHANS: usize = MAX_ORPHANS * 3 / 4;

// Recently removed mix message cache parameters (dcrd
// `maxRecentlyRemovedMixMsgs`, `maxRecentMixMsgsTTL`).
const MAX_RECENTLY_REMOVED_MIX_MSGS: u32 = 8_500;
const MAX_RECENT_MIX_MSGS_TTL_NANOS: i64 = 60_000_000_000; // 1 minute

const STRIKE_LIMIT: usize = 2;

/// The orphan receive-time and key-exchange epoch expiration cutoff
/// (20 minutes, in nanoseconds).
const ORPHAN_EXPIRY_NANOS: i64 = 20 * 60 * 1_000_000_000;

type IdPubKey = [u8; 33];
type OutPointKey = ([u8; 32], u32, i8);
type ActivePeers = HashMap<IdPubKey, (MsgMixPairReq, Vec<MsgMixKeyExchange>)>;

fn op_key(op: &OutPoint) -> OutPointKey {
    (op.hash.0, op.index, op.tree)
}

/// The non-PR message type tags (dcrd `msgtype`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MsgType {
    /// A key exchange.
    KE,
    /// Ciphertexts.
    CT,
    /// A slot reservation.
    SR,
    /// A DC-net broadcast.
    DC,
    /// A confirmation.
    CM,
    /// A factored polynomial.
    FP,
    /// Revealed secrets.
    RS,
}

impl core::fmt::Display for MsgType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            MsgType::KE => "KE",
            MsgType::CT => "CT",
            MsgType::SR => "SR",
            MsgType::DC => "DC",
            MsgType::CM => "CM",
            MsgType::FP => "FP",
            MsgType::RS => "RS",
        };
        f.write_str(s)
    }
}

/// Any mixing message accepted by the pool (dcrd passes
/// `mixing.Message` interface values; the closed set is modeled as an
/// enum).
#[derive(Clone)]
pub enum PoolMessage {
    /// A pair request.
    PR(MsgMixPairReq),
    /// A key exchange.
    KE(Box<MsgMixKeyExchange>),
    /// Ciphertexts.
    CT(MsgMixCiphertexts),
    /// A slot reservation.
    SR(MsgMixSlotReserve),
    /// A DC-net broadcast.
    DC(MsgMixDCNet),
    /// A confirmation.
    CM(MsgMixConfirm),
    /// A factored polynomial.
    FP(MsgMixFactoredPoly),
    /// Revealed secrets.
    RS(MsgMixSecrets),
}

impl PoolMessage {
    fn as_mix_message(&self) -> &dyn MixMessage {
        match self {
            PoolMessage::PR(m) => m,
            PoolMessage::KE(m) => &**m,
            PoolMessage::CT(m) => m,
            PoolMessage::SR(m) => m,
            PoolMessage::DC(m) => m,
            PoolMessage::CM(m) => m,
            PoolMessage::FP(m) => m,
            PoolMessage::RS(m) => m,
        }
    }

    /// The mixing message identity hash.
    pub fn mix_hash(&self) -> Result<Hash, PoolError> {
        self.as_mix_message()
            .mix_hash()
            .map_err(|err| PoolError::Other(format!("unable to hash message: {err}")))
    }

    /// The message sender's public key identity.
    pub fn identity(&self) -> IdPubKey {
        let mut id = [0u8; 33];
        id.copy_from_slice(self.as_mix_message().pub_key());
        id
    }

    /// The session ID, when the message carries one.
    pub fn sid(&self) -> Option<[u8; 32]> {
        self.as_mix_message().sid()
    }

    /// The run number.
    pub fn run(&self) -> u32 {
        self.as_mix_message().run()
    }

    fn msgtype(&self) -> Option<MsgType> {
        match self {
            PoolMessage::PR(_) => None,
            PoolMessage::KE(_) => Some(MsgType::KE),
            PoolMessage::CT(_) => Some(MsgType::CT),
            PoolMessage::SR(_) => Some(MsgType::SR),
            PoolMessage::DC(_) => Some(MsgType::DC),
            PoolMessage::CM(_) => Some(MsgType::CM),
            PoolMessage::FP(_) => Some(MsgType::FP),
            PoolMessage::RS(_) => Some(MsgType::RS),
        }
    }
}

/// The bannable rule violations (dcrd's named bannable errors).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleKind {
    /// A pair request's change amount is dust (dcrd `ErrChangeDust`).
    ChangeDust,
    /// A pair request's mix amount value is dust (dcrd `ErrMixDust`).
    MixDust,
    /// Not enough input value, or too low fee (dcrd `ErrLowInput`).
    LowInput,
    /// Too much contributed fee (dcrd `ErrHighFee`).
    HighFee,
    /// An invalid pair request message count (dcrd
    /// `ErrInvalidMessageCount`).
    InvalidMessageCount,
    /// An invalid script (dcrd `ErrInvalidScript`).
    InvalidScript,
    /// An invalid session ID (dcrd `ErrInvalidSessionID`).
    InvalidSessionID,
    /// The message is not properly signed for the claimed identity
    /// (dcrd `ErrInvalidSignature`).
    InvalidSignature,
    /// The product of message count and mix amount exceeds the total
    /// input value (dcrd `ErrInvalidTotalMixAmount`).
    InvalidTotalMixAmount,
    /// A pair request fails to prove ownership of each UTXO (dcrd
    /// `ErrInvalidUTXOProof`).
    InvalidUTXOProof,
    /// A pair request references no UTXOs (dcrd `ErrMissingUTXOs`).
    MissingUTXOs,
    /// A peer position outside the seen PRs bounds (dcrd
    /// `ErrPeerPositionOutOfBounds`).
    PeerPositionOutOfBounds,
    /// Any other rule violation (dcrd's ad hoc `fmt.Errorf` rule
    /// errors); not bannable.
    Other(String),
}

impl RuleKind {
    /// The peer service capabilities that make this rule violation an
    /// automatic bannable offense (dcrd's `bannableError.services`);
    /// `None` for non-bannable ad hoc violations.
    fn bannable_services(&self) -> Option<ServiceFlag> {
        match self {
            RuleKind::InvalidUTXOProof => Some(ServiceFlag::NODE_NETWORK),
            RuleKind::Other(_) => None,
            _ => Some(ServiceFlag(0)),
        }
    }

    fn message(&self) -> String {
        match self {
            RuleKind::ChangeDust => "change output is dust".into(),
            RuleKind::MixDust => "mix output is dust".into(),
            RuleKind::LowInput => "not enough input value, or too low fee".into(),
            RuleKind::HighFee => "too high fee".into(),
            RuleKind::InvalidMessageCount => "message count must be positive".into(),
            RuleKind::InvalidScript => "invalid script".into(),
            RuleKind::InvalidSessionID => "invalid session ID".into(),
            RuleKind::InvalidSignature => "invalid message signature".into(),
            RuleKind::InvalidTotalMixAmount => "invalid total mix amount".into(),
            RuleKind::InvalidUTXOProof => "invalid UTXO ownership proof".into(),
            RuleKind::MissingUTXOs => "pair request contains no UTXOs".into(),
            RuleKind::PeerPositionOutOfBounds => {
                "peer position cannot be a valid seen PRs index".into()
            }
            RuleKind::Other(msg) => msg.clone(),
        }
    }
}

/// Errors surfaced by the pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PoolError {
    /// A mixpool rule violation (dcrd `RuleError`).
    Rule(RuleKind),
    /// A key exchange does not reference the owner's own pair
    /// request; the KE is recorded as an orphan and may be processed
    /// later (dcrd `MissingOwnPRError`).
    MissingOwnPR(Hash),
    /// A message was not found (dcrd `errMessageNotFound`).
    MessageNotFound,
    /// Any peer unexpectedly revealed their secrets during a run
    /// stage (dcrd `ErrSecretsRevealed`).
    SecretsRevealed,
    /// A UTXO fetch failure (dcrd propagates the fetcher's error).
    UtxoFetch(String),
    /// Any other failure.
    Other(String),
}

impl PoolError {
    /// Whether the error condition is such that the peer with
    /// capabilities defined by services who sent the message should
    /// be immediately banned (dcrd `IsBannable`).
    pub fn is_bannable(&self, services: ServiceFlag) -> bool {
        match self {
            PoolError::Rule(kind) => match kind.bannable_services() {
                Some(required) => required.0 & services.0 == required.0,
                None => false,
            },
            _ => false,
        }
    }
}

impl core::fmt::Display for PoolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PoolError::Rule(kind) => f.write_str(&kind.message()),
            PoolError::MissingOwnPR(_) => {
                f.write_str("KE identity's own PR is missing from mixpool")
            }
            PoolError::MessageNotFound => f.write_str("message not found"),
            PoolError::SecretsRevealed => f.write_str("secrets revealed by peer"),
            PoolError::UtxoFetch(msg) | PoolError::Other(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for PoolError {}

fn rule(kind: RuleKind) -> PoolError {
    PoolError::Rule(kind)
}

fn rule_other(msg: impl Into<String>) -> PoolError {
    PoolError::Rule(RuleKind::Other(msg.into()))
}

/// Details regarding unspent transaction outputs (dcrd mixpool
/// `UtxoEntry`).
pub trait MixUtxoEntry {
    /// Whether the output is spent.
    fn is_spent(&self) -> bool;
    /// The public key script.
    fn pk_script(&self) -> &[u8];
    /// The script version.
    fn script_version(&self) -> u16;
    /// The height of the block containing the output.
    fn block_height(&self) -> i64;
    /// The output value.
    fn amount(&self) -> i64;
}

/// Methods used to validate unspent transaction outputs in the pair
/// request message (dcrd `UtxoFetcher`).  It is optional, but should
/// be implemented by full nodes to detect and stop relay of spam.
pub trait MixUtxoFetcher {
    /// Fetch unspent transaction output information.
    fn fetch_utxo_entry(&self, op: &OutPoint) -> Result<Box<dyn MixUtxoEntry>, String>;
}

/// Queries the current status of the blockchain (dcrd mixpool
/// `BlockChain`); implementable by both full nodes and SPV wallets.
pub trait MixBlockChain {
    /// The chain parameters the mixing pool is associated with.
    fn chain_params(&self) -> &Params;
    /// The hash and height of the current tip block.
    fn current_tip(&self) -> (Hash, i64);
}

/// A non-PR message accepted to the pool (dcrd `entry`).
struct Entry {
    sid: [u8; 32],
    recv_time: i64,
    msg: PoolMessage,
    msgtype: MsgType,
}

struct OrphanMsg {
    message: PoolMessage,
    src: u64,
    accepted: i64,
}

struct Session {
    sid: [u8; 32],
    prs: Vec<Hash>,
    counts: [u32; 7],
    hashes: HashSet<[u8; 32]>,
    expiry: u32,
}

impl Session {
    fn count_for(&self, t: MsgType) -> u32 {
        self.counts[t as usize]
    }
    fn increment_count_for(&mut self, t: MsgType) {
        self.counts[t as usize] += 1;
    }
}

type StrikeSetRef = Rc<RefCell<StrikeSet>>;

struct StrikeSet {
    set: HashSet<OutPointKey>,
    strikes: Vec<u64>,
}

/// Sort and remove duplicates of all epoch strike times (dcrd
/// `sortUniq`).
fn sort_uniq(mut strikes: Vec<u64>) -> Vec<u64> {
    strikes.sort_unstable();
    strikes.dedup();
    strikes
}

/// In-memory mix messages that have been broadcast over the
/// peer-to-peer network (dcrd `Pool`), including the misbehavior
/// observer state (dcrd `Observer`).
pub struct Pool<B: MixBlockChain> {
    prs: HashMap<[u8; 32], MsgMixPairReq>,
    out_points: HashMap<OutPointKey, Hash>,
    pool: HashMap<[u8; 32], Entry>,
    orphans: HashMap<[u8; 32], Rc<OrphanMsg>>,
    orphans_by_id: HashMap<IdPubKey, HashMap<[u8; 32], Rc<OrphanMsg>>>,
    messages_by_identity: HashMap<IdPubKey, Vec<Hash>>,
    latest_ke: HashMap<IdPubKey, MsgMixKeyExchange>,
    sessions: HashMap<[u8; 32], Session>,
    // Maps mix transaction hashes to session IDs; dcrd retains stale
    // entries for removed sessions and so does this port.
    sessions_by_tx_hash: HashMap<[u8; 32], [u8; 32]>,
    epoch_secs: i64,
    expire_height: u32,

    recent_mix_msgs: lru::Map<[u8; 32], PoolMessage>,

    blockchain: B,
    utxo_fetcher: Option<Rc<dyn MixUtxoFetcher>>,
    fee_rate: i64,

    // Observer state (dcrd `Observer.strikes`).
    strikes: HashMap<OutPointKey, StrikeSetRef>,

    now_fn: lru::Clock,
}

impl<B: MixBlockChain> Pool<B> {
    /// A new mixing pool that accepts and validates mixing messages
    /// required for distributed transaction mixing (dcrd `NewPool`).
    /// Pass a fetcher when UTXO validation capability is available
    /// (dcrd type-asserts this from the blockchain).
    pub fn new(blockchain: B, utxo_fetcher: Option<Rc<dyn MixUtxoFetcher>>) -> Pool<B> {
        Pool::new_with_clock(
            blockchain,
            utxo_fetcher,
            // The LRU clock must be Send + Sync, unlike the mixpool's
            // single-threaded internal Rc structures.
            std::sync::Arc::new(|| {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos() as i64)
                    .unwrap_or_default()
            }),
        )
    }

    /// [`new`](Pool::new) with an injectable clock; exposed so tests
    /// can control expiration deterministically.
    #[doc(hidden)]
    pub fn new_with_clock(
        blockchain: B,
        utxo_fetcher: Option<Rc<dyn MixUtxoFetcher>>,
        now_fn: lru::Clock,
    ) -> Pool<B> {
        // XXX (dcrd): mainnet epoch; add to chainparams.
        let mut epoch_secs = 10 * 60;
        if blockchain.chain_params().net == dcroxide_wire::CurrencyNet::TEST_NET3 {
            epoch_secs = 3 * 60;
        }
        Pool {
            prs: HashMap::new(),
            out_points: HashMap::new(),
            pool: HashMap::new(),
            orphans: HashMap::new(),
            orphans_by_id: HashMap::new(),
            messages_by_identity: HashMap::new(),
            latest_ke: HashMap::new(),
            sessions: HashMap::new(),
            sessions_by_tx_hash: HashMap::new(),
            epoch_secs,
            expire_height: 0,
            recent_mix_msgs: lru::Map::new_with_default_ttl_and_clock(
                MAX_RECENTLY_REMOVED_MIX_MSGS,
                MAX_RECENT_MIX_MSGS_TTL_NANOS,
                now_fn.clone(),
            ),
            blockchain,
            utxo_fetcher,
            fee_rate: FEE_RATE,
            strikes: HashMap::new(),
            now_fn,
        }
    }

    /// The duration between mix epochs, in seconds (dcrd `Epoch`).
    pub fn epoch_secs(&self) -> i64 {
        self.epoch_secs
    }

    /// Search the mixing pool for a message by its hash (dcrd
    /// `Message`).
    pub fn message(&self, query: &Hash) -> Result<PoolMessage, PoolError> {
        if let Some(pr) = self.prs.get(&query.0) {
            return Ok(PoolMessage::PR(pr.clone()));
        }
        match self.pool.get(&query.0) {
            Some(e) => Ok(e.msg.clone()),
            None => Err(PoolError::MessageNotFound),
        }
    }

    /// Whether the mixing pool contains a message by its hash (dcrd
    /// `HaveMessage`).
    pub fn have_message(&self, query: &Hash) -> bool {
        self.pool.contains_key(&query.0) || self.prs.contains_key(&query.0)
    }

    /// Attempt to find a message by its hash in both the mixing pool
    /// and the cache of recently removed messages (dcrd
    /// `RecentMessage`).
    pub fn recent_message(&mut self, query: &Hash) -> Option<PoolMessage> {
        if let Some(pr) = self.prs.get(&query.0) {
            return Some(PoolMessage::PR(pr.clone()));
        }
        if let Some(e) = self.pool.get(&query.0) {
            return Some(e.msg.clone());
        }
        self.recent_mix_msgs.get(&query.0)
    }

    /// All pair request messages, excluding any expired PRs that are
    /// still internally tracked for ongoing sessions (dcrd `MixPRs`).
    pub fn mix_prs(&mut self) -> Vec<MsgMixPairReq> {
        self.remove_confirmed_sessions();

        self.prs
            .values()
            .filter(|pr| pr.expiry > self.expire_height)
            .cloned()
            .collect()
    }

    /// All pair request messages with pairing descriptions matching
    /// the parameter, ordered lexicographically by hash (dcrd
    /// `CompatiblePRs`).
    pub fn compatible_prs(&self, pairing: &[u8]) -> Vec<MsgMixPairReq> {
        let mut res: Vec<&MsgMixPairReq> = self
            .prs
            .values()
            .filter(|pr| pr.pairing() == pairing)
            .collect();

        // Sort by decreasing expiries and remove any PRs double
        // spending an output with an earlier expiry.
        res.sort_by_key(|pr| core::cmp::Reverse(pr.expiry));
        let mut seen: HashMap<OutPointKey, u32> = HashMap::new();
        let mut keep = vec![true; res.len()];
        for (i, pr) in res.iter().enumerate() {
            for utxo in &pr.utxos {
                match seen.get(&op_key(&utxo.out_point)) {
                    None => {
                        seen.insert(op_key(&utxo.out_point), pr.expiry);
                    }
                    Some(&prev_expiry) if pr.expiry < prev_expiry => keep[i] = false,
                    Some(_) => {}
                }
            }
        }
        let mut filtered: Vec<MsgMixPairReq> = res
            .into_iter()
            .zip(&keep)
            .filter(|(_, k)| **k)
            .map(|(pr, _)| pr.clone())
            .collect();

        // Sort again lexicographically by hash.
        filtered.sort_by_key(|pr| pr.mix_hash().map(|h| h.0).unwrap_or_default());
        filtered
    }

    /// Latch the height for a scheduled expiry (dcrd
    /// `ExpireMessagesInBackground`, which additionally schedules
    /// [`expire_scheduled_messages`](Pool::expire_scheduled_messages)
    /// to run after the current epoch ends; the daemon phase owns
    /// that timer).
    pub fn expire_messages_in_background(&mut self, height: u32) {
        if self.expire_height == 0 {
            self.expire_height = height;
        }
    }

    /// Perform the expiry that dcrd's background task runs after its
    /// epoch sleep.
    pub fn expire_scheduled_messages(&mut self) {
        let height = self.expire_height;
        self.expire_height = 0;
        self.expire_messages_now(height);
    }

    /// Immediately expire all pair requests and sessions built from
    /// them that indicate expiry at or after a block height (dcrd
    /// `ExpireMessages`).
    pub fn expire_messages(&mut self, height: u32) {
        self.expire_messages_now(height);
        self.expire_height = 0;
    }

    fn expire_messages_now(&mut self, height: u32) {
        // Expire sessions and their messages.  Note that dcrd creates
        // every session with the maximum possible expiry (see
        // accept_ke), so in practice sessions only die through PR
        // expiry below.
        let expired_sids: Vec<[u8; 32]> = self
            .sessions
            .iter()
            .filter(|(_, ses)| ses.expiry <= height)
            .map(|(sid, _)| *sid)
            .collect();
        for sid in expired_sids {
            if let Some(ses) = self.sessions.remove(&sid) {
                for hash in &ses.hashes {
                    self.remove_message_by_hash(hash);
                }
            }
        }

        // Expire PRs and remove identity tracking.
        let expired_prs: Vec<MsgMixPairReq> = self
            .prs
            .values()
            .filter(|pr| pr.expiry <= height)
            .cloned()
            .collect();
        for pr in expired_prs {
            self.remove_pr(&pr);
        }

        // Expire orphans with old receive times, and in the case of
        // any orphan KE, expire those with old epochs.
        let now = (self.now_fn)();
        let expired_orphans: Vec<([u8; 32], IdPubKey)> = self
            .orphans
            .iter()
            .filter(|(_, o)| {
                let mut expire = now - o.accepted >= ORPHAN_EXPIRY_NANOS;
                if !expire && let PoolMessage::KE(ke) = &o.message {
                    let epoch_nanos = (ke.epoch as i64).wrapping_mul(1_000_000_000);
                    expire = now - epoch_nanos >= ORPHAN_EXPIRY_NANOS;
                }
                expire
            })
            .map(|(hash, o)| (*hash, o.message.identity()))
            .collect();
        for (hash, id) in expired_orphans {
            self.remove_orphan(&hash, &id);
        }
    }

    /// Remove the message associated with the passed hash from the
    /// pool and add it to the cache of recently removed mix messages
    /// (dcrd `removeMessage`).
    fn remove_message_by_hash(&mut self, hash: &[u8; 32]) {
        if let Some(e) = self.pool.remove(hash) {
            self.recent_mix_msgs.put(*hash, e.msg);
        }
    }

    /// Remove the message from the orphan pool and orphans-by-ID
    /// index (dcrd `removeOrphan`).
    fn remove_orphan(&mut self, hash: &[u8; 32], id: &IdPubKey) {
        self.orphans.remove(hash);
        if let Some(by_id) = self.orphans_by_id.get_mut(id) {
            by_id.remove(hash);
            if by_id.is_empty() {
                self.orphans_by_id.remove(id);
            }
        }
    }

    /// Remove up to the maximum specified number of orphan messages
    /// associated with the provided source ID (dcrd
    /// `removeOrphansBySourceID`).
    fn remove_orphans_by_source_id(&mut self, src_id: u64, max_to_evict: u64) -> u64 {
        let mut num_evicted = 0u64;
        let candidates: Vec<([u8; 32], IdPubKey)> = self
            .orphans
            .iter()
            .filter(|(_, o)| o.src == src_id)
            .map(|(hash, o)| (*hash, o.message.identity()))
            .collect();
        for (hash, id) in candidates {
            if num_evicted >= max_to_evict {
                break;
            }
            self.remove_orphan(&hash, &id);
            num_evicted += 1;
        }
        num_evicted
    }

    /// Remove a message that was rejected by the network (dcrd
    /// `RemoveMessage`).
    pub fn remove_message(&mut self, msg: &PoolMessage) -> Result<(), PoolError> {
        let msg_hash = msg.mix_hash()?;
        self.remove_message_by_hash(&msg_hash.0);
        if let PoolMessage::PR(pr) = msg {
            self.remove_pr(pr);
        }
        if let PoolMessage::KE(ke) = msg {
            self.latest_ke.remove(&ke.identity);
        }
        Ok(())
    }

    /// Remove the PRs and all session messages involving them from a
    /// completed session (dcrd `RemoveSession`).
    pub fn remove_session(&mut self, sid: [u8; 32]) {
        self.remove_session_internal(sid, None, true);
    }

    fn remove_session_internal(&mut self, sid: [u8; 32], tx_hash: Option<Hash>, success: bool) {
        let Some(ses) = self.sessions.remove(&sid) else {
            return;
        };

        // Delete PRs used to form the final run.
        let remove_prs: Vec<Hash> = if success { ses.prs.clone() } else { Vec::new() };

        let mut tx_hash = tx_hash;
        if tx_hash.is_some() || success {
            if tx_hash.is_none() {
                for h in &ses.hashes {
                    if let Some(e) = self.pool.get(h)
                        && let PoolMessage::CM(cm) = &e.msg
                    {
                        tx_hash = Some(cm.mix.tx_hash());
                        break;
                    }
                }
            }
            if let Some(tx_hash) = &tx_hash {
                self.sessions_by_tx_hash.remove(&tx_hash.0);
            }
        }

        for hash in &ses.hashes {
            self.remove_message_by_hash(hash);
        }

        for pr_hash in &remove_prs {
            self.remove_message_by_hash(&pr_hash.0);
            if let Some(pr) = self.prs.get(&pr_hash.0).cloned() {
                self.remove_pr(&pr);
            }
        }
    }

    /// Remove all messages including pair requests from runs which
    /// ended in each peer sending a confirm mix message (dcrd
    /// `RemoveConfirmedSessions`).
    pub fn remove_confirmed_sessions(&mut self) {
        let complete: Vec<[u8; 32]> = self
            .sessions
            .iter()
            .filter(|(_, ses)| ses.prs.len() as u32 == ses.count_for(MsgType::CM))
            .map(|(sid, _)| *sid)
            .collect();
        for sid in complete {
            let Some(ses) = self.sessions.remove(&sid) else {
                continue;
            };
            for hash in &ses.hashes {
                self.remove_message_by_hash(hash);
            }
            for pr_hash in &ses.prs {
                self.remove_message_by_hash(&pr_hash.0);
                if let Some(pr) = self.prs.get(&pr_hash.0).cloned() {
                    self.remove_pr(&pr);
                }
            }
        }
    }

    /// Remove sessions and messages belonging to a completed session
    /// that resulted in published or mined transactions (dcrd
    /// `RemoveConfirmedMixes`).
    pub fn remove_confirmed_mixes(&mut self, tx_hashes: &[Hash]) {
        for hash in tx_hashes {
            let Some(sid) = self.sessions_by_tx_hash.get(&hash.0).copied() else {
                continue;
            };
            self.remove_session_internal(sid, Some(*hash), true);
        }
    }

    /// Remove all pair requests that are spent by any transaction
    /// input (dcrd `RemoveSpentPRs`).
    pub fn remove_spent_prs(&mut self, txs: &[MsgTx]) {
        for tx in txs {
            let tx_hash = tx.tx_hash();
            if let Some(sid) = self.sessions_by_tx_hash.get(&tx_hash.0).copied() {
                self.remove_strikes_for_mix(tx);
                self.remove_session_internal(sid, Some(tx_hash), true);
                continue;
            }

            for tx_in in &tx.tx_in {
                let Some(pr_hash) = self.out_points.get(&op_key(&tx_in.previous_out_point)) else {
                    continue;
                };
                if let Some(pr) = self.prs.get(&pr_hash.0).cloned() {
                    self.remove_pr(&pr);
                }
            }
        }
    }

    /// Whether a transaction that is not known to be the mix tx for
    /// any confirmed session spends a current pair request UTXO (dcrd
    /// `NonMixSpendsPR`).
    pub fn non_mix_spends_pr(&self, tx: &MsgTx) -> bool {
        if self.sessions_by_tx_hash.contains_key(&tx.tx_hash().0) {
            return false;
        }

        tx.tx_in.iter().any(|tx_in| {
            self.out_points
                .contains_key(&op_key(&tx_in.previous_out_point))
        })
    }

    /// The most recently received run-0 KE messages by a peer that
    /// reference PRs of a particular pairing and epoch (dcrd
    /// `ReceiveKEsByPairing`).
    pub fn receive_kes_by_pairing(&self, pairing: &[u8], epoch: u64) -> Vec<MsgMixKeyExchange> {
        let mut kes = Vec::new();
        for (id, ke) in &self.latest_ke {
            if ke.epoch != epoch {
                continue;
            }
            let Some(hashes) = self.messages_by_identity.get(id) else {
                continue;
            };
            let Some(pr) = self.prs.get(&hashes[0].0) else {
                continue;
            };
            if pr.pairing() == pairing {
                kes.push(ke.clone());
            }
        }
        kes
    }

    /// Collect the messages currently accepted for a session (dcrd
    /// `Receive`, which additionally blocks until all expected
    /// messages arrive; this synchronous port matches dcrd's
    /// pre-cancelled-context behavior of returning immediately, which
    /// is also what the misbehavior observer uses).
    pub fn receive(&self, r: &mut Received) -> Result<(), PoolError> {
        let ses = self
            .sessions
            .get(&r.sid)
            .ok_or_else(|| PoolError::Other(format!("unknown session {}", hex(&r.sid))))?;

        let mut cap_slices = 0;
        for has in [
            r.kes.is_some(),
            r.cts.is_some(),
            r.srs.is_some(),
            r.dcs.is_some(),
            r.cms.is_some(),
            r.fps.is_some(),
            r.rss.is_some(),
        ] {
            if has {
                cap_slices += 1;
            }
        }
        if cap_slices != 1 && !r.receive_all {
            return Err(PoolError::Other(
                "mixpool: exactly one Received slice must have non-zero capacity".into(),
            ));
        }

        let mut err = Ok(());
        for hash in &ses.hashes {
            let Some(e) = self.pool.get(hash) else {
                continue;
            };
            match &e.msg {
                PoolMessage::KE(m) => {
                    if let Some(kes) = &mut r.kes {
                        kes.push((**m).clone());
                    }
                }
                PoolMessage::CT(m) => {
                    if let Some(cts) = &mut r.cts {
                        cts.push(m.clone());
                    }
                }
                PoolMessage::SR(m) => {
                    if let Some(srs) = &mut r.srs {
                        srs.push(m.clone());
                    }
                }
                PoolMessage::DC(m) => {
                    if let Some(dcs) = &mut r.dcs {
                        dcs.push(m.clone());
                    }
                }
                PoolMessage::CM(m) => {
                    if let Some(cms) = &mut r.cms {
                        cms.push(m.clone());
                    }
                }
                PoolMessage::FP(m) => {
                    if let Some(fps) = &mut r.fps {
                        fps.push(m.clone());
                    }
                }
                PoolMessage::RS(m) => match &mut r.rss {
                    Some(rss) => rss.push(m.clone()),
                    None => err = Err(PoolError::SecretsRevealed),
                },
                PoolMessage::PR(_) => {}
            }
        }
        err
    }

    /// Limit the number of orphan mixing messages by evicting a
    /// subset of the existing orphans when adding a new one would
    /// cause it to overflow the max allowed (dcrd `limitNumOrphans`).
    fn limit_num_orphans(&mut self) {
        if self.orphans.len() < MAX_ORPHANS {
            return;
        }

        // Remove all of the orphans associated with each source in
        // descending count order until the pool has reached the
        // target maximum number of post-eviction orphans.
        let mut src_counters: HashMap<u64, i64> = HashMap::new();
        for o in self.orphans.values() {
            *src_counters.entry(o.src).or_default() += 1;
        }
        let mut src_counts: Vec<(u64, i64)> = src_counters.into_iter().collect();
        src_counts.sort_by_key(|(_, count)| core::cmp::Reverse(*count));
        let mut num_orphans = self.orphans.len() as u64;
        let mut idx = 0;
        while num_orphans > MAX_POST_EVICTION_ORPHANS as u64 && idx < src_counts.len() {
            let src_id = src_counts[idx].0;
            let max_to_evict = num_orphans - MAX_POST_EVICTION_ORPHANS as u64;
            let num_evicted = self.remove_orphans_by_source_id(src_id, max_to_evict);
            num_orphans -= num_evicted;
            idx += 1;
        }
    }

    /// Add the passed message to the orphan pool when it is not
    /// already present (dcrd `addOrphan`).
    fn add_orphan(&mut self, msg: &PoolMessage, hash: &[u8; 32], id: &IdPubKey, src: u64) {
        if let Some(by_id) = self.orphans_by_id.get(id)
            && by_id.contains_key(hash)
        {
            // Already an orphan.
            return;
        }

        self.limit_num_orphans();

        let orphan = Rc::new(OrphanMsg {
            message: msg.clone(),
            src,
            accepted: (self.now_fn)(),
        });
        self.orphans.insert(*hash, orphan.clone());
        self.orphans_by_id
            .entry(*id)
            .or_default()
            .insert(*hash, orphan);
    }

    /// Accept a mixing message to the pool (dcrd `AcceptMessage`).
    ///
    /// Messages must contain the mixing participant's identity and a
    /// valid signature committing to all non-signature fields.  PR
    /// messages will not be accepted if they reference an unknown
    /// UTXO or if not enough fee is contributed; any other message
    /// will not be accepted if it references previous messages that
    /// are not recorded by the pool.
    ///
    /// All newly accepted messages, including any orphans that were
    /// processed after processing missing previous messages, are
    /// returned.
    pub fn accept_message(
        &mut self,
        msg: &PoolMessage,
        src: u64,
    ) -> Result<Vec<PoolMessage>, PoolError> {
        if msg.run() != 0 {
            return Err(rule_other("nonzero reruns are unsupported"));
        }

        let hash = msg.mix_hash()?;

        // Check if already accepted.
        if self.pool.contains_key(&hash.0) || self.prs.contains_key(&hash.0) {
            return Ok(Vec::new());
        }

        // Require message to be signed by the presented identity.
        if !verify_signed_message(msg.as_mix_message()) {
            return Err(rule(RuleKind::InvalidSignature));
        }
        let id = msg.identity();

        let msgtype = match msg {
            PoolMessage::PR(pr) => {
                self.check_accept_pr(pr)?;

                let accepted = self.accept_pr(pr, &hash, &id)?;
                if !accepted {
                    return Ok(Vec::new());
                }
                return Ok(self.reconsider_orphans(msg.clone(), &id));
            }
            PoolMessage::KE(ke) => {
                self.check_accept_ke(ke)?;

                let accepted = self.accept_ke(ke, &hash, &id, src)?;
                if !accepted {
                    return Ok(Vec::new());
                }
                return Ok(self.reconsider_orphans(msg.clone(), &id));
            }
            PoolMessage::CT(ct) => {
                check_ct_limits(ct)?;
                MsgType::CT
            }
            PoolMessage::SR(sr) => {
                check_sr_limits(sr)?;
                MsgType::SR
            }
            PoolMessage::DC(dc) => {
                check_dc_limits(dc)?;
                MsgType::DC
            }
            PoolMessage::CM(cm) => {
                check_cm_limits(cm)?;
                MsgType::CM
            }
            PoolMessage::FP(fp) => {
                check_fp_limits(fp)?;
                MsgType::FP
            }
            PoolMessage::RS(rs) => {
                check_rs_limits(rs)?;
                MsgType::RS
            }
        };

        let Some(sid) = msg.sid() else {
            return Err(rule(RuleKind::InvalidSessionID));
        };

        // Check that a message from this identity does not conflict
        // with a different message of the same type in the session.
        let mut have_ke = false;
        if let Some(hashes) = self.messages_by_identity.get(&id) {
            for prev_hash in hashes {
                let Some(e) = self.pool.get(&prev_hash.0) else {
                    continue;
                };
                if e.msgtype == msgtype && e.msg.sid() == Some(sid) {
                    return Err(rule_other(format!(
                        "message {} by identity {} in session {} conflicts with \
                         already accepted message {}",
                        hash,
                        hex(&id),
                        hex(&sid),
                        prev_hash
                    )));
                }
                if !have_ke && e.msgtype == MsgType::KE && e.msg.sid() == Some(sid) {
                    have_ke = true;
                }
            }
        }
        // Save as an orphan if their KE is not (yet) accepted.
        if !have_ke {
            self.add_orphan(msg, &hash.0, &id, src);
            return Ok(Vec::new());
        }

        if !self.sessions.contains_key(&sid) {
            return Err(rule_other(format!(
                "{msgtype} {hash} belongs to unknown session {}",
                hex(&sid)
            )));
        }

        self.accept_entry(msg.clone(), msgtype, &hash, &id, &sid);
        Ok(vec![msg.clone()])
    }

    /// Remove a pair request message and all other messages and
    /// sessions that the peer sent and was involved in (dcrd
    /// `removePR`).
    fn remove_pr(&mut self, pr: &MsgMixPairReq) {
        let Ok(pr_hash) = pr.mix_hash() else {
            return;
        };

        self.prs.remove(&pr_hash.0);
        self.recent_mix_msgs
            .put(pr_hash.0, PoolMessage::PR(pr.clone()));

        let hashes = self
            .messages_by_identity
            .get(&pr.identity)
            .cloned()
            .unwrap_or_default();
        for hash in hashes {
            let ke_sid = match self.pool.get(&hash.0) {
                Some(e) => match &e.msg {
                    PoolMessage::KE(ke) => Some(ke.session_id),
                    _ => None,
                },
                None => continue,
            };
            if let Some(sid) = ke_sid {
                self.remove_session_internal(sid, None, false);
            }
            self.remove_message_by_hash(&hash.0);
        }
        self.messages_by_identity.remove(&pr.identity);
        self.latest_ke.remove(&pr.identity);
        let orphan_hashes: Vec<[u8; 32]> = self
            .orphans_by_id
            .get(&pr.identity)
            .map(|m| m.keys().copied().collect())
            .unwrap_or_default();
        for orphan_hash in orphan_hashes {
            self.remove_orphan(&orphan_hash, &pr.identity);
        }
        for utxo in &pr.utxos {
            self.out_points.remove(&op_key(&utxo.out_point));
        }
    }

    fn check_accept_pr(&self, pr: &MsgMixPairReq) -> Result<(), PoolError> {
        check_pr_limits(pr)?;

        let mut input_value = pr.input_value;
        if let Some(change) = &pr.change {
            if change.value < 0 || is_dust_amount(change.value, P2PKHV0_PK_SCRIPT_SIZE, FEE_RATE) {
                return Err(rule(RuleKind::ChangeDust));
            }

            if change.value > input_value {
                return Err(rule(RuleKind::LowInput));
            }
            input_value -= change.value;

            if change.version != 0 {
                return Err(rule_other("unrecognized script version"));
            }
            if change.version == 0
                && !stdscript::is_pub_key_hash_script_v0(&change.pk_script)
                && !stdscript::is_script_hash_script_v0(&change.pk_script)
            {
                return Err(rule(RuleKind::InvalidScript));
            }
        }
        if pr.utxos.is_empty() {
            // Require at least one utxo.
            return Err(rule(RuleKind::MissingUTXOs));
        }
        if pr.message_count == 0 {
            // Require at least one mixed message.
            return Err(rule(RuleKind::InvalidMessageCount));
        }
        if is_dust_amount(pr.mix_amount, P2PKHV0_PK_SCRIPT_SIZE, FEE_RATE) {
            return Err(rule(RuleKind::MixDust));
        }
        if input_value < i64::from(pr.message_count) * pr.mix_amount {
            return Err(rule(RuleKind::InvalidTotalMixAmount));
        }

        // Check that expiry has not been reached, nor that it is too
        // far into the future.  This limits replay attacks.
        let (_, cur_height) = self.blockchain.current_tip();
        let max_expiry = max_expiry(cur_height as u32, self.blockchain.chain_params());
        if cur_height as u32 >= pr.expiry {
            return Err(rule_other("message has expired"));
        }
        if pr.expiry > max_expiry {
            return Err(rule_other("expiry is too far into future"));
        }

        // Require known script classes.
        if pr.script_class != SCRIPT_CLASS_P2PKH_V0 {
            return Err(rule_other("unsupported mixing script class"));
        }

        // Require enough fee contributed from this mixing participant.
        check_fee(pr, self.fee_rate)?;

        // Check that UTXOs exist, have confirmations, the sum of UTXO
        // values matches the input value, and proof of ownership is
        // valid.
        let mut total_value = 0i64;
        let mut outpoints: HashSet<OutPointKey> = HashSet::new();
        for utxo in &pr.utxos {
            if !outpoints.insert(op_key(&utxo.out_point)) {
                return Err(rule(RuleKind::InvalidUTXOProof));
            }

            if !utxo.script.is_empty() {
                return Err(rule_other("P2SH inputs are unsupported"));
            }

            if let Some(fetcher) = &self.utxo_fetcher {
                let entry = fetcher
                    .fetch_utxo_entry(&utxo.out_point)
                    .map_err(PoolError::UtxoFetch)?;
                if entry.is_spent() {
                    return Err(rule_other(format!(
                        "output {} is not unspent",
                        op_string(&utxo.out_point)
                    )));
                }
                let height = entry.block_height();
                if !confirmed(MINCONF, height, cur_height) {
                    return Err(rule_other(format!(
                        "output {} is unconfirmed",
                        op_string(&utxo.out_point)
                    )));
                }
                if entry.script_version() != 0 {
                    return Err(rule_other(format!(
                        "output {} does not use script version 0",
                        op_string(&utxo.out_point)
                    )));
                }

                // Check proof of key ownership and ability to sign
                // coinjoin inputs.
                let extract: fn(&[u8]) -> Option<&[u8]> = match utxo.opcode {
                    0 => stdscript::extract_pub_key_hash_v0,
                    dcroxide_txscript::OP_SSGEN => stdscript::extract_stake_gen_pub_key_hash_v0,
                    dcroxide_txscript::OP_SSRTX => {
                        stdscript::extract_stake_revocation_pub_key_hash_v0
                    }
                    dcroxide_txscript::OP_TGEN => stdscript::extract_treasury_gen_pub_key_hash_v0,
                    _ => {
                        return Err(rule_other(format!(
                            "unsupported output script for UTXO {}",
                            op_string(&utxo.out_point)
                        )));
                    }
                };
                let valid = validate_owner_proof_p2pkh_v0(
                    extract,
                    entry.pk_script(),
                    &utxo.pub_key,
                    &utxo.signature,
                    pr.expires(),
                );
                if !valid {
                    return Err(rule(RuleKind::InvalidUTXOProof));
                }

                total_value += entry.amount();
            }
        }
        if total_value != 0 && total_value != pr.input_value {
            return Err(rule(RuleKind::InvalidUTXOProof));
        }

        Ok(())
    }

    fn accept_pr(
        &mut self,
        pr: &MsgMixPairReq,
        hash: &Hash,
        id: &IdPubKey,
    ) -> Result<bool, PoolError> {
        // Check if already accepted.
        if self.prs.contains_key(&hash.0) {
            return Ok(false);
        }

        // Discourage identity reuse.  PRs should be the first message
        // sent by this identity, and there should only be one PR per
        // identity.
        if self
            .messages_by_identity
            .get(id)
            .is_some_and(|v| !v.is_empty())
        {
            return Err(rule_other("identity reused for a PR message"));
        }

        // Only accept PRs that double spend outpoints if they expire
        // later than existing PRs.  Otherwise, reject this PR message.
        for utxo in &pr.utxos {
            let Some(other_pr_hash) = self.out_points.get(&op_key(&utxo.out_point)) else {
                continue;
            };
            let Some(other_pr) = self.prs.get(&other_pr_hash.0) else {
                continue;
            };
            if other_pr.expiry >= pr.expiry {
                return Err(rule_other(
                    "PR double spends outpoints of already-accepted PR message \
                     without increasing expiry",
                ));
            }
        }

        // Accept the PR.
        self.prs.insert(hash.0, pr.clone());
        for utxo in &pr.utxos {
            self.out_points.insert(op_key(&utxo.out_point), *hash);
        }
        self.messages_by_identity.insert(*id, vec![*hash]);

        self.merge_accepted_pr_strikes(pr);

        Ok(true)
    }

    /// Reconsider any messages that are currently saved as orphans
    /// due to a missing previous PR message (in the case of KE
    /// orphans) or missing the identity's KE in a matching session
    /// (for all other messages) (dcrd `reconsiderOrphans`).
    fn reconsider_orphans(&mut self, accepted: PoolMessage, id: &IdPubKey) -> Vec<PoolMessage> {
        let mut accepted_messages = vec![accepted.clone()];

        let mut kes: Vec<MsgMixKeyExchange> = Vec::new();
        if let PoolMessage::KE(ke) = &accepted {
            kes.push((**ke).clone());
        }

        // If the accepted message was a PR, there may be KE orphans
        // that can be accepted now.
        if let PoolMessage::PR(pr) = &accepted {
            let Ok(pr_hash) = pr.mix_hash() else {
                return accepted_messages;
            };
            let orphan_kes: Vec<(MsgMixKeyExchange, u64)> = self
                .orphans_by_id
                .get(id)
                .map(|by_id| {
                    by_id
                        .values()
                        .filter_map(|o| match &o.message {
                            PoolMessage::KE(ke) if ke.seen_prs.contains(&pr_hash) => {
                                Some(((**ke).clone(), o.src))
                            }
                            _ => None,
                        })
                        .collect()
                })
                .unwrap_or_default();

            for (orphan_ke, src) in orphan_kes {
                let Ok(orphan_ke_hash) = orphan_ke.mix_hash() else {
                    continue;
                };
                match self.accept_ke(&orphan_ke, &orphan_ke_hash, &orphan_ke.identity, src) {
                    Ok(_) => {}
                    Err(_) => continue,
                }

                kes.push(orphan_ke.clone());
                self.remove_orphan(&orphan_ke_hash.0, id);

                accepted_messages.push(PoolMessage::KE(Box::new(orphan_ke)));
            }
            if self.orphans_by_id.get(id).is_none_or(|m| m.is_empty()) {
                return accepted_messages;
            }
        }

        // For any KE that has been accepted following reconsideration
        // after accepting a PR, other orphan messages may be
        // potentially accepted as well.
        for ke in kes {
            if !self.sessions.contains_key(&ke.session_id) {
                continue;
            }

            let orphan_entries: Vec<([u8; 32], PoolMessage)> = self
                .orphans_by_id
                .get(id)
                .map(|by_id| {
                    by_id
                        .iter()
                        .filter(|(_, o)| o.message.sid() == Some(ke.session_id))
                        .map(|(hash, o)| (*hash, o.message.clone()))
                        .collect()
                })
                .unwrap_or_default();

            for (orphan_hash, orphan) in orphan_entries {
                let Some(msgtype) = orphan.msgtype() else {
                    continue;
                };

                self.accept_entry(
                    orphan.clone(),
                    msgtype,
                    &Hash(orphan_hash),
                    id,
                    &ke.session_id,
                );

                accepted_messages.push(orphan);
                self.remove_orphan(&orphan_hash, id);
            }
            if self.orphans_by_id.get(id).is_none_or(|m| m.is_empty()) {
                return accepted_messages;
            }
        }

        accepted_messages
    }

    fn check_accept_ke(&self, ke: &MsgMixKeyExchange) -> Result<(), PoolError> {
        check_ke_limits(ke)?;

        // Validate PR order and session ID.  These wrap the mixing
        // package's plain errors, which are not bannable, unlike the
        // pool's own named ErrInvalidSessionID.
        if let Err(err) = validate_session(ke) {
            return Err(rule_other(err.to_string()));
        }

        if ke.pos as usize >= ke.seen_prs.len() {
            return Err(rule(RuleKind::PeerPositionOutOfBounds));
        }

        let now = (self.now_fn)();
        let ke_epoch_nanos = (ke.epoch as i64).wrapping_mul(1_000_000_000);
        if now.wrapping_add(EARLY_KE_DURATION_NANOS) < ke_epoch_nanos {
            return Err(rule_other("KE received too early for stated epoch"));
        }

        Ok(())
    }

    fn accept_ke(
        &mut self,
        ke: &MsgMixKeyExchange,
        hash: &Hash,
        id: &IdPubKey,
        src: u64,
    ) -> Result<bool, PoolError> {
        // Check if already accepted.
        if self.pool.contains_key(&hash.0) {
            return Ok(false);
        }

        // While KEs are allowed to reference unknown PRs, they must
        // at least reference the PR submitted by their own identity.
        // If not, the KE is saved as an orphan and may be processed
        // later.  Of all PRs that are known, their pairing types must
        // be compatible.
        let mut missing_own_pr: Option<Hash> = None;
        let mut pairing: Option<Vec<u8>> = None;
        for (i, seen_pr) in ke.seen_prs.iter().enumerate() {
            let Some(pr) = self.prs.get(&seen_pr.0) else {
                if i as u32 == ke.pos {
                    missing_own_pr = Some(*seen_pr);
                }
                continue;
            };
            if i as u32 == ke.pos && pr.identity != ke.identity {
                // This cannot be a bannable rule error: one peer may
                // have sent an orphan KE first, then another peer the
                // PR.
                return Err(rule_other(
                    "KE identity does not match own PR at unmixed position",
                ));
            }
            match &pairing {
                None => pairing = Some(pr.pairing()),
                Some(first) => {
                    if *first != pr.pairing() {
                        // Likewise not bannable: peers may relay a KE
                        // without knowing any but the identity's own
                        // PR.
                        return Err(rule_other("referenced PRs are incompatible"));
                    }
                }
            }
        }
        if let Some(missing) = missing_own_pr {
            self.add_orphan(&PoolMessage::KE(Box::new(ke.clone())), &hash.0, id, src);
            return Err(PoolError::MissingOwnPR(missing));
        }

        let sid = ke.session_id;

        // Create a session for the first KE.  Note that dcrd derives
        // the expiry from an always-empty list of PRs here, so every
        // session is created with the maximum expiry; ported bug for
        // bug.
        self.sessions.entry(sid).or_insert_with(|| Session {
            sid,
            prs: ke.seen_prs.clone(),
            counts: [0; 7],
            hashes: HashSet::new(),
            expiry: u32::MAX,
        });

        self.accept_entry(
            PoolMessage::KE(Box::new(ke.clone())),
            MsgType::KE,
            hash,
            id,
            &sid,
        );
        self.latest_ke.insert(*id, ke.clone());
        Ok(true)
    }

    fn accept_entry(
        &mut self,
        msg: PoolMessage,
        msgtype: MsgType,
        hash: &Hash,
        id: &IdPubKey,
        sid: &[u8; 32],
    ) {
        let Some(ses) = self.sessions.get_mut(sid) else {
            return;
        };
        ses.hashes.insert(hash.0);
        if let PoolMessage::CM(cm) = &msg {
            self.sessions_by_tx_hash.insert(cm.mix.tx_hash().0, *sid);
        }
        ses.increment_count_for(msgtype);

        let e = Entry {
            sid: *sid,
            recv_time: (self.now_fn)(),
            msg,
            msgtype,
        };
        let _ = e.recv_time;
        self.pool.insert(hash.0, e);
        self.messages_by_identity
            .entry(*id)
            .or_default()
            .push(*hash);
    }

    // ----------------------------------------------------------------
    // The misbehavior observer (dcrd `Observer`).
    // ----------------------------------------------------------------

    /// All key exchange messages that were received for a particular
    /// epoch from peers who formed sessions (as indicated by a
    /// received CT), and their pair requests (dcrd `activeInEpoch`).
    fn active_in_epoch(&self, epoch: u64) -> ActivePeers {
        let mut epoch_kes: Vec<&MsgMixKeyExchange> = Vec::new();
        for e in self.pool.values() {
            if let PoolMessage::KE(ke) = &e.msg
                && ke.epoch == epoch
            {
                epoch_kes.push(ke);
            }
        }
        let mut kes: Vec<&MsgMixKeyExchange> = Vec::new();
        'next_ke: for ke in epoch_kes {
            if let Some(hashes) = self.messages_by_identity.get(&ke.identity) {
                for msg_hash in hashes {
                    if let Some(e) = self.pool.get(&msg_hash.0)
                        && e.msgtype == MsgType::CT
                        && e.sid == ke.session_id
                    {
                        kes.push(ke);
                        continue 'next_ke;
                    }
                }
            }
        }

        let mut active_kes: HashMap<IdPubKey, Vec<MsgMixKeyExchange>> = HashMap::new();
        for ke in kes {
            active_kes.entry(ke.identity).or_default().push(ke.clone());
        }
        let mut active = HashMap::new();
        for pr in self.prs.values() {
            if let Some(kes) = active_kes.remove(&pr.identity) {
                active.insert(pr.identity, (pr.clone(), kes));
            }
        }

        active
    }

    /// Remove pair requests of unresponsive peers that did not
    /// provide any key exchange messages during the epoch in which a
    /// mix occurred (dcrd `RemoveUnresponsiveDuringEpoch`).
    pub fn remove_unresponsive_during_epoch(&mut self, prs: &[MsgMixPairReq], epoch: u64) {
        'pr_loop: for pr in prs {
            if let Some(hashes) = self.messages_by_identity.get(&pr.identity) {
                for msg_hash in hashes {
                    if let Some(e) = self.pool.get(&msg_hash.0)
                        && let PoolMessage::KE(ke) = &e.msg
                        && ke.epoch == epoch
                    {
                        continue 'pr_loop;
                    }
                }
            }

            self.remove_pr(pr);
        }
    }

    /// Check for timeout misbehavior in the previous epoch (dcrd
    /// `Observer.CheckPrevEpoch`; dcrd's `Run` drives this on the
    /// epoch ticker in a goroutine, which the daemon phase owns).
    pub fn check_prev_epoch(&mut self, prev_epoch: u64) -> Result<(), PoolError> {
        // Gather all attempted session formations, and those sessions
        // which ended in a pairings mix.
        let mut pairings: HashMap<Vec<u8>, HashMap<[u8; 32], Vec<MsgMixKeyExchange>>> =
            HashMap::new();
        let mut completed: HashMap<[u8; 32], Vec<MsgMixKeyExchange>> = HashMap::new();
        let mut pr_by_ke: HashMap<[u8; 32], MsgMixPairReq> = HashMap::new();
        let mut timed_out: HashMap<Vec<u8>, HashSet<IdPubKey>> = HashMap::new();
        let mut active = self.active_in_epoch(prev_epoch);
        let mut size_limited: HashMap<IdPubKey, Vec<u8>> = HashMap::new();

        for (pr, kes) in active.values() {
            let pairing = pr.pairing();
            let ses = pairings.entry(pairing).or_default();
            for ke in kes {
                ses.entry(ke.session_id).or_default().push(ke.clone());
                let Ok(ke_hash) = ke.mix_hash() else {
                    continue;
                };
                pr_by_ke.insert(ke_hash.0, pr.clone());
            }
        }

        for (pairing, ses) in &pairings {
            for (sid, ses_kes) in ses {
                // Sessions formed with fewer than the required
                // minimum peer count can't be used to discover
                // misbehavior.
                if (ses_kes.len() as u32) < MIN_PEERS {
                    continue;
                }

                let mut r = Received {
                    sid: *sid,
                    kes: None,
                    cts: Some(Vec::new()),
                    srs: Some(Vec::new()),
                    dcs: Some(Vec::new()),
                    cms: Some(Vec::new()),
                    fps: None,
                    rss: Some(Vec::new()),
                    receive_all: true,
                };
                let _ = self.receive(&mut r);
                let cts = r.cts.unwrap_or_default();
                let srs = r.srs.unwrap_or_default();
                let dcs = r.dcs.unwrap_or_default();
                let cms = r.cms.unwrap_or_default();
                let rss = r.rss.unwrap_or_default();

                // When no ciphertext messages were received, a
                // session was not formed, and timeout can not be
                // observed.  Mark all peers in this session as
                // potentially size limited.
                if cts.is_empty() {
                    for ke in ses_kes {
                        size_limited.insert(ke.identity, pairing.clone());
                    }
                    continue;
                }

                // If secrets were revealed, then clients would have
                // blamed peers for non-timeout misbehavior, which is
                // out of scope for this observer.
                if !rss.is_empty() {
                    continue;
                }

                if cms.len() == ses_kes.len() {
                    completed.insert(*sid, ses_kes.clone());
                    continue;
                }

                // If a session was fully formed but later messages in
                // the protocol were never received, peers may have
                // intentionally timed out.  Don't blame peers if all
                // messages are missing.
                if ses_kes[0].seen_prs.len() != ses_kes.len() {
                    continue;
                }
                let mut ids: HashSet<IdPubKey> = ses_kes.iter().map(|ke| ke.identity).collect();
                if cts.is_empty() {
                    continue;
                } else if cts.len() < ses_kes.len() {
                    for ct in &cts {
                        ids.remove(&ct.identity);
                    }
                } else if srs.is_empty() {
                    continue;
                } else if srs.len() < ses_kes.len() {
                    for sr in &srs {
                        ids.remove(&sr.identity);
                    }
                } else if dcs.is_empty() {
                    continue;
                } else if dcs.len() < ses_kes.len() {
                    for dc in &dcs {
                        ids.remove(&dc.identity);
                    }
                } else if cms.is_empty() {
                    continue;
                } else if cms.len() < ses_kes.len() {
                    for cm in &cms {
                        ids.remove(&cm.identity);
                    }
                }
                let timed_out_ids = timed_out.entry(pairing.clone()).or_default();
                for id in ids {
                    timed_out_ids.insert(id);
                }
            }
        }

        // Remove identities that were included in a completed mix and
        // record the completed pairings.
        let mut completed_pairings: HashSet<Vec<u8>> = HashSet::new();
        for kes in completed.values() {
            for ke in kes {
                active.remove(&ke.identity);
            }
            let Ok(ke_hash) = kes[0].mix_hash() else {
                continue;
            };
            if let Some(pr) = pr_by_ke.get(&ke_hash.0) {
                completed_pairings.insert(pr.pairing());
            }
        }

        // Remove identities when no successful mix occurred for the
        // pairing, unless they timed out for the pairing.
        let ids: Vec<IdPubKey> = active.keys().copied().collect();
        for id in ids {
            let Some((_, kes)) = active.get(&id) else {
                continue;
            };
            let Ok(ke_hash) = kes[0].mix_hash() else {
                continue;
            };
            let Some(pr) = pr_by_ke.get(&ke_hash.0) else {
                continue;
            };
            let pairing = pr.pairing();
            if !completed_pairings.contains(&pairing) {
                if let Some(timed_out_ids) = timed_out.get(&pairing)
                    && timed_out_ids.contains(&id)
                {
                    continue;
                }
                active.remove(&id);
            }
        }

        // Remove identities that were in abandoned sessions exceeding
        // the mix limits, unless they also timed out.
        for (id, pairing) in &size_limited {
            if let Some(timed_out_ids) = timed_out.get(pairing)
                && timed_out_ids.contains(id)
            {
                continue;
            }
            active.remove(id);
        }

        self.update_strikes(prev_epoch, &active, &pr_by_ke, &completed);

        Ok(())
    }

    fn update_strikes(
        &mut self,
        epoch: u64,
        misbehaving: &ActivePeers,
        pr_by_ke: &HashMap<[u8; 32], MsgMixPairReq>,
        completed: &HashMap<[u8; 32], Vec<MsgMixKeyExchange>>,
    ) {
        // Add a strike for any active identity that was not included
        // in a completed mix last epoch.  Strikes are increased for
        // all UTXOs associated with the misbehaving identity; UTXO
        // sets sharing any outpoint establish common ownership and
        // merge.
        for (pr, _) in misbehaving.values() {
            let mut ss: Vec<StrikeSetRef> = Vec::new();
            for utxo in &pr.utxos {
                if let Some(s) = self.strikes.get(&op_key(&utxo.out_point))
                    && !ss.iter().any(|other| Rc::ptr_eq(other, s))
                {
                    ss.push(s.clone());
                }
            }
            let merged: StrikeSetRef = match ss.first() {
                Some(first) => {
                    for other in &ss[1..] {
                        let other_set = other.borrow();
                        let mut first_mut = first.borrow_mut();
                        for op in &other_set.set {
                            first_mut.set.insert(*op);
                        }
                        let mut strikes = first_mut.strikes.clone();
                        strikes.extend_from_slice(&other_set.strikes);
                        first_mut.strikes = sort_uniq(strikes);
                    }
                    first.clone()
                }
                None => Rc::new(RefCell::new(StrikeSet {
                    set: HashSet::new(),
                    strikes: Vec::new(),
                })),
            };
            merged.borrow_mut().strikes.push(epoch);
            for utxo in &pr.utxos {
                self.strikes.insert(op_key(&utxo.out_point), merged.clone());
            }
        }

        // Remove strikes for UTXOs spent by completed mixes.
        for kes in completed.values() {
            for ke in kes {
                let Ok(ke_hash) = ke.mix_hash() else {
                    continue;
                };
                let Some(pr) = pr_by_ke.get(&ke_hash.0) else {
                    continue;
                };
                for utxo in &pr.utxos {
                    self.strikes.remove(&op_key(&utxo.out_point));
                }
            }
        }

        // Remove strikes if none occurred in the past 24h.
        let cutoff = epoch.wrapping_sub(60 * 60 * 24);
        self.strikes.retain(|_, s| {
            let s = s.borrow();
            s.strikes.last().copied().unwrap_or_default() > cutoff
        });
    }

    /// Merge observed common UTXO ownership of newly-accepted PRs
    /// with current strikes recorded for an overlapping set of UTXOs,
    /// without adding any new strikes (dcrd
    /// `mergeAcceptedPRStrikes`).
    fn merge_accepted_pr_strikes(&mut self, pr: &MsgMixPairReq) {
        for utxo in &pr.utxos {
            let Some(s) = self.strikes.get(&op_key(&utxo.out_point)) else {
                continue;
            };
            let mut s = s.borrow_mut();
            for other in &pr.utxos {
                s.set.insert(op_key(&other.out_point));
            }
            return;
        }
    }

    fn remove_strikes_for_mix(&mut self, tx: &MsgTx) {
        for tx_in in &tx.tx_in {
            self.strikes.remove(&op_key(&tx_in.previous_out_point));
        }
    }

    /// Whether any transaction in the block spends an output that was
    /// flagged as submitted by a misbehaving mixing peer (dcrd
    /// `MisbehavingBlock`).
    pub fn misbehaving_block(&self, block: &dcroxide_wire::MsgBlock) -> bool {
        block
            .transactions
            .iter()
            .chain(block.stransactions.iter())
            .any(|tx| self.misbehaving_tx_internal(tx))
    }

    /// Whether any transaction output was flagged as submitted by a
    /// misbehaving mixing peer (dcrd `MisbehavingTx`).
    pub fn misbehaving_tx(&self, tx: &MsgTx) -> bool {
        self.misbehaving_tx_internal(tx)
    }

    fn misbehaving_tx_internal(&self, tx: &MsgTx) -> bool {
        let tx_hash = tx.tx_hash();
        if self.sessions_by_tx_hash.contains_key(&tx_hash.0) {
            return false;
        }

        for tx_in in &tx.tx_in {
            let Some(s) = self.strikes.get(&op_key(&tx_in.previous_out_point)) else {
                continue;
            };
            if s.borrow().strikes.len() >= STRIKE_LIMIT {
                return true;
            }
        }
        false
    }

    /// A slice of pair request messages excluding any which spend
    /// previously-flagged misbehaving outputs (dcrd `ExcludePRs`).
    pub fn exclude_prs(&self, prs: &[MsgMixPairReq]) -> Vec<MsgMixPairReq> {
        let mut out = Vec::with_capacity(prs.len());
        'prs: for pr in prs {
            for utxo in &pr.utxos {
                let Some(s) = self.strikes.get(&op_key(&utxo.out_point)) else {
                    continue;
                };
                if s.borrow().strikes.len() >= STRIKE_LIMIT {
                    continue 'prs;
                }
            }
            out.push(pr.clone());
        }
        out
    }

    /// The strike counts per outpoint; exposed for tests.
    #[doc(hidden)]
    pub fn strike_counts(&self) -> Vec<(OutPoint, usize)> {
        self.strikes
            .iter()
            .map(|((hash, index, tree), s)| {
                (
                    OutPoint {
                        hash: Hash(*hash),
                        index: *index,
                        tree: *tree,
                    },
                    s.borrow().strikes.len(),
                )
            })
            .collect()
    }

    /// A snapshot of the internal state; exposed for tests.
    #[doc(hidden)]
    #[allow(clippy::type_complexity)]
    pub fn state_snapshot(
        &self,
    ) -> (
        Vec<[u8; 32]>,
        Vec<([u8; 32], MsgType, [u8; 32])>,
        Vec<[u8; 32]>,
        Vec<([u8; 32], u32, Vec<u32>, usize)>,
        usize,
        usize,
    ) {
        let prs = self.prs.keys().copied().collect();
        let pool = self
            .pool
            .iter()
            .map(|(hash, e)| (*hash, e.msgtype, e.sid))
            .collect();
        let orphans = self.orphans.keys().copied().collect();
        let sessions = self
            .sessions
            .values()
            .map(|ses| (ses.sid, ses.expiry, ses.counts.to_vec(), ses.hashes.len()))
            .collect();
        (
            prs,
            pool,
            orphans,
            sessions,
            self.out_points.len(),
            self.latest_ke.len(),
        )
    }
}

/// The result carrier for [`Pool::receive`] (dcrd `Received`): fields
/// set to `Some` indicate which message types to collect, mirroring
/// dcrd's non-nil slices.  Unless `receive_all` is set, exactly one
/// field must be `Some`.
pub struct Received {
    /// The session to receive messages for.
    pub sid: [u8; 32],
    /// Collected key exchanges.
    pub kes: Option<Vec<MsgMixKeyExchange>>,
    /// Collected ciphertexts.
    pub cts: Option<Vec<MsgMixCiphertexts>>,
    /// Collected slot reservations.
    pub srs: Option<Vec<MsgMixSlotReserve>>,
    /// Collected DC-net broadcasts.
    pub dcs: Option<Vec<MsgMixDCNet>>,
    /// Collected confirmations.
    pub cms: Option<Vec<MsgMixConfirm>>,
    /// Collected factored polynomials.
    pub fps: Option<Vec<MsgMixFactoredPoly>>,
    /// Collected revealed secrets.
    pub rss: Option<Vec<MsgMixSecrets>>,
    /// Collect every message type.
    pub receive_all: bool,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn op_string(op: &OutPoint) -> String {
    format!("{}:{}", op.hash, op.index)
}

fn validate_owner_proof_p2pkh_v0(
    extract: fn(&[u8]) -> Option<&[u8]>,
    pkscript: &[u8],
    pubkey: &[u8],
    sig: &[u8],
    expires: u32,
) -> bool {
    let pubkey_hash160 = hash160(pubkey);
    if extract(pkscript) != Some(&pubkey_hash160[..]) {
        return false;
    }

    validate_secp256k1_p2pkh(pubkey, sig, expires)
}

fn confirmed(min_conf: i64, tx_height: i64, cur_height: i64) -> bool {
    confirms(tx_height, cur_height) >= min_conf
}

fn confirms(tx_height: i64, cur_height: i64) -> i64 {
    if tx_height == -1 || tx_height > cur_height {
        0
    } else {
        cur_height - tx_height + 1
    }
}

/// Whether a transaction output value and script length would cause
/// the output to be considered dust (dcrd mixpool `isDustAmount`).
fn is_dust_amount(amount: i64, script_size: usize, relay_fee_per_kb: i64) -> bool {
    let total_size = 8 + 2 + var_int_serialize_size(script_size as u64) + script_size + 165;

    amount.wrapping_mul(1000) / (3 * total_size as i64) < relay_fee_per_kb
}

fn check_fee(pr: &MsgMixPairReq, fee_rate: i64) -> Result<(), PoolError> {
    let mut fee = pr.input_value - i64::from(pr.message_count).wrapping_mul(pr.mix_amount);
    if let Some(change) = &pr.change {
        fee -= change.value;
    }

    let estimated_size = estimate_p2pkh_v0_serialize_size(
        pr.utxos.len(),
        pr.message_count as usize,
        pr.change.is_some(),
    );
    let required_fee = fee_for_serialize_size(fee_rate, estimated_size);
    if fee < required_fee {
        return Err(rule(RuleKind::LowInput));
    }
    let max_fee = fee_for_serialize_size(
        fee_rate,
        estimated_size.wrapping_mul(MAX_RELAY_FEE_MULTIPLIER as usize),
    );
    if fee > max_fee {
        return Err(rule(RuleKind::HighFee));
    }

    Ok(())
}

fn fee_for_serialize_size(relay_fee_per_kb: i64, tx_serialize_size: usize) -> i64 {
    let mut fee = relay_fee_per_kb.wrapping_mul(tx_serialize_size as i64) / 1000;

    if fee == 0 && relay_fee_per_kb > 0 {
        fee = relay_fee_per_kb;
    }

    const MAX_AMOUNT: i64 = 21_000_000 * 100_000_000;
    if !(0..=MAX_AMOUNT).contains(&fee) {
        fee = MAX_AMOUNT;
    }

    fee
}

const REDEEM_P2PKHV0_SIG_SCRIPT_SIZE: usize = 1 + 73 + 1 + 33;
const P2PKHV0_PK_SCRIPT_SIZE: usize = 1 + 1 + 1 + 20 + 1 + 1;

fn estimate_p2pkh_v0_serialize_size(inputs: usize, outputs: usize, has_change: bool) -> usize {
    // Sum the estimated sizes of the inputs and outputs.
    let tx_ins_size = inputs * estimate_input_size(REDEEM_P2PKHV0_SIG_SCRIPT_SIZE);
    let tx_outs_size = outputs * estimate_output_size(P2PKHV0_PK_SCRIPT_SIZE);

    let mut outputs = outputs;
    let mut change_size = 0;
    if has_change {
        change_size = estimate_output_size(P2PKHV0_PK_SCRIPT_SIZE);
        outputs += 1;
    }

    // 12 additional bytes are for version, locktime and expiry.
    12 + (2 * var_int_serialize_size(inputs as u64))
        + var_int_serialize_size(outputs as u64)
        + tx_ins_size
        + tx_outs_size
        + change_size
}

/// The worst case serialize size estimate for a tx input (dcrd
/// mixpool `estimateInputSize`).
fn estimate_input_size(script_size: usize) -> usize {
    32 + 4 + 1 + 8 + 4 + 4 + var_int_serialize_size(script_size as u64) + script_size + 4
}

/// The worst case serialize size estimate for a tx output (dcrd
/// mixpool `estimateOutputSize`).
fn estimate_output_size(script_size: usize) -> usize {
    8 + 2 + var_int_serialize_size(script_size as u64) + script_size
}

fn check_pr_limits(pr: &MsgMixPairReq) -> Result<(), PoolError> {
    if pr.mix_amount > MAX_MIX_AMOUNT {
        return Err(rule_other(format!(
            "mixed output value {} exceeds max {}",
            pr.mix_amount, MAX_MIX_AMOUNT
        )));
    }
    if pr.message_count > MAX_MCOUNT {
        return Err(rule_other(format!(
            "message count {} exceeds max {}",
            pr.message_count, MAX_MCOUNT
        )));
    }

    Ok(())
}

fn check_ke_limits(ke: &MsgMixKeyExchange) -> Result<(), PoolError> {
    if ke.seen_prs.len() as u32 > MAX_PEERS {
        return Err(rule_other(format!(
            "{} referenced PRs exceeds max peers {}",
            ke.seen_prs.len(),
            MAX_PEERS
        )));
    }

    Ok(())
}

fn check_ct_limits(ct: &MsgMixCiphertexts) -> Result<(), PoolError> {
    if ct.ciphertexts.len() as u32 > MAX_PEERS {
        return Err(rule_other(format!(
            "{} ciphertexts exceeds max peers {}",
            ct.ciphertexts.len(),
            MAX_PEERS
        )));
    }
    if ct.seen_key_exchanges.len() as u32 > MAX_PEERS {
        return Err(rule_other(format!(
            "{} referenced KEs exceeds max peers {}",
            ct.seen_key_exchanges.len(),
            ct.ciphertexts.len()
        )));
    }

    Ok(())
}

fn check_sr_limits(sr: &MsgMixSlotReserve) -> Result<(), PoolError> {
    if sr.dc_mix.len() as u32 > MAX_MCOUNT {
        return Err(rule_other(format!(
            "outer DC-mix dimension size {} exceeds max message count {}",
            sr.dc_mix.len(),
            MAX_MCOUNT
        )));
    }
    for row in &sr.dc_mix {
        if row.len() as u32 > MAX_MTOT {
            return Err(rule_other(format!(
                "inner DC-mix dimension size {} exceeds max session message total {}",
                row.len(),
                MAX_MTOT
            )));
        }
    }
    if sr.seen_ciphertexts.len() as u32 > MAX_PEERS {
        return Err(rule_other(format!(
            "{} referenced CTs exceeds max peers {}",
            sr.seen_ciphertexts.len(),
            MAX_PEERS
        )));
    }

    Ok(())
}

fn check_dc_limits(dc: &MsgMixDCNet) -> Result<(), PoolError> {
    if dc.dc_net.len() as u32 > MAX_MCOUNT {
        return Err(rule_other(format!(
            "outer DC-net dimension size {} exceeds max message count {}",
            dc.dc_net.len(),
            MAX_MCOUNT
        )));
    }
    for vect in &dc.dc_net {
        if vect.len() as u32 > MAX_MTOT {
            return Err(rule_other(format!(
                "inner DC-net dimension size {} exceeds max session message total {}",
                vect.len(),
                MAX_MTOT
            )));
        }
    }
    if dc.seen_slot_reserves.len() as u32 > MAX_PEERS {
        return Err(rule_other(format!(
            "{} referenced SRs exceeds max peers {}",
            dc.seen_slot_reserves.len(),
            MAX_PEERS
        )));
    }

    Ok(())
}

fn check_cm_limits(cm: &MsgMixConfirm) -> Result<(), PoolError> {
    let sz = cm.mix.serialize_size();
    if sz as u32 > MAX_MIX_TX_SERIALIZE_SIZE {
        return Err(rule_other(format!(
            "mix transaction serialize size {sz} exceeds maximum size {MAX_MIX_TX_SERIALIZE_SIZE}"
        )));
    }
    if cm.seen_dc_nets.len() as u32 > MAX_PEERS {
        return Err(rule_other(format!(
            "{} referenced DCs exceeds max peers {}",
            cm.seen_dc_nets.len(),
            MAX_PEERS
        )));
    }

    Ok(())
}

fn check_fp_limits(fp: &MsgMixFactoredPoly) -> Result<(), PoolError> {
    if fp.roots.len() as u32 > MAX_MTOT {
        return Err(rule_other(format!(
            "{} solved roots exceeds max session message total {}",
            fp.roots.len(),
            MAX_MTOT
        )));
    }
    if fp.seen_slot_reserves.len() as u32 > MAX_PEERS {
        return Err(rule_other(format!(
            "{} referenced SRs exceeds max peers {}",
            fp.seen_slot_reserves.len(),
            MAX_PEERS
        )));
    }

    Ok(())
}

fn check_rs_limits(rs: &MsgMixSecrets) -> Result<(), PoolError> {
    if rs.slot_reserve_msgs.len() as u32 > MAX_MCOUNT {
        return Err(rule_other(format!(
            "{} unpadded SR messages exceeds max message count {}",
            rs.slot_reserve_msgs.len(),
            MAX_MCOUNT
        )));
    }
    let dc_net_msgs: &MixVect = &rs.dc_net_msgs;
    if dc_net_msgs.len() as u32 > MAX_MCOUNT {
        return Err(rule_other(format!(
            "{} unpadded DC messages exceeds max message count {}",
            dc_net_msgs.len(),
            MAX_MCOUNT
        )));
    }
    if rs.seen_secrets.len() as u32 > MAX_PEERS {
        return Err(rule_other(format!(
            "{} referenced RSs exceeds max peers {}",
            rs.seen_secrets.len(),
            MAX_PEERS
        )));
    }

    Ok(())
}
