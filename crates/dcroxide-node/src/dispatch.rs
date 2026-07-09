// SPDX-License-Identifier: ISC
//! The server-handler dispatch for served peers — the daemon wiring of
//! dcrd `server.go`'s `serverPeer` message callbacks (`OnGetHeaders`,
//! `OnGetBlocks`, `OnGetData`) over the ported decision cores and the
//! shared chain.
//!
//! Each served connection gets a [`ServerPeerHandler`] holding the
//! per-peer server state dcrd keeps on `serverPeer` (the decaying ban
//! score, the getblocks continuation hash), sharing the daemon-wide
//! [`ServerContext`].  The handler runs on the peer's input thread and
//! queues responses through the peer's [`OutboundQueue`], so all writes
//! stay serialized on the output loop exactly like dcrd's `QueueMessage`.
//!
//! dcrd serves getdata batches asynchronously behind a semaphore and
//! pending-request counters; this synchronous translation serves each
//! batch inline on the input thread, so batches never overlap by
//! construction and the intake gates see zero prior pending requests.
//! The address/relay handlers (`OnAddr`, `OnGetAddr`, inventory relay),
//! the sync-manager forwards (`OnInv`, `OnHeaders`, block/tx intake),
//! and the mempool/mixpool-backed fetches arrive with later pieces;
//! messages without a handler are ignored, matching a dcrd node whose
//! subsystems simply have nothing to do.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use dcroxide_blockchain::process::Chain;
use dcroxide_chainhash::Hash;
use dcroxide_peer::Peer;
use dcroxide_uint256::Uint256;
use dcroxide_wire::{InvType, InvVect, Message, MsgHeaders, MsgInv, MsgNotFound};

use crate::peerloop::{OutboundQueue, ServeSignal};
use crate::server::{
    GetDataResolution, GetHeadersResponse, MAX_BLOCKS_PER_MSG, OnGetDataOutcome,
    ServeGetDataAction, ServerPeerAddrState, build_get_blocks_response, build_get_headers_response,
    on_get_data, serve_get_data,
};

/// The daemon-wide state the server handlers consult, shared across
/// every served peer (the relevant slice of dcrd's `server`).
pub struct ServerContext {
    /// The chain instance answering block locator and fetch queries.
    pub chain: Arc<Mutex<Chain>>,
    /// The minimum known chain work from the network parameters; a
    /// best tip with less cumulative work answers getheaders with an
    /// empty message (dcrd `server.minKnownWork`, zero when the
    /// network defines none).
    pub min_known_work: Option<Uint256>,
    /// Whether banning misbehaving peers is disabled (`--nobanning`).
    pub disable_banning: bool,
    /// The ban score threshold (`--banthreshold`).
    pub ban_threshold: u32,
    /// The parsed whitelisted networks (`--whitelist`); peers matching
    /// one are exempt from banning.
    pub whitelists: Vec<crate::config::IpNet>,
}

/// The per-connection server state and message dispatch (the message
/// handling slice of dcrd's `serverPeer`).
pub struct ServerPeerHandler {
    ctx: Arc<ServerContext>,
    /// The peer's address-and-abuse bookkeeping (dcrd's per-peer
    /// `knownAddresses`/`banScore` state).
    addr_state: ServerPeerAddrState,
    /// The block hash of the final inventory of a full getblocks
    /// response; serving that block triggers a best-tip inventory to
    /// prompt the next batch (dcrd `serverPeer.continueHash`).
    continue_hash: Option<Hash>,
}

impl ServerPeerHandler {
    /// Fresh per-peer server state (dcrd `newServerPeer`).
    pub fn new(ctx: Arc<ServerContext>, is_whitelisted: bool) -> ServerPeerHandler {
        ServerPeerHandler {
            ctx,
            addr_state: ServerPeerAddrState::new(is_whitelisted),
            continue_hash: None,
        }
    }

    /// Dispatch one incoming message to its server handler, queueing
    /// any responses to the peer (the `serverPeer` message listeners
    /// dcrd registers on the peer).
    pub fn handle_message(
        &mut self,
        peer: &mut Peer,
        msg: &Message,
        outbound: &OutboundQueue,
    ) -> ServeSignal {
        match msg {
            Message::GetHeaders(get_headers) => {
                self.on_get_headers(&get_headers.0, outbound);
                ServeSignal::Continue
            }
            Message::GetBlocks(get_blocks) => {
                self.on_get_blocks(peer, &get_blocks.0, outbound);
                ServeSignal::Continue
            }
            Message::GetData(get_data) => self.on_get_data(&get_data.inv_list, outbound),
            // The remaining server handlers (addr exchange, inventory
            // relay, sync-manager intake, init state, cfilters) arrive
            // with later pieces.
            _ => ServeSignal::Continue,
        }
    }

    /// Answer a getheaders request with the located headers, or with an
    /// empty headers message when the local best tip has too little
    /// cumulative work to be worth following (dcrd
    /// `serverPeer.OnGetHeaders`).
    fn on_get_headers(&self, locator: &dcroxide_wire::BlockLocator, outbound: &OutboundQueue) {
        let (work, located) = {
            let chain = self.ctx.chain.lock().expect("chain mutex poisoned");
            let best_hash = chain.best_snapshot().hash;
            (
                chain.chain_work(&best_hash),
                chain.locate_headers(&locator.block_locator_hashes, &locator.hash_stop),
            )
        };
        let min_known_work = self.ctx.min_known_work.unwrap_or_default();
        let tip_work_below_min = work.map(|work| work < min_known_work).unwrap_or(false);
        let headers = match build_get_headers_response(work.is_none(), tip_work_below_min, located)
        {
            GetHeadersResponse::Empty => Vec::new(),
            GetHeadersResponse::Headers(headers) => headers,
        };
        let _ = outbound.queue_message(Message::Headers(MsgHeaders { headers }));
    }

    /// Answer a getblocks request with the located block inventory,
    /// recording the continuation hash when the response fills an
    /// entire message (dcrd `serverPeer.OnGetBlocks`).
    fn on_get_blocks(
        &mut self,
        peer: &mut Peer,
        locator: &dcroxide_wire::BlockLocator,
        outbound: &OutboundQueue,
    ) {
        let located = {
            let chain = self.ctx.chain.lock().expect("chain mutex poisoned");
            chain.locate_blocks(
                &locator.block_locator_hashes,
                &locator.hash_stop,
                MAX_BLOCKS_PER_MSG as u32,
            )
        };
        // The known-inventory check touches the peer's LRU, so route the
        // shared reference through a cell for the decision core's `Fn`
        // seam.
        let peer = std::cell::RefCell::new(peer);
        let response =
            build_get_blocks_response(&located, |iv| peer.borrow_mut().is_known_inventory(iv));
        if let Some(continue_hash) = response.continue_hash {
            self.continue_hash = Some(continue_hash);
        }
        if !response.inv.is_empty() {
            let _ = outbound.queue_message(Message::Inv(MsgInv {
                inv_list: response.inv,
            }));
        }
    }

    /// Gate and serve a getdata request: apply dcrd's intake gates
    /// (ban empty requests, the decaying oversized-request ban score,
    /// the pending-request limits), then serve the batch inline —
    /// blocks from the chain, everything else answered in the
    /// consolidated notfound since the mempool and mix pool are not
    /// yet wired (matching a node whose pools are empty), and unknown
    /// inventory types skipped entirely (dcrd `serverPeer.OnGetData`
    /// plus `handleServeGetData`).
    fn on_get_data(&mut self, inv_list: &[InvVect], outbound: &OutboundQueue) -> ServeSignal {
        // The synchronous translation serves each batch before the next
        // getdata is read, so there are never prior pending requests.
        let outcome = on_get_data(
            &mut self.addr_state,
            inv_list.len() as u32,
            0,
            0,
            self.ctx.disable_banning,
            self.ctx.ban_threshold,
            now_unix(),
        );
        match outcome {
            // The ban outcomes drop the connection; the ban-list
            // bookkeeping refusing reconnects arrives with the
            // peer-state wiring.
            OnGetDataOutcome::BanEmpty => {
                return ServeSignal::Disconnect("sent an empty getdata request");
            }
            OnGetDataOutcome::BanScore => {
                return ServeSignal::Disconnect("ban score exceeds threshold");
            }
            OnGetDataOutcome::DisconnectConcurrent => {
                return ServeSignal::Disconnect("too many concurrent getdata requests");
            }
            OnGetDataOutcome::DisconnectPendingItems => {
                return ServeSignal::Disconnect("too many pending getdata item requests");
            }
            OnGetDataOutcome::Enqueue { .. } => {}
        }

        // Resolve each item against the chain, keeping the fetched
        // blocks so the serve actions can queue them in request order.
        let mut blocks = HashMap::new();
        let (items, best_hash) = {
            let chain = self.ctx.chain.lock().expect("chain mutex poisoned");
            let items: Vec<(InvVect, GetDataResolution)> = inv_list
                .iter()
                .map(|iv| {
                    let resolution = match iv.inv_type {
                        InvType::BLOCK => match chain.block_by_hash(&iv.hash) {
                            Some(block) => {
                                blocks.insert(iv.hash, block);
                                GetDataResolution::Found
                            }
                            None => GetDataResolution::NotFound,
                        },
                        // Transactions and mix messages resolve against
                        // pools that are not yet wired, so they miss
                        // exactly like an empty mempool's fetch.
                        InvType::TX | InvType::MIX => GetDataResolution::NotFound,
                        _ => GetDataResolution::UnknownType,
                    };
                    (*iv, resolution)
                })
                .collect();
            (items, chain.best_snapshot().hash)
        };

        let outcome = serve_get_data(&items, self.continue_hash, best_hash);
        for action in outcome.actions {
            let queued = match action {
                ServeGetDataAction::QueueData(iv) => match blocks.remove(&iv.hash) {
                    Some(block) => outbound.queue_message(Message::Block(block)),
                    None => Ok(()),
                },
                ServeGetDataAction::QueueContinueInv(best) => {
                    outbound.queue_message(Message::Inv(MsgInv {
                        inv_list: vec![InvVect {
                            inv_type: InvType::BLOCK,
                            hash: best,
                        }],
                    }))
                }
                ServeGetDataAction::QueueNotFound(inv_list) => {
                    outbound.queue_message(Message::NotFound(MsgNotFound { inv_list }))
                }
            };
            if queued.is_err() {
                // The output loop already stopped; the input loop will
                // observe the teardown on its next read.
                return ServeSignal::Continue;
            }
        }
        if outcome.cleared_continue_hash {
            self.continue_hash = None;
        }
        ServeSignal::Continue
    }
}

/// The current unix time in seconds for the decaying ban score (dcrd's
/// `time.Now()` at the score sites).
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
