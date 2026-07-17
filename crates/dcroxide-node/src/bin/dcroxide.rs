// SPDX-License-Identifier: ISC
//! The dcroxide daemon binary — the runtime front-end of dcrd's
//! `dcrd.go` `dcrdMain`: build the configuration environment from the
//! real operating system, parse the command line through the ported
//! configuration pipeline, handle the help, version, and
//! debug-level-show exits with dcrd's exit codes, print the startup
//! banner, open the block database and initialize the chain state,
//! create the address manager, bind the peer-to-peer listeners and
//! serve inbound peers, and idle on a shutdown-signal listener until
//! interrupted, then stop accepting connections.
//!
//! Served peers, inbound and dialed, run through the sync-manager
//! dispatch, and the connection manager keeps the permanent `--connect`
//! peers up while also dialing discovered peers from the address manager
//! (off simnet/regnet), which the HTTPS seeder bootstrap primes; the
//! chain carries a live UTXO cache flushed to the block database on
//! shutdown; and the JSON-RPC/websocket server binds unless `--norpc`.
//! The logging subsystem is still a fixed-prefix stdout stub
//! (`log_info`), of which the absent rotating file backend is one facet.

use std::path::Path;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dcroxide_addrmgr::{AddrManager, NetAddressType};
use dcroxide_blockchain::process::Chain;
use dcroxide_chainhash::Hash;
use dcroxide_connmgr::DEFAULT_RETRY_DURATION;
use dcroxide_database::{Database, ErrorKind, Options};
use dcroxide_node::dispatch::ServerContext;
use dcroxide_node::outbound::{OutboundConfig, start_outbound};
use dcroxide_node::runtime::{ConnectedPeers, ListenerRuntime, PeerTemplate, inbound_peer_handler};
use dcroxide_node::{
    Config, ConfigEnv, DEFAULT_TARGET_OUTBOUND, ERR_HELP_REQUESTED, ERR_SHOW_SUBSYSTEMS,
    ERR_VERSION_REQUESTED, app_data_dir, load_config_from_argv, logo, parse_listeners,
    supported_subsystems, version,
};
use dcroxide_peer::{DEFAULT_IDLE_TIMEOUT, PING_INTERVAL};
use dcroxide_rpc::server::RpcCpuMiner;
use dcroxide_wire::ServiceFlag;

const APP_NAME: &str = "dcroxide";

fn main() -> ExitCode {
    // dcrd derives the application data directory with Go's GOOS; map
    // Rust's target OS onto the same names (notably macos -> darwin).
    let goos = match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    };
    let home = app_data_dir(goos, "dcrd", false, &|name| std::env::var(name).ok());

    let env = ConfigEnv {
        default_home_dir: home,
        lookup_localhost: Box::new(|| {
            use std::net::ToSocketAddrs;
            match ("localhost", 0u16).to_socket_addrs() {
                Ok(addrs) => Ok(addrs.map(|a| a.ip().to_string()).collect()),
                Err(e) => Err(e.to_string()),
            }
        }),
        // Network interface enumeration is not yet wired, so
        // interface-name listeners do not expand; IP listeners are
        // unaffected.
        interface_by_name: Box::new(|_name| None),
        getenv: Box::new(|name| std::env::var(name).ok()),
        user_home: Box::new(|name| {
            if name.is_empty() {
                std::env::var("HOME").ok()
            } else {
                // Resolving other users' home directories is not yet
                // wired.
                None
            }
        }),
        rand_bytes: Box::new(|buf| getrandom::fill(buf).expect("system random source")),
    };

    let args: Vec<String> = std::env::args().skip(1).collect();
    match load_config_from_argv(&args, &env) {
        Ok((cfg, _remaining_args)) => run(cfg),
        Err(msg) => match msg.as_str() {
            ERR_HELP_REQUESTED => {
                // The full go-flags help text is not yet generated.
                println!("Usage: {APP_NAME} [OPTIONS]");
                println!("(the full option help text is not yet generated)");
                ExitCode::SUCCESS
            }
            ERR_VERSION_REQUESTED => {
                println!("{APP_NAME} version {}", version::version_string());
                ExitCode::SUCCESS
            }
            ERR_SHOW_SUBSYSTEMS => {
                println!("Supported subsystems {}", supported_subsystems());
                ExitCode::SUCCESS
            }
            other => {
                eprintln!("{other}");
                eprintln!("Use {APP_NAME} -h to show usage");
                ExitCode::FAILURE
            }
        },
    }
}

/// Bring the daemon up and idle until a shutdown signal.  This is the
/// portion of `dcrdMain` after a successful configuration load: it opens
/// the block database and chain, creates the address manager, binds the
/// peer listeners, starts outbound dialing, seeding, and the RPC server,
/// then idles on the shutdown listener before tearing everything down.
fn run(cfg: Config) -> ExitCode {
    print!("{}", logo::startup_banner(version::version_string()));
    println!();

    log_info(&format!(
        "Version {} ({})",
        version::version_string(),
        std::env::consts::OS
    ));
    log_info(&format!("Home dir: {}", cfg.home_dir));
    if cfg.no_file_logging {
        log_info("File logging disabled");
    }

    // The shared interrupt flag standing in for dcrd's daemon context
    // cancellation, armed before the block database work so an
    // interrupt (SIGINT) or termination (SIGTERM) signal aborts the
    // long-running index drops and catch-up too (dcrd installs its
    // shutdown listener at the top of `dcrdMain`, before
    // `loadBlockDB`).  The channel carries the same signal to the
    // idle wait at the end of startup.
    let interrupt: dcroxide_indexers::Interrupt =
        Arc::new(core::sync::atomic::AtomicBool::new(false));
    let (shutdown_tx, shutdown_rx) = mpsc::channel();
    {
        let signal_interrupt = Arc::clone(&interrupt);
        // Clone the sender for the signal handler so the original stays
        // owned by `run` and can be handed to the RPC server's
        // `request_shutdown` seam, letting the `stop` command trigger the
        // same graceful shutdown as SIGINT (dcrd's `requestProcessShutdown`
        // channel, which its signal handler also sends on).
        let signal_shutdown = shutdown_tx.clone();
        if let Err(e) = ctrlc::set_handler(move || {
            signal_interrupt.store(true, core::sync::atomic::Ordering::SeqCst);
            let _ = signal_shutdown.send(());
        }) {
            log_info(&format!("unable to install signal handler: {e}"));
            return ExitCode::FAILURE;
        }
    }

    // Load the block database and initialize the chain state, creating
    // the genesis state when the database is fresh.
    log_info("Loading block database from disk...");
    let db = match open_block_db(&cfg) {
        Ok(db) => db,
        Err(e) => {
            log_info(&format!("Unable to load block database: {e}"));
            return ExitCode::FAILURE;
        }
    };

    // Always drop the legacy address index, drop any other indexes
    // and exit if requested, then drop the legacy v1 committed filter
    // index (dcrd `dcrdMain` between `loadBlockDB` and `newServer`;
    // the order matters because dropping the tx index also drops the
    // address index since it relied on it).
    if let Err(e) = dcroxide_indexers::drop_addr_index(&interrupt, &db) {
        log_info(&format!("{e}"));
        return ExitCode::FAILURE;
    }
    if cfg.drop_tx_index {
        if let Err(e) = dcroxide_indexers::drop_tx_index(&interrupt, &db) {
            log_info(&format!("{e}"));
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }
    if cfg.drop_exists_addr_index {
        if let Err(e) = dcroxide_indexers::drop_exists_addr_index(&interrupt, &db) {
            log_info(&format!("{e}"));
            return ExitCode::FAILURE;
        }
        return ExitCode::SUCCESS;
    }
    if let Err(e) = dcroxide_indexers::drop_cf_index(&db) {
        log_info(&format!("{e}"));
        return ExitCode::FAILURE;
    }

    let chain = match open_chain(&cfg, db.clone()) {
        Ok(chain) => chain,
        Err(e) => {
            log_info(&format!("Unable to load block database: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let best = chain.best_snapshot();
    log_info(&format!(
        "Block database loaded with best block height {} hash {}",
        best.height, best.hash
    ));
    // Share the chain with the served peers' message handlers (dcrd's
    // server holding the chain the serverPeer callbacks consult).
    let chain = Arc::new(Mutex::new(chain));

    // Create the enabled indexes and catch them up to the main chain
    // (dcrd `newServer`'s index block: the transaction index under
    // --txindex, the exists address index unless disabled, one
    // catch-up over the shared subscriber).
    let indexes = if cfg.tx_index || !cfg.no_exists_addr_index {
        if cfg.tx_index {
            log_info("Transaction index is enabled");
        }
        if !cfg.no_exists_addr_index {
            log_info("Exists address index is enabled");
        }
        match dcroxide_node::indexes::start_indexes(
            Arc::clone(&interrupt),
            Arc::new(db.clone()),
            Arc::clone(&chain),
            cfg.params.params.clone(),
            cfg.tx_index,
            !cfg.no_exists_addr_index,
        ) {
            Ok(indexes) => Some(indexes),
            Err(e) => {
                log_info(&format!("Unable to start the indexes: {e}"));
                return ExitCode::FAILURE;
            }
        }
    } else {
        None
    };

    // Create the address manager and load any persisted peers (dcrd
    // `newServer`'s `addrmgr.New(cfg.DataDir)`).
    let mut addr_manager = AddrManager::new(Path::new(&cfg.data_dir));
    addr_manager.load_peers();
    let known_addrs = addr_manager.address_cache(|_: NetAddressType| true).len();
    log_info(&format!(
        "Address manager loaded {known_addrs} known address(es)"
    ));
    // Share the manager with the served peers' addr exchange.
    let addr_manager = Arc::new(Mutex::new(addr_manager));
    // Dump the address book periodically for crash resilience (the
    // ticker half of dcrd addrmgr's addressHandler; the final save
    // still runs at shutdown).
    let address_dump = dcroxide_node::seeding::start_address_dump(
        Arc::clone(&addr_manager),
        dcroxide_node::seeding::DUMP_ADDRESS_INTERVAL,
    );

    // Build the daemon-wide server state shared by every peer, inbound
    // or outbound (dcrd's single `server`).
    // The shared transaction memory pool over the chain (dcrd
    // `newServer` building the pool before the rest of the server).
    let tx_pool = dcroxide_node::txmempool::new_shared_tx_pool(
        Arc::clone(&chain),
        &cfg.params.params,
        cfg.accept_non_std,
        cfg.max_orphan_txs,
        cfg.min_relay_tx_fee_atoms,
        cfg.allow_old_votes,
        !cfg.mining_addrs.is_empty(),
    );
    // The shared fee estimator dcrd always builds in `newServer` and
    // hands to both the mempool (fed as transactions enter and leave)
    // and the RPC server (read by estimatesmartfee).  It starts
    // disabled until the first accepted block and empty each run — the
    // on-disk statistics store is deferred in the port.
    let fee_estimator = dcroxide_node::fees::new_shared_estimator(cfg.min_relay_tx_fee_atoms)
        .expect("build the fee estimator");
    tx_pool
        .lock()
        .expect("tx pool mutex poisoned")
        .set_fee_estimator(Box::new(dcroxide_node::fees::NodeFeeEstimatorSink::new(
            Arc::clone(&fee_estimator),
        )));
    // The pool records every added unconfirmed transaction's
    // addresses in the exists address index when it is enabled
    // (dcrd's mempool config carrying `ExistsAddrIndex`).
    if let Some(exists) = indexes
        .as_ref()
        .and_then(|indexes| indexes.exists_addr_index.as_ref())
    {
        tx_pool
            .lock()
            .expect("tx pool mutex poisoned")
            .set_exists_addr_index(Box::new(
                dcroxide_node::indexes::NodeUnconfirmedAddrIndexer::new(Arc::clone(exists)),
            ));
    }
    // The websocket notification manager exists whenever the RPC
    // server will run, so the peer handlers can announce accepted
    // transactions (dcrd's nil rpcServer checks).
    let ntfn = if cfg.disable_rpc {
        None
    } else {
        Some(dcroxide_node::websocket::NodeNtfnMgr::with_max_websockets(
            cfg.rpc_max_websockets.max(0) as usize,
        ))
    };
    let (server, connected, template, stall_timer) = build_server(
        &cfg,
        Arc::clone(&chain),
        Arc::clone(&addr_manager),
        Arc::clone(&tx_pool),
        ntfn.clone(),
    );

    // Track user-submitted transactions and periodically rebroadcast
    // them until they make it into a block (dcrd `server.Run`
    // launching `rebroadcastHandler` only when the RPC server runs —
    // only RPC submissions are ever tracked).
    let rebroadcaster = if cfg.disable_rpc {
        None
    } else {
        Some(dcroxide_node::rebroadcast::start_rebroadcaster(
            Arc::clone(&chain),
            server.sync_peers.clone(),
            Arc::clone(&server.recently_advertised),
        ))
    };

    // The mining policy the background template generator and the
    // getwork seam share (dcrd's mining `Policy`).
    let mining_policy = dcroxide_mining::MiningPolicy {
        block_max_size: cfg.block_max_size,
        tx_min_free_fee: cfg.min_relay_tx_fee_atoms,
        aggressive_mining: !cfg.non_aggressive,
    };

    // Feed the chain's events into the daemon handler as blocks
    // connect, disconnect, and reorganize (dcrd installing
    // handleBlockchainNotification as its blockchain notification
    // callback inside `newServer`, before any peer activity): the
    // mempool maintenance and index notifications run whether or not
    // the RPC server does — only the websocket sends need the
    // manager — and the sync adapter drains the handler's deferred
    // work after each processing call.
    // The netsync is-current gate the relay, estimator-enable, and
    // generator paths consult (dcrd wiring `s.syncManager.IsCurrent`
    // into those sites rather than the chain's own view).
    let sync_gate = dcroxide_node::sync::SyncGate::from_manager(
        &server
            .sync_manager
            .lock()
            .expect("sync manager mutex poisoned"),
    );
    let mut handler = dcroxide_node::chainntfns::ChainNtfnHandler::new(
        ntfn.clone(),
        cfg.params.params.clone(),
        cfg.allow_unsynced_mining,
        sync_gate.clone(),
        Arc::clone(&tx_pool),
        server.sync_peers.clone(),
        Arc::clone(&server.recently_advertised),
    );
    // The drained block events also feed the subscribed indexes
    // (dcrd's handler notifying `s.indexSubscriber`).
    if let Some(indexes) = &indexes {
        handler.set_index_subscriber(Arc::clone(&indexes.subscriber));
    }
    // Confirmed transactions feed the recently-confirmed filter the
    // sync manager consults, and — when the RPC server runs — remove
    // their rebroadcast entries and trigger the block-change prunes
    // (dcrd `TransactionConfirmed` and the `rpcServer != nil` gates).
    handler.set_recently_confirmed(
        server
            .sync_manager
            .lock()
            .expect("sync manager mutex poisoned")
            .recently_confirmed_txns(),
    );
    if let Some(rebroadcaster) = &rebroadcaster {
        handler.set_rebroadcast(rebroadcaster.sink());
    }
    // Every connected block feeds the fee estimator, and the first
    // accepted block enables it (dcrd's `s.feeEstimator` driven from
    // the chain notifications, run whether or not the RPC server does).
    handler.set_fee_estimator(Arc::clone(&fee_estimator));

    // Run the background block template generator when mining addresses
    // are configured (dcrd only constructs `s.bg` and serves getwork
    // with `--miningaddr` set): a dedicated thread drives the
    // regeneration state machine over the live chain and mempool,
    // feeding the getwork RPC and the websocket work notifications.  It
    // starts after the chain handler exists so its drain hook can run
    // the handler's deferred maintenance for reorgs the generator
    // itself initiates (which the sync adapter's post-process drain
    // never covers).
    let generator = if cfg.mining_addrs.is_empty() {
        None
    } else {
        let drain_handler = handler.clone();
        let drain_chain = Arc::clone(&chain);
        let drain_hook: Box<dyn Fn() + Send> = Box::new(move || {
            drain_handler.drain_pending(&drain_chain, now_unix());
        });
        Some(dcroxide_node::bgtemplate::start_generator(
            Arc::clone(&chain),
            Arc::clone(&tx_pool),
            cfg.params.params.clone(),
            cfg.mining_addrs.clone(),
            mining_policy.clone(),
            cfg.mining_time_offset,
            cfg.allow_unsynced_mining,
            sync_gate.clone(),
            ntfn.clone(),
            Some(drain_hook),
        ))
    };

    // Forward accepted votes from the pool into the generator (dcrd's
    // mempool `OnVoteReceived` firing `s.bg.VoteReceived`).
    if let Some(generator) = &generator {
        tx_pool
            .lock()
            .expect("tx pool mutex poisoned")
            .set_vote_receiver(Box::new(dcroxide_node::bgtemplate::NodeVoteReceiver::new(
                generator.sink(),
            )));
    }

    // The chain's block and reorganization events feed the background
    // template generator (dcrd's chain notifications driving `s.bg`).
    if let Some(generator) = &generator {
        handler.set_generator(generator.sink());
    }
    {
        let callback_handler = handler.clone();
        chain
            .lock()
            .expect("chain mutex poisoned")
            .set_notification_callback(Box::new(move |n| callback_handler.handle(n)));
    }
    server
        .sync_manager
        .lock()
        .expect("sync manager mutex poisoned")
        .chain_mut()
        .set_chain_ntfn_handler(handler);

    // The CPU miner (dcrd `s.cpuMiner`), built and started whenever a
    // block template generator runs — i.e. mining addresses are
    // configured — so it can mine under `--norpc` too, exactly as dcrd
    // runs `go s.cpuMiner.Run(ctx)` unconditionally in `newServer`.  The
    // background threads start idle; `--generate` kicks off continuous
    // mining with the default worker count (dcrd's `if cfg.Generate {
    // SetNumWorkers(-1) }`).  The RPC-facing `NodeCpuMiner` moves into
    // the RPC server config below; the `MinerRuntime` stays here to be
    // shut down at the end.
    let mut cpu_miner: Option<dcroxide_node::cpuminer::NodeCpuMiner> = None;
    let mut miner_runtime: Option<dcroxide_node::cpuminer::MinerRuntime> = None;
    if let Some(generator) = &generator {
        let mut miner = dcroxide_node::cpuminer::NodeCpuMiner::new(
            generator.current_handle(),
            generator.subscribers_handle(),
            generator.sink(),
            Arc::clone(&chain),
            Arc::clone(&server.sync_manager),
            Arc::clone(&tx_pool),
            cfg.params.params.clone(),
            mining_policy.clone(),
            cfg.mining_time_offset,
            connected.clone(),
            cfg.sim_net || cfg.reg_net,
        );
        let runtime = miner.start();
        if cfg.generate {
            miner.set_num_workers(-1);
        }
        cpu_miner = Some(miner);
        miner_runtime = Some(runtime);
    }

    // The outbound driver's command channel is created ahead of the RPC
    // server so its control handle can back the manual peer-control
    // RPCs (`addnode`, `node connect`/`remove`); the driver itself
    // starts below with the other peer activity.
    let outbound_channel = dcroxide_node::outbound::outbound_channel();

    // Serve the JSON-RPC endpoint (dcrd's RPC server): TLS over the
    // generated certificate pair by default, plain HTTP under the
    // localhost-validated --notls.  This runs before the peer-to-peer
    // listeners come up, like dcrd's rpc server existing before
    // `server.Run` starts any peer activity (the chain notification
    // callback installs even earlier, above, with the handler).
    let rpc_listener = if cfg.disable_rpc {
        log_info("RPC service is disabled");
        None
    } else {
        let transport = if cfg.disable_tls {
            dcroxide_node::rpcrun::RpcTransport::Plain
        } else {
            let config = dcroxide_node::rpcrun::load_or_generate_cert_pair(
                Path::new(&cfg.rpc_cert),
                Path::new(&cfg.rpc_key),
                &cfg.external_ips,
            )
            .and_then(|(cert, key)| dcroxide_node::rpcrun::tls_server_config(&cert, &key));
            match config {
                Ok(config) => dcroxide_node::rpcrun::RpcTransport::Tls(config),
                Err(e) => {
                    log_info(&format!("Unable to set up RPC TLS: {e}"));
                    return ExitCode::FAILURE;
                }
            }
        };
        // The index seams over the live indexes (dcrd assigning
        // `s.txIndex` and `s.existsAddrIndex` to the rpcserver
        // config).
        let tx_indexer = indexes
            .as_ref()
            .and_then(|indexes| indexes.tx_index.as_ref().map(|index| (index, indexes)))
            .map(|(index, indexes)| {
                Box::new(dcroxide_node::indexes::NodeRpcTxIndexer::new(
                    Arc::clone(index),
                    Arc::clone(&indexes.queryer),
                )) as Box<dyn dcroxide_rpc::server::RpcTxIndexer + Send>
            });
        let exists_addresser = indexes
            .as_ref()
            .and_then(|indexes| {
                indexes
                    .exists_addr_index
                    .as_ref()
                    .map(|index| (index, indexes))
            })
            .map(|(index, indexes)| {
                Box::new(dcroxide_node::indexes::NodeRpcExistsAddresser::new(
                    Arc::clone(index),
                    Arc::clone(&indexes.queryer),
                )) as Box<dyn dcroxide_rpc::server::RpcExistsAddresser + Send>
            });
        // The getwork seam over the running generator (dcrd assigning
        // `s.bg` to the rpcserver config's `BlockTemplater`); `None`
        // when no mining addresses are configured, so getwork errors
        // with dcrd's "no payment addresses" message.
        let block_templater = generator.as_ref().map(|generator| {
            Box::new(dcroxide_node::bgtemplate::NodeRpcBlockTemplater::new(
                generator.current_handle(),
                generator.subscribers_handle(),
                generator.sink(),
                Arc::clone(&chain),
                Arc::clone(&tx_pool),
                cfg.params.params.clone(),
                mining_policy.clone(),
                cfg.mining_time_offset,
            )) as Box<dyn dcroxide_rpc::server::RpcBlockTemplater + Send>
        });
        // Hand the already-built CPU miner to the RPC server so
        // `generate`/`setgenerate`/`getmininginfo` reach it (dcrd
        // assigning `s.cpuMiner`); the idle stand-in when no mining
        // addresses are configured, so `generate` answers dcrd's "no
        // payment addresses" error.
        let cpu_miner: Box<dyn dcroxide_rpc::server::RpcCpuMiner + Send> = match cpu_miner.take() {
            Some(miner) => Box::new(miner),
            None => Box::new(dcroxide_node::rpcrun::IdleCpuMiner),
        };
        // The `stop` RPC requests the same graceful shutdown as an
        // interrupt: set the shared interrupt flag and send on the
        // shutdown channel the idle wait blocks on (dcrd's non-blocking
        // send on the server's `requestProcessShutdown` channel).
        let request_shutdown: Box<dyn FnMut() + Send> = {
            let interrupt = Arc::clone(&interrupt);
            let shutdown_tx = shutdown_tx.clone();
            Box::new(move || {
                interrupt.store(true, core::sync::atomic::Ordering::SeqCst);
                let _ = shutdown_tx.send(());
            })
        };
        let mut rpc_srv = dcroxide_rpc::server::Server::new(rpc_config(
            &cfg,
            Arc::clone(&chain),
            connected.clone(),
            Arc::clone(&server.sync_manager),
            Arc::clone(&server.net_totals),
            Arc::clone(&tx_pool),
            server.sync_peers.clone(),
            Arc::clone(&server.recently_advertised),
            rebroadcaster
                .as_ref()
                .expect("the rebroadcaster exists when RPC is enabled")
                .sink(),
            ntfn.clone()
                .expect("the manager exists when RPC is enabled"),
            tx_indexer,
            exists_addresser,
            db.clone(),
            block_templater,
            Arc::clone(&fee_estimator),
            cpu_miner,
            Arc::clone(&addr_manager),
            request_shutdown,
            outbound_channel.control(),
        ));
        // Install the websocket notification manager (dcrd's
        // wsNotificationManager) and start its delivery thread over
        // the server.
        let ntfn = ntfn
            .clone()
            .expect("the manager exists when RPC is enabled");
        rpc_srv.ntfn_mgr = Box::new(ntfn.clone());
        let rpc_server = Arc::new(Mutex::new(rpc_srv));
        let ntfn_thread = ntfn.start(Arc::clone(&rpc_server));
        match dcroxide_node::rpcrun::start_rpc_listener(
            &cfg.rpc_listeners,
            rpc_server,
            transport,
            ntfn.clone(),
            cfg.rpc_max_clients.max(0) as usize,
        ) {
            Ok(listener) => {
                let addrs: Vec<String> = listener
                    .bound_addrs()
                    .iter()
                    .map(|addr| addr.to_string())
                    .collect();
                log_info(&format!("RPC server listening on {}", addrs.join(", ")));
                Some((listener, ntfn, ntfn_thread))
            }
            Err(e) => {
                log_info(&format!("Unable to start RPC server: {e}"));
                return ExitCode::FAILURE;
            }
        }
    };

    // Bind the peer-to-peer listeners and start serving inbound peers
    // unless listening is disabled (dcrd's server listeners).
    let runtime = if cfg.disable_listen {
        log_info("Listening for peer-to-peer connections is disabled");
        None
    } else {
        match start_listeners(&cfg, &template, connected.clone(), Arc::clone(&server)) {
            Ok(runtime) => {
                let addrs: Vec<String> = runtime
                    .bound_addrs()
                    .iter()
                    .map(|addr| addr.to_string())
                    .collect();
                log_info(&format!(
                    "Serving peer-to-peer connections on {}",
                    if addrs.is_empty() {
                        "(no listeners bound)".to_string()
                    } else {
                        addrs.join(", ")
                    }
                ));
                Some(runtime)
            }
            Err(e) => {
                log_info(&format!("Unable to start peer-to-peer listeners: {e}"));
                return ExitCode::FAILURE;
            }
        }
    };

    // Open outbound connections through the connection manager: the
    // permanent `--connect` peers when configured, otherwise automatic
    // dialing from the address manager.  dcrd installs `newAddressFunc`
    // only when there are no `--connect` peers AND the network is neither
    // simnet nor regnet — those networks stay in connect-only mode and
    // never dial discovered peers (dcrd server.go: `!cfg.SimNet &&
    // !cfg.RegNet && len(cfg.ConnectPeers) == 0`).
    let get_new_address = if !cfg.sim_net && !cfg.reg_net && cfg.connect_peers.is_empty() {
        Some(dcroxide_node::outbound::new_address_source(
            Arc::clone(&addr_manager),
            server.outbound_groups.clone(),
            cfg.params.params.default_port.to_string(),
        ))
    } else {
        log_info(&format!(
            "Connecting to {} permanent peer(s)",
            cfg.connect_peers.len()
        ));
        None
    };
    // Resolve the permanent peers up front (dcrd `newServer` running
    // each through `addrStringToNetAddr`, failing the start on an
    // unresolvable address), so the manager's stored request addresses
    // are the resolved form the duplicate-connect and cancel-pending
    // checks compare against.
    let mut permanent = Vec::with_capacity(cfg.connect_peers.len());
    for addr in &cfg.connect_peers {
        match dcroxide_node::outbound::addr_string_to_socket_addr(addr) {
            Ok(resolved) => permanent.push(resolved.to_string()),
            Err(e) => {
                log_info(&format!("Unable to resolve connect peer {addr}: {e}"));
                return ExitCode::FAILURE;
            }
        }
    }
    let connector = start_outbound(
        OutboundConfig {
            template: template.clone(),
            connected: connected.clone(),
            server: Some(Arc::clone(&server)),
            target_outbound: DEFAULT_TARGET_OUTBOUND.min(cfg.max_peers) as u32,
            max_peers: cfg.max_peers.max(0) as usize,
            retry_duration: Duration::from_nanos(DEFAULT_RETRY_DURATION as u64),
            dial_timeout: Duration::from_nanos(cfg.dial_timeout_nanos as u64),
            // The configured dial routing: direct, or SOCKS5 with the
            // onion rules (dcrd's dcrdDial closures).
            dialer: dcroxide_node::socks::NodeDialer::from_config(&cfg),
            permanent,
            get_new_address,
            // Record dial attempts against the address manager off simnet and
            // regnet, matching where dcrd installs attemptDcrdDial.
            addr_manager: if !cfg.sim_net && !cfg.reg_net {
                Some(Arc::clone(&addr_manager))
            } else {
                None
            },
        },
        outbound_channel,
    );
    // Query the network seeders to bootstrap the address manager (dcrd
    // `Run` launching `querySeeders` when seeding is enabled).
    let seeder_boot = if cfg.disable_seeders {
        log_info("Peer discovery through seeders is disabled");
        None
    } else {
        let seeders: Vec<String> = cfg
            .params
            .params
            .seeders
            .iter()
            .map(|s| s.to_string())
            .collect();
        if seeders.is_empty() {
            None
        } else {
            log_info(&format!("Querying {} network seeder(s)", seeders.len()));
            // dcrd routes its seeder HTTP transport through `dcrdDial`,
            // so a proxied daemon queries the seeders over the SOCKS
            // proxy rather than leaking the traffic; without a proxy the
            // battle-tested ureq transport does the direct dial.
            let services = ServiceFlag::NODE_NETWORK.0;
            if cfg.dial == dcroxide_node::config::DialSelection::SocksProxy {
                let dialer = dcroxide_node::socks::NodeDialer::from_config(&cfg);
                Some(dcroxide_node::seeding::start_seeding(
                    seeders,
                    Arc::clone(&addr_manager),
                    services,
                    move || dcroxide_node::seeding::ProxySeederTransport::new(dialer.clone()),
                ))
            } else {
                Some(dcroxide_node::seeding::start_seeding(
                    seeders,
                    Arc::clone(&addr_manager),
                    services,
                    dcroxide_node::seeding::UreqTransport::new,
                ))
            }
        }
    };

    log_info("Serving peers until a shutdown signal is received.");

    // Idle until the signal handler armed at startup reports an
    // interrupt (SIGINT) or termination (SIGTERM) signal, mirroring
    // dcrd's shutdown listener.
    let _ = shutdown_rx.recv();

    // Stop seeding and dialing, stop the watchdog, disconnect the live
    // peers, and stop accepting new connections (dcrd's server
    // shutdown).
    // Signal the miner to stop hashing so any in-flight solve or
    // `generate` winds down promptly and releases the RPC server before
    // the listener is torn down.
    if let Some(runtime) = &miner_runtime {
        runtime.signal_quit();
    }
    if let Some((rpc_listener, ntfn, ntfn_thread)) = rpc_listener {
        rpc_listener.shutdown();
        ntfn.shutdown();
        if let Some(thread) = ntfn_thread {
            let _ = thread.join();
        }
    }
    if let Some(seeder_boot) = seeder_boot {
        seeder_boot.shutdown();
    }
    connector.shutdown();
    stall_timer.shutdown();
    if let Some(rebroadcaster) = rebroadcaster {
        rebroadcaster.shutdown();
    }
    // Stop the miner's background threads before the generator so its
    // workers deregister their template subscriptions first, and while
    // the chain, sync manager, and database are still live for any
    // in-flight block submission to complete.
    if let Some(runtime) = miner_runtime {
        runtime.shutdown();
    }
    if let Some(generator) = generator {
        generator.shutdown();
    }
    connected.disconnect_all();
    if let Some(runtime) = runtime {
        runtime.shutdown();
    }

    // Stop the periodic dump ticker, then persist the address book so a
    // restart redials its learned peers instead of re-bootstrapping from
    // the seeders every time (dcrd's final `savePeers` when the address
    // handler stops).  save_peers is a no-op when nothing changed and
    // writes atomically.
    address_dump.shutdown();
    if let Err(e) = addr_manager
        .lock()
        .expect("addr manager mutex poisoned")
        .save_peers()
    {
        log_info(&format!("Unable to save peers: {e}"));
    }

    // Flush the chain's in-memory UTXO cache and modified block index to
    // the database now that no thread can process another block (dcrd's
    // clean-shutdown flush).  Every connect persists the best state but
    // holds the UTXO changes in the cache, so without this a restart
    // loads a best state ahead of the persisted UTXO set and wedges the
    // node on the next block.
    log_info("Flushing the block database to disk...");
    if let Err(e) = chain
        .lock()
        .expect("chain mutex poisoned")
        .flush(&cfg.params.params)
    {
        log_info(&format!("Unable to flush the block database: {e:?}"));
    }

    log_info("Shutdown complete");
    ExitCode::SUCCESS
}

/// Build the daemon-wide server state: the shared context the peer
/// handlers consult, the connected-peer registry, the peer template,
/// and the armed header-sync watchdog (dcrd `newServer`).
fn build_server(
    cfg: &Config,
    chain: Arc<Mutex<Chain>>,
    addr_manager: Arc<Mutex<AddrManager>>,
    tx_pool: Arc<Mutex<dcroxide_node::txmempool::NodeTxPool>>,
    ntfn: Option<dcroxide_node::websocket::NodeNtfnMgr>,
) -> (
    Arc<ServerContext>,
    ConnectedPeers,
    PeerTemplate,
    dcroxide_node::dispatch::StallTimer,
) {
    let params = &cfg.params.params;
    let template = PeerTemplate {
        net: params.net,
        // 0 selects the package's maximum protocol version.
        protocol_version: 0,
        // dcrd's `defaultServices`.
        services: ServiceFlag::NODE_NETWORK,
        user_agent_name: APP_NAME.to_string(),
        user_agent_version: version::version_string().to_string(),
        idle_timeout: Duration::from_nanos(DEFAULT_IDLE_TIMEOUT as u64),
        ping_interval: Duration::from_nanos(PING_INTERVAL as u64),
    };
    // The mixing pool the getdata serve path and the sync manager share
    // (dcrd `newServer` building one `mixpool.Pool`).
    let mix_pool = dcroxide_node::mixnode::shared_mix_pool(Arc::clone(&chain), params.clone());
    // The sync manager shares the chain with the message handlers
    // (dcrd `newServer` building its `netsync.Config`).
    let sync_manager = Arc::new(Mutex::new(dcroxide_node::sync::new_sync_manager(
        Arc::clone(&chain),
        params,
        cfg.no_mining_state_sync,
        // dcrd's targetOutbound: the default capped by --maxpeers.
        DEFAULT_TARGET_OUTBOUND.min(cfg.max_peers) as u64,
        cfg.max_orphan_txs as usize,
        Arc::clone(&tx_pool),
        Arc::clone(&mix_pool),
    )));
    // The daemon-wide state the served peers' message handlers consult
    // (dcrd `newServer` deriving `minKnownWork` from the params).
    let server = Arc::new(ServerContext {
        chain,
        min_known_work: params.min_known_chain_work,
        params: params.clone(),
        disable_banning: cfg.disable_banning,
        ban_threshold: cfg.ban_threshold,
        whitelists: cfg.whitelists.clone(),
        addr_manager,
        sim_or_reg_net: cfg.sim_net || cfg.reg_net,
        stake_validation_height: params.stake_validation_height,
        blocks_only: cfg.blocks_only,
        sync_manager,
        sync_peers: dcroxide_node::dispatch::SyncPeers::new(),
        next_peer_id: std::sync::atomic::AtomicI32::new(1),
        outbound_groups: dcroxide_node::dispatch::OutboundGroups::new(),
        net_totals: std::sync::Arc::new(dcroxide_node::transport::NetByteTotals::new()),
        disable_listen: cfg.disable_listen,
        tx_pool,
        ntfn,
        recently_advertised: dcroxide_node::dispatch::new_recently_advertised(),
        mix_pool,
    });
    // Arm the header-sync stall watchdog around the manager (dcrd's
    // stallHandler timer).
    let stall_timer = dcroxide_node::dispatch::start_stall_timer(
        Arc::clone(&server.sync_manager),
        server.sync_peers.clone(),
        Duration::from_secs(dcroxide_netsync::manager::HEADER_SYNC_STALL_TIMEOUT_SECS),
    );
    (server, ConnectedPeers::new(), template, stall_timer)
}

/// Bind the configured peer-to-peer listeners and start serving inbound
/// peers (dcrd `newServer`'s listener setup plus `inboundPeerConnected`).
fn start_listeners(
    cfg: &Config,
    template: &PeerTemplate,
    connected: ConnectedPeers,
    server: Arc<ServerContext>,
) -> Result<ListenerRuntime, String> {
    let specs = parse_listeners(&cfg.listeners)?;
    ListenerRuntime::start(
        &specs,
        inbound_peer_handler(
            template.clone(),
            connected,
            Some(server),
            cfg.max_peers.max(0) as usize,
        ),
    )
    .map_err(|e| e.to_string())
}

/// Open (or create) the block database (dcrd `dcrdMain`'s
/// `loadBlockDB`).  The block database lives at
/// `<datadir>/blocks_<dbtype>`; the same handle backs the chain and
/// the enabled indexes.
fn open_block_db(cfg: &Config) -> Result<Database, String> {
    let params = &cfg.params.params;
    let db_path = Path::new(&cfg.data_dir).join(format!("blocks_{}", cfg.db_type));
    let opts = Options::new(&db_path, params.net.0);

    // Open the existing database, creating it when it does not yet
    // exist (dcrd's `database.Open` then `database.Create` fallback).
    match Database::open(&opts) {
        Ok(db) => Ok(db),
        Err(e) if e.kind == ErrorKind::DbDoesNotExist => {
            std::fs::create_dir_all(&db_path)
                .map_err(|e| format!("unable to create database directory: {e}"))?;
            Database::create(&opts).map_err(|e| format!("unable to create database: {e}"))
        }
        Err(e) => Err(format!("unable to open database: {e}")),
    }
}

/// Initialize the chain state over the open block database (the chain
/// construction inside dcrd's `newServer`); a fresh database creates
/// the genesis chain state.
fn open_chain(cfg: &Config, db: Database) -> Result<Chain, String> {
    let params = &cfg.params.params;

    // The assume-valid hash defaults to the network's hard-coded value
    // and is overridden by the command line when provided.
    let assume_valid = if cfg.assume_valid.is_empty() {
        params.assume_valid
    } else {
        cfg.assume_valid
            .parse::<Hash>()
            .map_err(|e| format!("invalid assumevalid hash: {e:?}"))?
    };

    let created_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    Chain::open(db, params, assume_valid, cfg.allow_old_forks, created_unix)
        .map_err(|e| format!("unable to initialize chain: {e:?}"))
}

/// Build the RPC server configuration over the shared chain with the
/// daemon's not-yet-wired subsystem seams as no-ops (dcrd `newRPCServer`;
/// each seam fills in as its subsystem lands).
// Mirrors dcrd's rpcserver config assembly, which takes the same set.
#[allow(clippy::too_many_arguments)]
fn rpc_config(
    cfg: &Config,
    chain: Arc<Mutex<Chain>>,
    connected: ConnectedPeers,
    sync_manager: Arc<Mutex<dcroxide_node::sync::NodeSyncManager>>,
    net_totals: Arc<dcroxide_node::transport::NetByteTotals>,
    tx_pool: Arc<Mutex<dcroxide_node::txmempool::NodeTxPool>>,
    sync_peers: dcroxide_node::dispatch::SyncPeers,
    recently_advertised: Arc<
        Mutex<dcroxide_containers::lru::Map<dcroxide_chainhash::Hash, dcroxide_wire::MsgTx>>,
    >,
    rebroadcast: dcroxide_node::rebroadcast::RebroadcastSink,
    ntfn: dcroxide_node::websocket::NodeNtfnMgr,
    tx_indexer: Option<Box<dyn dcroxide_rpc::server::RpcTxIndexer + Send>>,
    exists_addresser: Option<Box<dyn dcroxide_rpc::server::RpcExistsAddresser + Send>>,
    db: Database,
    block_templater: Option<Box<dyn dcroxide_rpc::server::RpcBlockTemplater + Send>>,
    fee_estimator: dcroxide_node::fees::SharedFeeEstimator,
    cpu_miner: Box<dyn dcroxide_rpc::server::RpcCpuMiner + Send>,
    addr_manager: Arc<Mutex<AddrManager>>,
    request_shutdown: Box<dyn FnMut() + Send>,
    outbound_control: dcroxide_node::outbound::OutboundControl,
) -> dcroxide_rpc::server::Config<dcroxide_node::rpcrun::NodeRpcChain> {
    let params = cfg.params.params.clone();
    // The version 2 filter source shares the live chain (cloned before it
    // is moved into the chain adapter below); the sanity checker keeps the
    // parameters (cloned before they are moved into the subsidy cache).
    let filterer_v2 = dcroxide_node::rpcrun::NodeRpcFiltererV2::new(Arc::clone(&chain));
    let sanity_checker = dcroxide_node::rpcrun::NodeRpcSanityChecker::new(params.clone());
    dcroxide_rpc::server::Config {
        chain: dcroxide_node::rpcrun::NodeRpcChain::new(chain, params.clone()),
        chain_params: params.clone(),
        subsidy_cache: dcroxide_standalone::SubsidyCache::new(
            dcroxide_rpc::server::RpcSubsidyParams(params),
        ),
        min_relay_tx_fee: cfg.min_relay_tx_fee_atoms,
        max_protocol_version: dcroxide_wire::PROTOCOL_VERSION,
        sync_mgr: Box::new(dcroxide_node::rpcrun::NodeRpcSyncManager::new(
            sync_manager,
            Arc::clone(&tx_pool),
        )),
        conn_mgr: Box::new(
            dcroxide_node::rpcrun::NodeRpcConnManager::new(connected, net_totals)
                .with_relay(
                    sync_peers,
                    recently_advertised,
                    Arc::clone(&tx_pool),
                    rebroadcast,
                    ntfn.clone(),
                )
                .with_outbound(outbound_control)
                // The configured lookup routing, so getaddednodeinfo's
                // DNS detail resolves like dcrd's dcrdLookup.
                .with_dialer(dcroxide_node::socks::NodeDialer::from_config(cfg)),
        ),
        tx_mempooler: Box::new(dcroxide_node::txmempool::NodeRpcTxMempooler::new(tx_pool)),
        clock: Box::new(dcroxide_node::rpcrun::SystemClock),
        interfaces: Box::new(dcroxide_rpc::helpers::NoInterfaces),
        rand_u64: Box::new(|| {
            let mut buf = [0u8; 8];
            getrandom::fill(&mut buf).expect("system random source");
            u64::from_le_bytes(buf)
        }),
        tx_indexer,
        db: Box::new(dcroxide_node::indexes::NodeRpcDb::new(db)),
        filterer_v2: Box::new(filterer_v2),
        exists_addresser,
        log_manager: Box::new(()),
        fee_estimator: Box::new(dcroxide_node::fees::NodeRpcFeeEstimator::new(fee_estimator)),
        block_templater,
        sanity_checker: Box::new(sanity_checker),
        time_source: Box::new(dcroxide_node::rpcrun::SystemTimeSource),
        proxy: cfg.proxy.clone(),
        test_net: cfg.test_net,
        runtime_version: String::new(),
        // The generating CPU miner arrives with a later piece; the idle
        // stand-in reports not-mining so the getwork handler's mining
        // gate allows work polling and submission (dcrd's miner is off
        // by default).
        cpu_miner,
        mix_pooler: Box::new(()),
        profiler_mgr: Box::new(()),
        addr_manager: Box::new(dcroxide_node::rpcrun::NodeRpcAddrManager::new(addr_manager)),
        mining_addrs: cfg.mining_addrs.clone(),
        user_agent_version: version::version_string().to_string(),
        // The three per-network reachability descriptions the config's
        // `parse_network_interfaces` already derived from the listeners
        // and proxy settings (dcrd's `cfg.generateNetworkInfo()`).
        net_info: vec![
            cfg.ipv4_net_info.clone(),
            cfg.ipv6_net_info.clone(),
            cfg.onion_net_info.clone(),
        ],
        services: ServiceFlag::NODE_NETWORK.0,
        request_shutdown,
        allow_unsynced_mining: cfg.allow_unsynced_mining,
        rpc_user: cfg.rpc_user.clone(),
        rpc_pass: cfg.rpc_pass.clone(),
        rpc_limit_user: cfg.rpc_limit_user.clone(),
        rpc_limit_pass: cfg.rpc_limit_pass.clone(),
    }
}

/// The current time as unix seconds (matching the sync adapter's
/// `adjusted_time_unix`), for driving the chain handler's deferred
/// maintenance from the generator's drain hook.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A minimal startup log line until the rotating logging subsystem is
/// wired.
fn log_info(msg: &str) {
    println!("[INF] DCRD: {msg}");
}
