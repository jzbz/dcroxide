// SPDX-License-Identifier: ISC
//! Shared replay machinery for the configuration and flags vector
//! tests: hex decoding and the effective-config emit that mirrors
//! the dumps' field order.

// Index arithmetic over pinned vector rows.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_node::config::Config;
use dcroxide_node::logsubsys::SUBSYSTEM_IDS;

// Only the config vector binary decodes hex rows.
#[allow(dead_code)]
pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Rebuild the dump's emitted key=value payload from the effective
/// config.
pub fn emit_cfg(cfg: &Config, remaining: &[String], home: &str, norm_creds: bool) -> String {
    let rep = |s: &str| s.replace(home, "@HOME@");
    let reps = |v: &[String]| v.iter().map(|s| rep(s)).collect::<Vec<_>>().join(",");
    let dur = dcroxide_node::go_duration_string;
    let mut kv: Vec<String> = Vec::new();
    let mut add = |k: &str, v: String| kv.push(format!("{k}={v}"));

    add("homedir", rep(&cfg.home_dir));
    add("configfile", rep(&cfg.config_file));
    add("datadir", rep(&cfg.data_dir));
    add("logdir", rep(&cfg.log_dir));
    add("logsize", cfg.log_size.clone());
    add("nofilelogging", cfg.no_file_logging.to_string());
    add("dbtype", cfg.db_type.clone());
    add("profile", cfg.profile.clone());
    add("cpuprofile", cfg.cpu_profile.clone());
    add("memprofile", cfg.mem_profile.clone());
    add("testnet", cfg.test_net.to_string());
    add("simnet", cfg.sim_net.to_string());
    add("regnet", cfg.reg_net.to_string());
    add("debuglevel", cfg.debug_level.clone());
    add("sigcachemaxsize", cfg.sig_cache_max_size.to_string());
    add("utxocachemaxsize", cfg.utxo_cache_max_size.to_string());
    add("norpc", cfg.disable_rpc.to_string());
    add("rpclisten", reps(&cfg.rpc_listeners));
    if norm_creds && !cfg.rpc_user.is_empty() {
        add("rpcuser", "@RAND@".to_string());
        add("rpcpass", "@RAND@".to_string());
    } else {
        add("rpcuser", cfg.rpc_user.clone());
        add("rpcpass", cfg.rpc_pass.clone());
    }
    add("authtype", cfg.rpc_auth_type.clone());
    add("clientcafile", rep(&cfg.rpc_client_cas));
    add("rpclimituser", cfg.rpc_limit_user.clone());
    add("rpclimitpass", cfg.rpc_limit_pass.clone());
    add("rpccert", rep(&cfg.rpc_cert));
    add("rpckey", rep(&cfg.rpc_key));
    add("tlscurve", cfg.tls_curve.clone());
    add("altdnsnames", cfg.alt_dns_names.join(","));
    add("notls", cfg.disable_tls.to_string());
    add("rpcmaxclients", cfg.rpc_max_clients.to_string());
    add("rpcmaxwebsockets", cfg.rpc_max_websockets.to_string());
    add(
        "rpcmaxconcurrentreqs",
        cfg.rpc_max_concurrent_reqs.to_string(),
    );
    add("proxy", cfg.proxy.clone());
    add("proxyuser", cfg.proxy_user.clone());
    add("proxypass", cfg.proxy_pass.clone());
    add("onion", cfg.onion_proxy.clone());
    add("onionuser", cfg.onion_proxy_user.clone());
    add("onionpass", cfg.onion_proxy_pass.clone());
    add("noonion", cfg.no_onion.to_string());
    add("torisolation", cfg.tor_isolation.to_string());
    add("addpeer", reps(&cfg.add_peers));
    add("connect", reps(&cfg.connect_peers));
    add("nolisten", cfg.disable_listen.to_string());
    add("listen", reps(&cfg.listeners));
    add("maxsameip", cfg.max_same_ip.to_string());
    add("maxpeers", cfg.max_peers.to_string());
    add("dialtimeout", dur(cfg.dial_timeout_nanos));
    add("peeridletimeout", dur(cfg.peer_idle_timeout_nanos));
    add("noseeders", cfg.disable_seeders.to_string());
    add("nodnsseed", cfg.disable_dns_seed.to_string());
    add("externalip", cfg.external_ips.join(","));
    add("nodiscoverip", cfg.no_discover_ip.to_string());
    add("upnp", cfg.upnp.to_string());
    add("nobanning", cfg.disable_banning.to_string());
    add("banduration", dur(cfg.ban_duration_nanos));
    add("banthreshold", cfg.ban_threshold.to_string());
    add("whitelistraw", cfg.whitelists_raw.join(","));
    add("allowoldforks", cfg.allow_old_forks.to_string());
    add("dumpblockchain", rep(&cfg.dump_blockchain));
    add("assumevalid", cfg.assume_valid.clone());
    add("minrelaytxfee", format!("{}", cfg.min_relay_tx_fee));
    add("limitfreerelay", format!("{}", cfg.free_tx_relay_limit));
    add("norelaypriority", cfg.no_relay_priority.to_string());
    add("maxorphantx", cfg.max_orphan_txs.to_string());
    add("blocksonly", cfg.blocks_only.to_string());
    add("acceptnonstd", cfg.accept_non_std.to_string());
    add("rejectnonstd", cfg.reject_non_std.to_string());
    add("allowoldvotes", cfg.allow_old_votes.to_string());
    add("generate", cfg.generate.to_string());
    add("miningaddrraw", cfg.mining_addrs_raw.join(","));
    add("blockminsize", cfg.block_min_size.to_string());
    add("blockmaxsize", cfg.block_max_size.to_string());
    add("blockprioritysize", cfg.block_priority_size.to_string());
    add("miningtimeoffset", cfg.mining_time_offset.to_string());
    add("nonaggressive", cfg.non_aggressive.to_string());
    add("nominingstatesync", cfg.no_mining_state_sync.to_string());
    add("allowunsyncedmining", cfg.allow_unsynced_mining.to_string());
    add("txindex", cfg.tx_index.to_string());
    add("droptxindex", cfg.drop_tx_index.to_string());
    add("noexistsaddrindex", cfg.no_exists_addr_index.to_string());
    add(
        "dropexistsaddrindex",
        cfg.drop_exists_addr_index.to_string(),
    );
    add("piperx", cfg.pipe_rx.to_string());
    add("pipetx", cfg.pipe_tx.to_string());
    add("lifetimeevents", cfg.lifetime_events.to_string());
    add("boundaddrevents", cfg.bound_addr_events.to_string());

    // Cooked values.
    add("cminfee", cfg.min_relay_tx_fee_atoms.to_string());
    add(
        "cminingaddrs",
        cfg.mining_addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(","),
    );
    add(
        "cwhitelists",
        cfg.whitelists
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(","),
    );
    for (key, info) in [
        ("cipv4", &cfg.ipv4_net_info),
        ("cipv6", &cfg.ipv6_net_info),
        ("conion", &cfg.onion_net_info),
    ] {
        add(
            key,
            format!(
                "{};{};{};{};{}",
                info.name,
                info.limited,
                info.reachable,
                info.proxy,
                info.proxy_randomize_credentials
            ),
        );
    }
    add(
        "cnet",
        format!("{};{}", cfg.params.params.name, cfg.params.rpc_port),
    );
    add("remaining", remaining.join(","));
    add(
        "levels",
        SUBSYSTEM_IDS
            .iter()
            .map(|id| format!("{id}={}", cfg.log_levels.0[id]))
            .collect::<Vec<_>>()
            .join(","),
    );

    kv.join("\u{1f}")
}
