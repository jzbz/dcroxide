// SPDX-License-Identifier: ISC
//! The server version handler against dcrd master 452c1a6c's
//! `serverPeer.OnVersion` (the callback dcrd 2.2 fires from inside
//! the handshake): the services update that precedes every rejection,
//! the old-protocol rejection, the mix-capable outbound preference
//! that now rejects (pre-2.2 it disconnected and deliberately
//! continued), the missing-services rejection, the accept paths, and
//! dcrd's exact rejection texts.  The address advertisement, getaddr
//! request, and good marking that v1's OnVersion carried moved to the
//! post-handshake add-peer admission and are exercised by the served
//! peer integration tests.

use dcroxide_addrmgr::{AddrManager, NetAddressType};
use dcroxide_node::server::{
    OnVersionFacts, VersionRejection, natf_supported, on_ver_ack, on_version,
    version_rejection_text, wire_to_addrmgr_net_address,
};
use dcroxide_wire::{
    MIX_VERSION, Message, MsgVersion, NetAddress, PROTOCOL_VERSION, REMOVE_REJECT_VERSION,
    ServiceFlag,
};

fn wire_addr(ip: &str, port: u16) -> NetAddress {
    let mut bytes = [0u8; 16];
    match ip.parse::<std::net::IpAddr>().unwrap() {
        std::net::IpAddr::V4(v4) => {
            bytes[10] = 0xff;
            bytes[11] = 0xff;
            bytes[12..16].copy_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => bytes.copy_from_slice(&v6.octets()),
    }
    NetAddress {
        timestamp: 1_700_000_000,
        services: ServiceFlag::NODE_NETWORK,
        ip: bytes,
        port,
    }
}

fn facts(inbound: bool, sim_or_reg: bool, target_outbound: u32) -> OnVersionFacts {
    OnVersionFacts {
        inbound,
        sim_or_reg_net: sim_or_reg,
        num_outbound: 0,
        num_mix_capable_outbound: 0,
        target_outbound,
        remote_na: wire_to_addrmgr_net_address(&wire_addr("52.91.77.2", 34567)),
    }
}

fn msg(pver: i32, services: ServiceFlag, disable_relay: bool) -> MsgVersion {
    MsgVersion {
        protocol_version: pver,
        services,
        timestamp: 1_700_000_000,
        addr_you: wire_addr("52.91.77.1", 9108),
        addr_me: wire_addr("52.91.77.2", 34567),
        nonce: 1,
        user_agent: "/dcrwire:1.0.0/dcrd:2.2.0(pre)/".to_string(),
        last_block: 0,
        disable_relay_tx: disable_relay,
    }
}

fn amgr(dir: &std::path::Path, seed_remote: bool) -> AddrManager {
    let mut amgr = AddrManager::new(dir);
    if seed_remote {
        let na = wire_to_addrmgr_net_address(&wire_addr("52.91.77.2", 34567));
        let src = wire_to_addrmgr_net_address(&wire_addr("8.8.8.8", 9108));
        amgr.add_addresses(&[na], &src);
    }
    amgr
}

#[test]
fn old_protocol_is_rejected_after_the_services_update() {
    let dir = tempfile::tempdir().unwrap();
    let mut mgr = amgr(dir.path(), true);
    let f = facts(false, false, 8);
    let m = msg(
        REMOVE_REJECT_VERSION as i32 - 1,
        ServiceFlag::NODE_NETWORK,
        false,
    );
    let out = on_version(
        &mut mgr,
        &f,
        m.protocol_version,
        m.services,
        m.disable_relay_tx,
    );
    // The services update runs before the rejection (dcrd's NOTE on
    // keeping the manager updated for not-yet-upgraded nodes).
    assert!(out.set_services);
    assert_eq!(out.rejected, Some(VersionRejection::OldProtocol));
    assert_eq!(
        version_rejection_text(&f, &m, VersionRejection::OldProtocol),
        format!(
            "rejecting protocol version {} prior to the required version {}",
            REMOVE_REJECT_VERSION as i32 - 1,
            REMOVE_REJECT_VERSION
        ),
    );
}

#[test]
fn a_non_mix_capable_outbound_peer_is_rejected_when_more_are_wanted() {
    let dir = tempfile::tempdir().unwrap();
    let mut mgr = amgr(dir.path(), true);
    // target 3 caps the wanted mix-capable count at 3; with no
    // outbound peers at all, 0 + 3 >= 3 forces the preference.
    let f = facts(false, false, 3);
    let m = msg(MIX_VERSION as i32 - 1, ServiceFlag::NODE_NETWORK, false);
    let out = on_version(
        &mut mgr,
        &f,
        m.protocol_version,
        m.services,
        m.disable_relay_tx,
    );
    // dcrd 2.2 rejects here; pre-2.2 disconnected without rejecting
    // and continued to mark the address good.
    assert_eq!(out.rejected, Some(VersionRejection::MixCapableWanted));
    assert_eq!(
        version_rejection_text(&f, &m, VersionRejection::MixCapableWanted),
        format!(
            "rejecting outbound peer with protocol version {} in favor of a \
             peer with minimum version {} (have: 0, target: 3)",
            MIX_VERSION as i32 - 1,
            MIX_VERSION
        ),
    );
}

#[test]
fn an_outbound_peer_without_full_node_services_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut mgr = amgr(dir.path(), false);
    let f = facts(false, false, 8);
    let m = msg(PROTOCOL_VERSION as i32, ServiceFlag(0), false);
    let out = on_version(
        &mut mgr,
        &f,
        m.protocol_version,
        m.services,
        m.disable_relay_tx,
    );
    assert_eq!(out.rejected, Some(VersionRejection::MissingServices));
    assert_eq!(
        version_rejection_text(&f, &m, VersionRejection::MissingServices),
        "rejecting peer with services 0x0 due to not providing desired \
         services SFNodeNetwork",
    );
}

#[test]
fn accepted_outbound_and_inbound_peers_gate_the_services_update() {
    let dir = tempfile::tempdir().unwrap();

    // Outbound: the manager learns the advertised services and the
    // relay preference is carried through.
    let mut mgr = amgr(dir.path(), true);
    let f = facts(false, false, 8);
    let out = on_version(
        &mut mgr,
        &f,
        PROTOCOL_VERSION as i32,
        ServiceFlag::NODE_NETWORK,
        true,
    );
    assert!(out.set_services);
    assert_eq!(out.rejected, None);
    assert!(out.disable_relay_tx);

    // Inbound: no services update (malicious-behavior prevention).
    let out = on_version(
        &mut mgr,
        &facts(true, false, 8),
        PROTOCOL_VERSION as i32,
        ServiceFlag::NODE_NETWORK,
        false,
    );
    assert!(!out.set_services);
    assert_eq!(out.rejected, None);
    assert!(!out.disable_relay_tx);

    // Simulation and regression networks skip it entirely.
    let out = on_version(
        &mut mgr,
        &facts(false, true, 8),
        PROTOCOL_VERSION as i32,
        ServiceFlag::NODE_NETWORK,
        false,
    );
    assert!(!out.set_services);
    assert_eq!(out.rejected, None);
}

#[test]
fn the_type_filter_and_sendheaders_follow_the_negotiated_version() {
    // Below the addrv2 version only the legacy types pass; from it on
    // Tor v3 joins (dcrd `natfSupported`).
    let v1 = natf_supported(PROTOCOL_VERSION - 1);
    assert!(v1(NetAddressType::IPv4) && v1(NetAddressType::IPv6));
    assert!(!v1(NetAddressType::TorV3));
    let v2 = natf_supported(PROTOCOL_VERSION);
    assert!(v2(NetAddressType::IPv4) && v2(NetAddressType::IPv6));
    assert!(v2(NetAddressType::TorV3));

    // The post-handshake header-announcement request (dcrd
    // `serverPeer.Run`).
    assert_eq!(on_ver_ack(), Message::SendHeaders);
}
