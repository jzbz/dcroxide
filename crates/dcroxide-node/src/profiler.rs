// SPDX-License-Identifier: ISC
//! The profile server manager behind the `startprofiler` and
//! `stopprofiler` RPCs (dcrd's `profileServer`, `profiler.go`).
//!
//! dcrd's profile server serves the Go runtime's `net/http/pprof`
//! endpoints, which have no counterpart here, so it is not ported
//! (PARITY.md, the daemon row).  What is ported is every step of dcrd's
//! `Start` before its first `net.Listen`, in dcrd's order, so that an
//! address dcrd refuses is refused with dcrd's text:
//!
//! 1. a bare port gains the host 127.0.0.1 (`portToLocalHostAddr`);
//! 2. the address must be `host:port`, the port from 1024 through 65535
//!    (`validateProfileAddr`);
//! 3. a host that names an interface stands for every address of that
//!    interface (`normalizeAddresses` with `normalizeInterfaceAddrs`);
//! 4. without the flag to allow it, every address must read as an IPv4 or
//!    IPv6 loopback address under `netip.ParseAddrPort`;
//! 5. every host must be an IP address, or empty (`parseListeners`).
//!
//! Where dcrd would then bind a listener for each address and serve,
//! [`ProfileServer`] binds nothing and refuses with [`NOT_PORTED`], which
//! the handler reports as dcrd reports a failed start.  So no profile
//! server ever runs, [`RpcProfilerManager::listeners`] is always empty,
//! and `stopprofiler` always answers dcrd's "profile server is not
//! started".  The daemon's start for `--profile`
//! ([`ProfileServer::start_configured`]) makes the same checks with
//! addresses that are not loopback allowed, as dcrd's does, and goes on
//! where dcrd would serve: so a `--profile` dcrd refuses ends the daemon
//! as it ends dcrd, and one it accepts starts nothing.
//!
//! One address passes every check and leaves dcrd nothing to bind: a host
//! that names an interface with no address normalizes to no address at
//! all.  dcrd then records a server that has no listener, the handler
//! answers that it started without active listeners, and every later
//! `Start` returns at once because a server is recorded, so the profile
//! server answers that way until the `Stop` dcrd defers runs at shutdown
//! (QUIRKS.md QK-0032), or from startup when `--profile` names such an
//! interface.  That state binds nothing either, and is reproduced.

use std::sync::{Arc, Mutex, PoisonError};

use dcroxide_rpc::server::RpcProfilerManager;

use crate::config::{
    IfaceAddrs, NORMALIZE_INTERFACE_ADDRS, normalize_addresses, parse_addr_netip, parse_listeners,
    port_to_local_host_addr, validate_profile_addr,
};
use crate::gostd::go_quote;

/// The reason an address dcrd would listen on is refused; the handler
/// reports it as `unable to start profile server: ` and this text, under
/// dcrd's invalid parameter code, as it reports a failed bind.
pub const NOT_PORTED: &str = "the profile server is not part of this port of dcrd";

/// A network interface lookup by name, for the profile server's address
/// normalization.
pub type InterfaceByName = Box<dyn Fn(&str) -> Option<IfaceAddrs> + Send + Sync>;

/// The profile server manager (dcrd `profileServer`): the checks dcrd's
/// `Start` makes before it binds, and no server (see the module
/// documentation).  Clones share one state, as the daemon's one
/// `profileServer` is shared by the RPC server and `dcrdMain`'s deferred
/// `Stop`.
#[derive(Clone)]
pub struct ProfileServer {
    inner: Arc<ProfileState>,
}

/// The state behind every clone of a [`ProfileServer`].
struct ProfileState {
    /// Whether dcrd's `server` field would be set: only after a start
    /// whose address normalized to no address at all, since every other
    /// start that passes the checks is refused before dcrd would set it.
    /// The mutex is dcrd's `mtx`, held across a start and a stop.
    server: Mutex<bool>,
    /// The interface lookup of the address normalization.
    interface_by_name: InterfaceByName,
}

impl ProfileServer {
    /// A manager whose address normalization looks interface names up
    /// with `interface_by_name`.
    pub fn new(interface_by_name: InterfaceByName) -> Self {
        ProfileServer {
            inner: Arc::new(ProfileState {
                server: Mutex::new(false),
                interface_by_name,
            }),
        }
    }

    /// The daemon's manager, which looks interface names up on the host
    /// ([`crate::rpcrun::system_interface_by_name`]).
    pub fn system() -> Self {
        Self::new(Box::new(crate::rpcrun::system_interface_by_name))
    }

    /// The start `dcrdMain` makes for `--profile`, with addresses that are
    /// not loopback allowed (`dcrd.go:118-126`): `Ok` where dcrd's start
    /// succeeds, though an address dcrd would listen on starts nothing
    /// here, and dcrd's error where its `Start` refuses the address before
    /// it binds, which dcrd logs and exits on.  An interface with no
    /// address records dcrd's server with no listener (QUIRKS.md QK-0032).
    pub fn start_configured(&self, listen_addr: &str) -> Result<(), String> {
        const ALLOW_NON_LOOPBACK: bool = true;
        self.start_checked(listen_addr, ALLOW_NON_LOOPBACK)
            .map(|_| ())
    }

    /// dcrd's `Start` up to its first `net.Listen`: dcrd's error for an
    /// address it refuses, and otherwise whether dcrd would bind and
    /// serve.
    fn start_checked(
        &self,
        listen_addr: &str,
        allow_non_loopback: bool,
    ) -> Result<Started, String> {
        let mut server = self
            .inner
            .server
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        // Nothing to do when the server is already running.
        if *server {
            return Ok(Started::Recorded);
        }

        // Potentially convert a raw port to an IPv4 localhost address (aka
        // prepend 127.0.0.1).
        let listen_addr = port_to_local_host_addr(listen_addr);

        // Ensure the provided address is a valid hostname and port with a
        // port that is in range.
        validate_profile_addr(&listen_addr)?;

        // Resolve interface names to associated IP addresses and remove
        // duplicates.  No default port is specified since a port is
        // guaranteed to be present per the previous validation.
        let listen_addrs = normalize_addresses(
            &[listen_addr],
            "",
            NORMALIZE_INTERFACE_ADDRS,
            &*self.inner.interface_by_name,
        );

        // Reject non loopback addresses when requested.
        if !allow_non_loopback {
            for addr in &listen_addrs {
                if !is_loopback_addr_port(addr) {
                    return Err(format!(
                        "not permitted to listen on non loopback address {} without setting \
                         the flag to allow it",
                        go_quote(addr)
                    ));
                }
            }
        }

        // Expand the provided listen address into relevant IPv4 and IPv6
        // addresses to listen on with TCP.
        let net_addrs = parse_listeners(&listen_addrs)?;

        // dcrd binds a listener for each address here and serves the
        // profiling endpoints on them, which this port does not do.  With
        // no address there is nothing to bind, and dcrd records a server
        // with no listener.
        if !net_addrs.is_empty() {
            return Ok(Started::WouldServe);
        }
        *server = true;
        Ok(Started::Recorded)
    }
}

/// What a start that passes dcrd's checks leaves.
enum Started {
    /// A server is recorded, as dcrd records one: it was already, or the
    /// address normalized to no address, so there was nothing to bind.
    Recorded,
    /// dcrd would bind a listener for each address and serve; nothing is
    /// bound.
    WouldServe,
}

impl RpcProfilerManager for ProfileServer {
    fn start(&self, listen_addr: &str, allow_non_loopback: bool) -> Result<(), String> {
        match self.start_checked(listen_addr, allow_non_loopback)? {
            Started::Recorded => Ok(()),
            Started::WouldServe => Err(NOT_PORTED.to_string()),
        }
    }

    fn stop(&self) -> Result<(), String> {
        let mut server = self
            .inner
            .server
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        // Nothing to do when the server is not running.
        if !*server {
            return Ok(());
        }

        // A server with no listener closes without error.
        *server = false;
        crate::logging::info("DCRD", "Profiling server stopped");
        Ok(())
    }

    fn listeners(&self) -> Vec<String> {
        // No listener is ever bound.
        Vec::new()
    }
}

/// Whether `netip.ParseAddrPort` accepts the address and its address is
/// an IPv4 or IPv6 loopback address, dcrd's `addr.IsValid() &&
/// addr.Addr().IsLoopback()` (`net/netip/netip.go`: `ParseAddrPort`,
/// `splitAddrPort` and `IsLoopback`, Go 1.27).
fn is_loopback_addr_port(s: &str) -> bool {
    // The port follows the last colon, and neither half may be empty.
    let Some((ip, port)) = s.rsplit_once(':') else {
        return false;
    };
    if ip.is_empty() || port.is_empty() {
        return false;
    }
    // Brackets hold an IPv6 address and nothing else.
    let (ip, bracketed) = match ip.strip_prefix('[') {
        Some(rest) => match rest.strip_suffix(']') {
            Some(inner) => (inner, true),
            None => return false,
        },
        None => (ip, false),
    };
    // `strconv.ParseUint(port, 10, 16)`: decimal digits alone, no sign.
    if !port.bytes().all(|b| b.is_ascii_digit()) || port.parse::<u16>().is_err() {
        return false;
    }
    let Some(addr) = parse_addr_netip(ip) else {
        return false;
    };
    match addr.as_slice() {
        [first, _, _, _] => !bracketed && *first == 127,
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, first, _, _, _] => bracketed && *first == 127,
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] => bracketed,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A manager over a fixed interface table.
    fn over(table: Vec<(&'static str, IfaceAddrs)>) -> ProfileServer {
        ProfileServer::new(Box::new(move |name| {
            table
                .iter()
                .find(|(n, _)| *n == name)
                .map(|(_, iface)| iface.clone())
        }))
    }

    fn iface(index: u32, addrs: &[&str]) -> IfaceAddrs {
        IfaceAddrs {
            index,
            addrs: addrs.iter().map(|a| a.parse().expect("an IP")).collect(),
        }
    }

    /// `netip.ParseAddrPort` and `IsLoopback` over the shapes the
    /// normalized addresses take: an IPv4 address only bare, an IPv6
    /// address only in brackets (an IPv4-mapped one included, which
    /// `IsLoopback` unmaps), any zone, and a port of decimal digits that
    /// fits sixteen bits.
    #[test]
    fn the_loopback_check_reads_addresses_as_netip_does() {
        let loopback = [
            "127.0.0.1:6060",
            "127.255.255.254:1024",
            "[::1]:6060",
            "[::1%lo]:6060",
            "[0:0:0:0:0:0:0:1]:6060",
            "[::ffff:127.0.0.1]:6060",
            "127.0.0.1:0",
            "127.0.0.1:65535",
            "127.0.0.1:0006060",
        ];
        for addr in loopback {
            assert!(is_loopback_addr_port(addr), "{addr}");
        }
        let refused = [
            "",
            ":6060",
            "127.0.0.1",
            "127.0.0.1:",
            "127.0.0.1:+6060",
            "127.0.0.1:65536",
            "127.0.0.1:6_060",
            "[127.0.0.1]:6060",
            "::1:6060",
            "[::1:6060",
            "[::1%]:6060",
            "127.0.0.1%lo:6060",
            "0127.0.0.1:6060",
            "127.1:6060",
            "localhost:6060",
            "128.0.0.1:6060",
            "[::]:6060",
            "[::2]:6060",
            "[::ffff:128.0.0.1]:6060",
            "[fe80::1%2]:6060",
        ];
        for addr in refused {
            assert!(!is_loopback_addr_port(addr), "{addr}");
        }
    }

    /// An interface name stands for every address of the interface, the
    /// IPv6 link-local ones zoned by its index, and each must be loopback
    /// without the flag: the error names the first that is not.
    #[test]
    fn an_interface_name_is_checked_address_by_address() {
        let server = over(vec![
            ("lo", iface(1, &["127.0.0.1", "::1"])),
            ("eth0", iface(2, &["192.0.2.10", "fe80::1"])),
            ("tun0", iface(7, &["fe80::7", "192.0.2.11"])),
        ]);
        let non_loopback = |addr: &str| {
            Err(format!(
                "not permitted to listen on non loopback address \"{addr}\" without setting \
                 the flag to allow it"
            ))
        };
        assert_eq!(server.start("lo:6060", false), Err(NOT_PORTED.to_string()));
        assert_eq!(server.start("lo:6060", true), Err(NOT_PORTED.to_string()));
        assert_eq!(
            server.start("eth0:6060", false),
            non_loopback("192.0.2.10:6060")
        );
        assert_eq!(
            server.start("tun0:6060", false),
            non_loopback("[fe80::7%7]:6060")
        );
        assert_eq!(server.start("eth0:6060", true), Err(NOT_PORTED.to_string()));
        // A bare port is never an interface name: it gains 127.0.0.1.
        assert_eq!(server.start("6060", false), Err(NOT_PORTED.to_string()));
        assert!(server.listeners().is_empty());
    }

    /// The daemon's `--profile` start allows addresses that are not
    /// loopback, as dcrd's does: dcrd's refusals come back for the daemon
    /// to log and exit on, an address dcrd would listen on starts nothing
    /// and leaves `startprofiler` its checks, and an interface with no
    /// address records the server with no listener from startup.
    #[test]
    fn the_profile_flag_start_allows_addresses_that_are_not_loopback() {
        let server = over(vec![
            ("eth0", iface(2, &["192.0.2.10"])),
            ("eth1", iface(3, &[])),
        ]);
        for (addr, err) in [
            ("localhost:6060", "'localhost' is not a valid IP address"),
            (
                "127.0.0.1%lo:6060",
                "'127.0.0.1%lo' is not a valid IP address",
            ),
            ("bogus", "address bogus: missing port in address"),
        ] {
            assert_eq!(
                server.start_configured(addr),
                Err(err.to_string()),
                "{addr}"
            );
        }
        for addr in [
            "192.0.2.1:6060",
            "eth0:6060",
            ":6060",
            "[::]:6060",
            "127.0.0.1:6060",
            "6060",
        ] {
            assert_eq!(server.start_configured(addr), Ok(()), "{addr}");
        }
        assert_eq!(
            server.start("192.0.2.1:6060", false),
            Err(
                "not permitted to listen on non loopback address \"192.0.2.1:6060\" without \
                 setting the flag to allow it"
                    .to_string()
            )
        );

        assert_eq!(server.start_configured("eth1:6060"), Ok(()));
        assert!(server.listeners().is_empty());
        assert_eq!(server.start("bogus", false), Ok(()));
        assert_eq!(server.stop(), Ok(()));
        assert_eq!(
            server.start("bogus", false),
            Err("address bogus: missing port in address".to_string())
        );
    }

    /// An interface with no address leaves dcrd's server recorded with no
    /// listener: the start succeeds, and every later start does too
    /// without a check, whatever its address, until a stop clears it.
    #[test]
    fn an_interface_with_no_address_records_a_server_with_no_listener() {
        let server = over(vec![("eth1", iface(3, &[]))]);
        assert_eq!(server.stop(), Ok(()));
        assert_eq!(server.start("eth1:6060", false), Ok(()));
        assert!(server.listeners().is_empty());
        assert_eq!(server.start("bogus", false), Ok(()));
        assert_eq!(server.start("127.0.0.1:6060", false), Ok(()));

        // A clone shares the state, as the daemon's deferred stop does.
        let clone = server.clone();
        assert_eq!(clone.stop(), Ok(()));
        assert_eq!(
            server.start("bogus", false),
            Err("address bogus: missing port in address".to_string())
        );
        assert_eq!(server.start("eth1:6060", true), Ok(()));
        assert_eq!(server.stop(), Ok(()));
        assert_eq!(server.stop(), Ok(()));
    }
}
