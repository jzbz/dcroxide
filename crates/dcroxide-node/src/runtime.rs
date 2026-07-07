// SPDX-License-Identifier: ISC
//! The threaded peer-to-peer server runtime — the OS-threads-and-channels
//! translation of the backbone of dcrd `server.go`'s `Run` and
//! `peerHandler` goroutines.
//!
//! This first slice binds the configured listeners and accepts inbound
//! connections on a dedicated thread per listener, coordinating a
//! graceful shutdown by signalling those threads and joining them.  The
//! connection manager (outbound dialing and seeding), the peer version
//! handshake, the per-peer input and output loops, the sync manager,
//! and the RPC server arrive with later pieces and plug into this same
//! shutdown coordination.

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

/// The interval the accept loops wait between polling for shutdown when
/// no connection is pending.
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// A handler invoked for each accepted inbound connection (dcrd
/// `server.inboundPeerConnected`).  It runs on the listener's accept
/// thread and must not block for long; later pieces hand the connection
/// off to a dedicated peer thread.
pub type InboundHandler = Arc<dyn Fn(TcpStream, SocketAddr) + Send + Sync>;

/// Resolve a listener spec's bind address, expanding the wildcard host
/// to the family-appropriate any-address (dcrd relies on Go's
/// `net.Listen("tcp4"|"tcp6", ":port")` for this).
fn bind_address(net: &str, addr: &str) -> String {
    match addr.strip_prefix(':') {
        Some(port) if net == "tcp6" => format!("[::]:{port}"),
        Some(port) => format!("0.0.0.0:{port}"),
        None => addr.to_string(),
    }
}

/// Binds the parsed peer-to-peer listeners and accepts inbound
/// connections until shutdown.
pub struct ListenerRuntime {
    shutdown: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    bound: Vec<SocketAddr>,
}

impl ListenerRuntime {
    /// Bind each `(network, address)` listener spec (as produced by
    /// `parse_listeners`) and start accepting inbound connections,
    /// invoking `on_inbound` for each accepted connection.  A bind
    /// failure aborts startup and returns the error, matching dcrd's
    /// refusal to start when it cannot listen on a requested address.
    pub fn start(
        specs: &[(&str, String)],
        on_inbound: InboundHandler,
    ) -> io::Result<ListenerRuntime> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::with_capacity(specs.len());
        let mut bound = Vec::with_capacity(specs.len());

        for (net, addr) in specs {
            let listener = TcpListener::bind(bind_address(net, addr))?;
            // Non-blocking accept so the loop can observe shutdown
            // promptly without a separate wakeup connection.
            listener.set_nonblocking(true)?;
            bound.push(listener.local_addr()?);

            let shutdown = Arc::clone(&shutdown);
            let handler = Arc::clone(&on_inbound);
            threads.push(std::thread::spawn(move || {
                accept_loop(&listener, &shutdown, &handler);
            }));
        }

        Ok(ListenerRuntime {
            shutdown,
            threads,
            bound,
        })
    }

    /// The addresses the runtime is actually listening on (resolved from
    /// the requested specs, so an ephemeral `:0` port is reported as the
    /// assigned port).
    pub fn bound_addrs(&self) -> &[SocketAddr] {
        &self.bound
    }

    /// Signal the accept threads to stop and join them (dcrd's server
    /// shutdown waiting on its wait group).
    pub fn shutdown(self) {
        self.shutdown.store(true, Ordering::SeqCst);
        for thread in self.threads {
            let _ = thread.join();
        }
    }
}

/// Accept inbound connections on the listener until shutdown is
/// signalled, handing each to the handler.
fn accept_loop(listener: &TcpListener, shutdown: &AtomicBool, handler: &InboundHandler) {
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, addr)) => handler(stream, addr),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL_INTERVAL);
            }
            // A hard listener error ends the accept loop; the runtime's
            // other listeners and the shutdown path are unaffected.
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_wildcard_bind_addresses() {
        assert_eq!(bind_address("tcp4", ":9108"), "0.0.0.0:9108");
        assert_eq!(bind_address("tcp6", ":9108"), "[::]:9108");
        assert_eq!(bind_address("tcp4", "127.0.0.1:9108"), "127.0.0.1:9108");
        assert_eq!(bind_address("tcp6", "[::1]:9108"), "[::1]:9108");
    }
}
