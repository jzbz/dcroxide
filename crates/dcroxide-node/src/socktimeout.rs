// SPDX-License-Identifier: ISC
//! Setting read and write timeouts on whatever a stream is really
//! sitting on.
//!
//! Both the peer transport and the RPC listener need to bound how long a
//! single receive or send may take, and both are generic over the stream
//! so their tests can drive an in-memory buffer.  A plain `Read`/`Write`
//! bound cannot express "and also arm the socket's timeout", so this
//! trait carries that capability alongside them.
//!
//! It lives in its own module because it belongs to neither caller: it
//! is a socket concern, used by the transport (`transport.rs`) and the
//! RPC server (`rpcrun.rs`) alike.  Keeping it here also lets the peer
//! layer build without the RPC layer, which it could not when the trait
//! was declared inside `rpcrun.rs`.
//!
//! The implementations deliberately swallow the `set_*_timeout` result.
//! Failing to arm a timeout is not a reason to drop a connection that is
//! otherwise fine, and the deadline loops that use this
//! (`read_exact_by_deadline`, `write_all_by_deadline`) re-check the
//! wall clock themselves, so a stream whose timeout cannot be set still
//! terminates — it just blocks longer inside one syscall.

use std::net::TcpStream;
use std::time::Duration;

/// A stream whose underlying socket timeouts can be armed.
pub trait SocketTimeout {
    /// Set the read timeout on the underlying socket.
    fn set_socket_read_timeout(&self, timeout: Option<Duration>);

    /// Set the write timeout on the underlying socket.  Without one a
    /// peer or client that advertises a zero receive window parks the
    /// writing thread forever, which is the tail of every "attacker
    /// stops reading" scenario.
    ///
    /// This bounds a single `send(2)`, and the kernel restarts that
    /// timer whenever a send makes progress, so it is not on its own a
    /// bound on writing a whole message; see `write_all_by_deadline`,
    /// which re-arms it against one absolute deadline.
    fn set_socket_write_timeout(&self, timeout: Option<Duration>);
}

impl SocketTimeout for TcpStream {
    fn set_socket_read_timeout(&self, timeout: Option<Duration>) {
        let _ = self.set_read_timeout(timeout);
    }

    fn set_socket_write_timeout(&self, timeout: Option<Duration>) {
        let _ = self.set_write_timeout(timeout);
    }
}

/// In-memory streams have no socket timeout; tests frame messages over
/// cursors and pipes.
impl<T> SocketTimeout for std::io::Cursor<T> {
    fn set_socket_read_timeout(&self, _timeout: Option<Duration>) {}

    fn set_socket_write_timeout(&self, _timeout: Option<Duration>) {}
}

impl SocketTimeout for rustls::StreamOwned<rustls::ServerConnection, TcpStream> {
    fn set_socket_read_timeout(&self, timeout: Option<Duration>) {
        let _ = self.sock.set_read_timeout(timeout);
    }

    fn set_socket_write_timeout(&self, timeout: Option<Duration>) {
        let _ = self.sock.set_write_timeout(timeout);
    }
}
