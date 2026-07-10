// SPDX-License-Identifier: ISC
//! The RPC listener — the daemon front-end serving the ported JSON-RPC
//! machinery over HTTP/1.1 (dcrd `rpcserver.Server`'s HTTP surface).
//!
//! Each accepted connection runs on its own thread: the request line,
//! headers, and body are parsed with dcrd's authenticated read limit,
//! the Authorization header runs through the ported `checkAuth`, and
//! the body flows through the ported `jsonRPCRead` pipeline
//! (`process_body`), holding the shared server for the duration of the
//! request — the OS-threads translation of dcrd's per-client handler
//! with its internal locking.  A handler that reaches a seam the
//! daemon has not wired yet panics on the connection thread; the panic
//! is caught and answered with an internal error so the server
//! survives.
//!
//! This slice serves plain HTTP for the localhost `--notls`
//! configuration; the TLS listener over the generated `rpc.cert` pair
//! and the websocket upgrade arrive with later pieces.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use dcroxide_blockchain::process::Chain;
use dcroxide_chainhash::Hash;
use dcroxide_rpc::server::{RpcBestState, RpcChain, Server};

/// The maximum number of bytes allowed for a request read from an
/// authenticated peer (dcrd `rpcReadLimitAuthenticated`).
const RPC_READ_LIMIT_AUTHENTICATED: usize = 1 << 23;

/// The interval the accept loop waits between polling for shutdown.
const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// The chain adapter answering the RPC handlers' queries over the
/// shared chain (a growing slice of the `RpcChain` seam; handlers
/// touching the rest answer with an internal error until their seams
/// are wired).
pub struct NodeRpcChain {
    chain: Arc<Mutex<Chain>>,
}

impl NodeRpcChain {
    /// Adapt the shared chain for the RPC handlers.
    pub fn new(chain: Arc<Mutex<Chain>>) -> NodeRpcChain {
        NodeRpcChain { chain }
    }
}

impl RpcChain for NodeRpcChain {
    fn best_snapshot(&mut self) -> RpcBestState {
        let chain = self.chain.lock().expect("chain mutex poisoned");
        let best = chain.best_snapshot();
        RpcBestState {
            hash: best.hash,
            prev_hash: best.prev_hash,
            height: best.height,
            bits: best.bits,
            next_stake_diff: best.next_stake_diff,
            total_subsidy: best.total_subsidy,
            block_size: best.block_size,
            num_txns: best.num_txns,
        }
    }

    fn best_header(&mut self) -> (Hash, i64) {
        self.chain
            .lock()
            .expect("chain mutex poisoned")
            .best_header()
    }
}

/// The running RPC listener; [`RpcListener::shutdown`] stops the accept
/// threads.
pub struct RpcListener {
    shutdown: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
    bound: Vec<SocketAddr>,
}

impl RpcListener {
    /// The addresses the listener is serving on.
    pub fn bound_addrs(&self) -> &[SocketAddr] {
        &self.bound
    }

    /// Signal the accept threads to stop and join them.
    pub fn shutdown(self) {
        self.shutdown.store(true, Ordering::SeqCst);
        for thread in self.threads {
            let _ = thread.join();
        }
    }
}

/// Bind the RPC listen addresses and serve JSON-RPC requests through
/// the shared server (dcrd's RPC listeners; this slice serves the
/// plain-HTTP `--notls` configuration).
pub fn start_rpc_listener(
    listeners: &[String],
    server: Arc<Mutex<Server<NodeRpcChain>>>,
) -> std::io::Result<RpcListener> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::with_capacity(listeners.len());
    let mut bound = Vec::with_capacity(listeners.len());

    for addr in listeners {
        let listener = TcpListener::bind(addr)?;
        listener.set_nonblocking(true)?;
        bound.push(listener.local_addr()?);

        let shutdown = Arc::clone(&shutdown);
        let server = Arc::clone(&server);
        threads.push(thread::spawn(move || {
            accept_loop(&listener, &shutdown, &server);
        }));
    }

    Ok(RpcListener {
        shutdown,
        threads,
        bound,
    })
}

/// Accept RPC connections until shutdown, serving each on its own
/// thread.
fn accept_loop(
    listener: &TcpListener,
    shutdown: &AtomicBool,
    server: &Arc<Mutex<Server<NodeRpcChain>>>,
) {
    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                if stream.set_nonblocking(false).is_ok() {
                    let server = Arc::clone(server);
                    thread::spawn(move || serve_rpc_connection(stream, &server));
                }
            }
            Err(_) => thread::sleep(ACCEPT_POLL_INTERVAL),
        }
    }
}

/// A parsed HTTP request: the Authorization header value and the body.
struct HttpRequest {
    authorization: Option<String>,
    body: String,
}

/// Read one HTTP/1.1 request from the stream (the minimal surface the
/// JSON-RPC endpoint needs: `POST /` with a `Content-Length` body,
/// capped at dcrd's authenticated read limit).
fn read_request(stream: &mut TcpStream) -> Result<HttpRequest, &'static str> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
    let mut reader = BufReader::new(stream);

    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .map_err(|_| "read failure")?;
    if !request_line.starts_with("POST ") {
        return Err("method not allowed");
    }

    let mut authorization = None;
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).map_err(|_| "read failure")?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            let value = value.trim();
            if name.eq_ignore_ascii_case("authorization") {
                authorization = Some(value.to_string());
            } else if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().map_err(|_| "bad content length")?;
            }
        }
    }
    if content_length > RPC_READ_LIMIT_AUTHENTICATED {
        return Err("request too large");
    }

    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).map_err(|_| "read failure")?;
    let body = String::from_utf8(body).map_err(|_| "invalid body")?;
    Ok(HttpRequest {
        authorization,
        body,
    })
}

/// Serve a single RPC connection: authenticate, process the body
/// through the ported pipeline, and answer (dcrd `jsonRPCRead` behind
/// the HTTP handler).
fn serve_rpc_connection(mut stream: TcpStream, server: &Arc<Mutex<Server<NodeRpcChain>>>) {
    let request = match read_request(&mut stream) {
        Ok(request) => request,
        Err(reason) => {
            let _ = write_response(&mut stream, "400 Bad Request", reason.as_bytes());
            return;
        }
    };

    // Authenticate (dcrd `checkAuth` with authentication required),
    // answering an auth failure with dcrd's 401 and realm.
    let auth = {
        let server = server
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        server.check_auth(request.authorization.as_deref(), true)
    };
    let (_, is_admin) = match auth {
        Ok(auth) => auth,
        Err(_) => {
            let _ = write_unauthorized(&mut stream);
            return;
        }
    };

    // Process the request body, holding the server for the duration
    // like dcrd's internal locking.  A panic from a not-yet-wired seam
    // is caught and answered as an internal error; the lock recovers
    // from the poisoning so later requests keep working.
    let response = catch_unwind(AssertUnwindSafe(|| {
        let mut server = server
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        dcroxide_rpc::http::process_body(&mut server, &request.body, is_admin)
    }))
    .unwrap_or_else(|_| {
        br#"{"jsonrpc":"1.0","result":null,"error":{"code":-32603,"message":"internal error: the handler's daemon seam is not yet wired"},"id":null}"#
            .to_vec()
    });

    let _ = write_response(&mut stream, "200 OK", &response);
}

/// Write an HTTP response with dcrd's JSON content type.
fn write_response(stream: &mut TcpStream, status: &str, body: &[u8]) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Write dcrd's 401 with its authenticate realm (dcrd `jsonAuthFail`).
fn write_unauthorized(stream: &mut TcpStream) -> std::io::Result<()> {
    let body = b"401 Unauthorized.\n";
    let header = format!(
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"dcrd RPC\"\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}
