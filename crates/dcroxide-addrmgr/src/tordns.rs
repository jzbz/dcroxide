// SPDX-License-Identifier: ISC
//! Tor DNS resolution via a SOCKS proxy (dcrd addrmgr `tordns.go`;
//! relocated from connmgr's `tor.go` in dcrd 2.2 with the error
//! constructors switched to the addrmgr kinds).

use crate::{AddrError, ErrorKind, make_error};

const TOR_GENERAL_ERROR: u8 = 0x01;
const TOR_NOT_ALLOWED: u8 = 0x02;
const TOR_NET_UNREACHABLE: u8 = 0x03;
const TOR_HOST_UNREACHABLE: u8 = 0x04;
const TOR_CONNECTION_REFUSED: u8 = 0x05;
const TOR_TTL_EXPIRED: u8 = 0x06;
const TOR_CMD_NOT_SUPPORTED: u8 = 0x07;
const TOR_ADDR_NOT_SUPPORTED: u8 = 0x08;

const TOR_ATYPE_IPV4: u8 = 1;
const TOR_ATYPE_DOMAIN_NAME: u8 = 3;
const TOR_ATYPE_IPV6: u8 = 4;

const TOR_CMD_RESOLVE: u8 = 240;

/// The error for a SOCKS status byte (dcrd `torStatusErrors`).
fn tor_status_error(status: u8) -> Option<AddrError> {
    let (kind, desc) = match status {
        TOR_GENERAL_ERROR => (ErrorKind::TorGeneralError, "tor general error"),
        TOR_NOT_ALLOWED => (ErrorKind::TorNotAllowed, "tor not allowed"),
        TOR_NET_UNREACHABLE => (ErrorKind::TorNetUnreachable, "tor network is unreachable"),
        TOR_HOST_UNREACHABLE => (ErrorKind::TorHostUnreachable, "tor host is unreachable"),
        TOR_CONNECTION_REFUSED => (ErrorKind::TorConnectionRefused, "tor connection refused"),
        TOR_TTL_EXPIRED => (ErrorKind::TorTTLExpired, "tor TTL expired"),
        TOR_CMD_NOT_SUPPORTED => (ErrorKind::TorCmdNotSupported, "tor command not supported"),
        TOR_ADDR_NOT_SUPPORTED => (
            ErrorKind::TorAddrNotSupported,
            "tor address type not supported",
        ),
        _ => return None,
    };
    Some(make_error(kind, desc))
}

/// The transport used to talk to the SOCKS proxy.  The daemon
/// supplies a TCP connection; tests supply scripted byte streams.
/// `read` fills at most `buf.len()` bytes and returns how many were
/// filled, mirroring Go's `net.Conn` semantics.
pub trait TorTransport {
    /// Write the whole buffer.
    fn write(&mut self, data: &[u8]) -> Result<(), AddrError>;
    /// Read up to `buf.len()` bytes.
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, AddrError>;
}

/// Resolve DNS for a host via the passed SOCKS proxy transport (dcrd
/// `TorLookupIP`).  The returned addresses carry the exact byte forms
/// Go produces: a 16-byte IPv4-mapped address for the IPv4 answer
/// type, and the raw reply bytes for the IPv6 answer type (whose
/// length dcrd does not validate beyond a minimum).
pub fn tor_lookup_ip<T: TorTransport>(host: &str, conn: &mut T) -> Result<Vec<Vec<u8>>, AddrError> {
    conn.write(&[0x05, 0x01, 0x00])?;

    let mut buf2 = [0u8; 2];
    // Mirrors Go, which ignores the number of bytes read.
    conn.read(&mut buf2)?;
    if buf2[0] != 0x05 {
        return Err(make_error(
            ErrorKind::TorInvalidProxyResponse,
            "invalid SOCKS proxy version",
        ));
    }
    if buf2[1] != 0x00 {
        return Err(make_error(
            ErrorKind::TorUnrecognizedAuthMethod,
            "invalid proxy authentication method",
        ));
    }

    // Go allocates 7+len(host) zero-filled bytes and writes one port
    // byte explicitly, so the request carries two zero port bytes.
    let mut req = vec![0u8; 7usize.saturating_add(host.len())];
    req[0] = 5; // socks protocol version
    req[1] = TOR_CMD_RESOLVE;
    req[2] = 0; // reserved
    req[3] = TOR_ATYPE_DOMAIN_NAME;
    req[4] = host.len() as u8;
    req[5..5usize.saturating_add(host.len())].copy_from_slice(host.as_bytes());
    req[5usize.saturating_add(host.len())] = 0; // Port 0
    conn.write(&req)?;

    let mut buf4 = [0u8; 4];
    conn.read(&mut buf4)?;
    if buf4[0] != 5 {
        return Err(make_error(
            ErrorKind::TorInvalidProxyResponse,
            "invalid SOCKS proxy version",
        ));
    }
    if buf4[1] != 0 {
        return Err(tor_status_error(buf4[1]).unwrap_or_else(|| {
            make_error(
                ErrorKind::TorInvalidProxyResponse,
                "invalid SOCKS proxy version",
            )
        }));
    }
    if buf4[3] != TOR_ATYPE_IPV4 && buf4[3] != TOR_ATYPE_IPV6 {
        return Err(make_error(
            ErrorKind::TorInvalidAddressResponse,
            "invalid IP address",
        ));
    }

    let mut reply = [0u8; 32 + 2];
    let reply_len = conn.read(&mut reply)?;

    let addr: Vec<u8> = match buf4[3] {
        TOR_ATYPE_IPV4 => {
            if reply_len != 4 + 2 {
                return Err(make_error(
                    ErrorKind::TorInvalidAddressResponse,
                    "invalid IPV4 address",
                ));
            }
            // Go builds the address through net.IPv4, which yields the
            // 16-byte IPv4-mapped form.
            let mut ip = [0u8; 16];
            ip[10] = 0xff;
            ip[11] = 0xff;
            ip[12..16].copy_from_slice(&reply[0..4]);
            ip.to_vec()
        }
        TOR_ATYPE_IPV6 => {
            if reply_len <= 4 + 2 {
                return Err(make_error(
                    ErrorKind::TorInvalidAddressResponse,
                    "invalid IPV6 address",
                ));
            }
            reply[..reply_len.saturating_sub(2)].to_vec()
        }
        _ => {
            return Err(make_error(
                ErrorKind::TorInvalidAddressResponse,
                "unknown address type",
            ));
        }
    };

    Ok(vec![addr])
}
