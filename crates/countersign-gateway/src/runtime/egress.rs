//! The proxied leg to a site: a plain-text `CONNECT` through the egress proxy
//! (ADR 0003). The egress proxy resolves the site's name and carries its
//! address policy; the Gateway resolves only the proxy.

use std::{error::Error, fmt, net::SocketAddr};

use countersign_protocol::Origin;
use ipnet::IpNet;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use super::{Result, config::EgressProxy, invalid};

/// The most the Gateway reads of the egress proxy's answer before the tunnel.
const MAX_HEAD: usize = 8 * 1024;

/// The egress proxy answered the `CONNECT` with something other than 2xx.
#[derive(Debug)]
pub struct ProxyAnswer(pub u16);

impl fmt::Display for ProxyAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the egress proxy answered {}", self.0)
    }
}

impl Error for ProxyAnswer {}

/// The `Countersign-Error` value for a proxied leg that failed (ADR 0003).
pub fn error_value(error: &(dyn Error + Send + Sync + 'static)) -> &'static str {
    match error.downcast_ref::<ProxyAnswer>() {
        Some(ProxyAnswer(400..=499)) => "proxy_denied",
        // As a direct route reports a site it cannot reach.
        Some(ProxyAnswer(500..=599)) => "upstream_failure",
        // Unreachable, resolved only inside `denied_networks`, out of time
        // (the deadline covers the whole leg), or no usable HTTP answer.
        _ => "proxy_unavailable",
    }
}

/// Opens a tunnel to `origin` through the egress proxy. On success the stream
/// carries the site's bytes from its first byte: the Gateway reads the
/// proxy's answer no further than the end of its head.
pub async fn tunnel(proxy: &EgressProxy, origin: &Origin, denied: &[IpNet]) -> Result<TcpStream> {
    // Resolved on every connection, so a load balancer may change addresses.
    // Only `denied_networks` applies: the proxy normally sits on a private one.
    let addresses = tokio::net::lookup_host((proxy.host.as_str(), proxy.port))
        .await?
        .filter(|address| {
            let ip = address.ip().to_canonical();
            !denied.iter().any(|block| block.contains(&ip))
        })
        .collect::<Vec<SocketAddr>>();
    if addresses.is_empty() {
        return Err(invalid("egress proxy resolved to no allowed addresses"));
    }
    let mut stream = TcpStream::connect(&addresses[..]).await?;
    stream
        .write_all(format!("CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n").as_bytes())
        .await?;
    match answer(&mut stream).await? {
        200..=299 => Ok(stream),
        code => Err(ProxyAnswer(code).into()),
    }
}

/// Reads the egress proxy's answer to the `CONNECT` and returns its status
/// code. It reads past the status line only for a 2xx answer, up to the head's
/// end, and gives up as soon as the bytes cannot be an HTTP answer: a proxy
/// that keeps the connection open after any other answer gets no wait.
async fn answer(stream: &mut TcpStream) -> Result<u16> {
    const VERSION: &[u8] = b"HTTP/1.";
    let not_http = || invalid("egress proxy gave no HTTP answer");
    let mut line = Vec::with_capacity(64);
    let mut code = None;
    for _ in 0..MAX_HEAD {
        // One byte at a time, so no byte of the tunnel is consumed.
        let byte = stream.read_u8().await?;
        if byte != b'\n' {
            line.push(byte);
            if code.is_none() && !line.starts_with(VERSION) && !VERSION.starts_with(&line) {
                return Err(not_http());
            }
            continue;
        }
        // A line ends at LF, with or without CR before it (RFC 9112, 2.2).
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        match code {
            None => {
                let status = status(&line).ok_or_else(not_http)?;
                if !(200..300).contains(&status) {
                    return Ok(status);
                }
                code = Some(status);
            }
            Some(status) if line.is_empty() => return Ok(status),
            Some(_) => {}
        }
        line.clear();
    }
    Err(invalid("egress proxy answer exceeds the limit"))
}

/// The status code of a status line, given without its line end.
fn status(line: &[u8]) -> Option<u16> {
    let line = std::str::from_utf8(line).ok()?;
    let mut parts = line.splitn(3, ' ');
    if !matches!(parts.next()?, "HTTP/1.1" | "HTTP/1.0") {
        return None;
    }
    let code = parts.next()?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    code.parse().ok()
}
