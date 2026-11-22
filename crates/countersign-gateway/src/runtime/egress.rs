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
    let mut head = Vec::with_capacity(128);
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HEAD {
            return Err(invalid("egress proxy answer exceeds the limit"));
        }
        // One byte at a time, so no byte of the tunnel is consumed.
        head.push(stream.read_u8().await?);
    }
    match status(&head) {
        Some(code) if (200..300).contains(&code) => Ok(stream),
        Some(code) => Err(ProxyAnswer(code).into()),
        None => Err(invalid("egress proxy gave no HTTP answer")),
    }
}

fn status(head: &[u8]) -> Option<u16> {
    let line = head.split(|&b| b == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?.strip_suffix('\r')?;
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
