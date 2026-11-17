use super::{Result, invalid};
use bytes::Bytes;
use countersign_protocol::Origin;
use http_body_util::{BodyExt, Empty, combinators::UnsyncBoxBody};
use hyper::{
    Method, Request, Response, StatusCode, Uri, Version,
    body::Incoming,
    client::conn::{http1, http2},
    header::{self, HeaderValue},
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

type Body = UnsyncBoxBody<Bytes, hyper::Error>;

enum Sender {
    H1(Mutex<http1::SendRequest<Incoming>>),
    H2(http2::SendRequest<Incoming>),
}

fn forbidden<B>(req: &Request<B>, origin: &Origin) -> bool {
    if req.method() == Method::CONNECT
        || req.headers().contains_key(header::UPGRADE)
        || req
            .uri()
            .scheme_str()
            .is_some_and(|scheme| scheme != "https")
    {
        return true;
    }
    let mut hosts = req.headers().get_all(header::HOST).iter();
    let host = hosts.next();
    if hosts.next().is_some() {
        return true;
    }
    let authority = req.uri().authority();
    if host.is_none() && authority.is_none() {
        return true;
    }
    let same = |s: &str| Origin::parse(s).ok().as_ref() == Some(origin);
    if host.is_some_and(|h| !h.to_str().is_ok_and(same)) {
        return true;
    }
    authority.is_some_and(|a| !same(a.as_str()))
}

fn strip(headers: &mut hyper::HeaderMap) -> Result<()> {
    let mut nominated = Vec::new();
    for value in headers.get_all(header::CONNECTION) {
        for name in value.to_str()?.split(',').map(str::trim) {
            let name = header::HeaderName::from_bytes(name.as_bytes())?;
            if name == header::HOST
                || name == header::CONTENT_LENGTH
                || name == header::TRANSFER_ENCODING
            {
                return Err(invalid(
                    "connection header names a framing or authority field",
                ));
            }
            nominated.push(name);
        }
    }
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "transfer-encoding",
        "upgrade",
        "proxy-authorization",
        "proxy-authenticate",
        "proxy-connection",
        "te",
        "trailer",
    ] {
        headers.remove(name);
    }
    Ok(())
}

fn error(status: StatusCode) -> Response<Body> {
    let mut resp = Response::new(Empty::<Bytes>::new().map_err(|e| match e {}).boxed_unsync());
    *resp.status_mut() = status;
    resp
}

async fn request(req: Request<Incoming>, origin: &Origin, sender: &Sender) -> Response<Body> {
    if forbidden(&req, origin) {
        return error(StatusCode::FORBIDDEN);
    }
    let mut req = req;
    if strip(req.headers_mut()).is_err() {
        return error(StatusCode::BAD_REQUEST);
    }
    let authority = origin.to_string();
    req.headers_mut().remove(header::HOST);
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/")
        .to_owned();
    if !path.starts_with('/') {
        return error(StatusCode::BAD_REQUEST);
    }
    // Set each hop's request-target independently of how the peer spelled it.
    let result = match sender {
        Sender::H1(queue) => {
            let Ok(uri) = path.parse::<Uri>() else {
                return error(StatusCode::BAD_REQUEST);
            };
            *req.uri_mut() = uri;
            *req.version_mut() = Version::HTTP_11;
            req.headers_mut().insert(
                header::HOST,
                HeaderValue::from_str(&authority).expect("canonical origin"),
            );
            let mut sender = queue.lock().await;
            if sender.ready().await.is_err() {
                return error(StatusCode::BAD_GATEWAY);
            }
            sender.send_request(req).await
        }
        Sender::H2(handle) => {
            let Ok(uri) = Uri::builder()
                .scheme("https")
                .authority(authority.as_str())
                .path_and_query(path)
                .build()
            else {
                return error(StatusCode::BAD_REQUEST);
            };
            *req.uri_mut() = uri;
            *req.version_mut() = Version::HTTP_2;
            let mut sender = handle.clone();
            if sender.ready().await.is_err() {
                return error(StatusCode::BAD_GATEWAY);
            }
            sender.send_request(req).await
        }
    };
    match result {
        Ok(mut response) if response.status() != StatusCode::SWITCHING_PROTOCOLS => {
            if strip(response.headers_mut()).is_err() {
                return error(StatusCode::BAD_GATEWAY);
            }
            response.map(|b| b.boxed_unsync())
        }
        _ => error(StatusCode::BAD_GATEWAY),
    }
}

pub async fn http<D, U>(
    downstream: D,
    down_h2: bool,
    upstream: U,
    up_h2: bool,
    origin: Origin,
) -> Result<()>
where
    D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    U: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, driver) = if up_h2 {
        let (sender, conn) = http2::Builder::new(TokioExecutor::new())
            .initial_stream_window_size(16384)
            .initial_connection_window_size(65535)
            .max_send_buf_size(16384)
            .handshake(TokioIo::new(upstream))
            .await?;
        (Sender::H2(sender), tokio::spawn(conn))
    } else {
        let (sender, conn) = http1::Builder::new()
            .max_buf_size(65536)
            .handshake(TokioIo::new(upstream))
            .await?;
        (Sender::H1(Mutex::new(sender)), tokio::spawn(conn))
    };
    let sender = Arc::new(sender);
    let service = service_fn(move |req| {
        let sender = sender.clone();
        let origin = origin.clone();
        async move { Ok::<_, Infallible>(request(req, &origin, &sender).await) }
    });
    let result = if down_h2 {
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .max_concurrent_streams(32)
            .max_header_list_size(16384)
            .initial_stream_window_size(16384)
            .initial_connection_window_size(65535)
            .max_send_buf_size(16384)
            .serve_connection(TokioIo::new(downstream), service)
            .await
    } else {
        hyper::server::conn::http1::Builder::new()
            .max_headers(64)
            .max_buf_size(65536)
            .serve_connection(TokioIo::new(downstream), service)
            .await
    };
    driver.abort();
    result?;
    Ok(())
}
