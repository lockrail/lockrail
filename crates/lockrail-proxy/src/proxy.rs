use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Bytes;
use hyper::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING};
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{info, warn};

use super::ca::{DynamicCertResolver, LocalCa};
use lockrail_protocol::seal::{SealOptions, SecretFinding, seal_text};

/// The AI API hostnames whose HTTPS traffic is intercepted and scanned.
pub const AI_INTERCEPT_HOSTS: &[&str] = &[
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.cohere.ai",
    "api.mistral.ai",
    "openrouter.ai",
    "api.together.xyz",
    "api.groq.com",
];

pub struct ProxyConfig {
    pub listen_addr: SocketAddr,
    pub ca: Arc<LocalCa>,
    pub allow_non_loopback: bool,
    pub secret_sink: Option<Arc<dyn SecretSink>>,
}

pub trait SecretSink: Send + Sync {
    fn save_findings(&self, prefix: &str, findings: &[SecretFinding]) -> Result<()>;
}

pub async fn run_proxy(config: ProxyConfig) -> Result<()> {
    // Install the ring crypto provider as the process default (idempotent).
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    if !config.allow_non_loopback && !config.listen_addr.ip().is_loopback() {
        return Err(anyhow::anyhow!(
            "refusing to bind proxy to non-loopback address {}; pass --unsafe-public-listen only on a trusted network",
            config.listen_addr
        ));
    }

    let listener = TcpListener::bind(config.listen_addr).await?;
    let ca = config.ca;
    let secret_sink = config.secret_sink;

    info!(addr = %config.listen_addr, "lockrail proxy listening");

    loop {
        let (stream, peer) = listener.accept().await?;
        let ca = ca.clone();
        let secret_sink = secret_sink.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, ca, secret_sink).await {
                warn!(peer = %peer, error = %e, "proxy connection error");
            }
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    ca: Arc<LocalCa>,
    secret_sink: Option<Arc<dyn SecretSink>>,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut buf_stream = BufReader::new(&mut stream);

    // Read the CONNECT request line
    let mut request_line = String::new();
    buf_stream.read_line(&mut request_line).await?;
    let request_line = request_line.trim_end().to_string();

    // Drain remaining HTTP headers
    loop {
        let mut header = String::new();
        buf_stream.read_line(&mut header).await?;
        if header == "\r\n" || header == "\n" || header.trim().is_empty() {
            break;
        }
    }
    drop(buf_stream);

    let Some(host_port) = request_line
        .strip_prefix("CONNECT ")
        .and_then(|rest| rest.split_whitespace().next())
    else {
        // Not a CONNECT request — ignore
        return Ok(());
    };

    let host = host_port.split(':').next().unwrap_or(host_port);

    // Acknowledge the CONNECT tunnel
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    if AI_INTERCEPT_HOSTS.contains(&host) {
        intercept_tls(stream, host, ca, secret_sink).await
    } else {
        // Pass-through tunnel for non-AI hosts
        let port: u16 = host_port
            .split(':')
            .nth(1)
            .and_then(|p| p.parse().ok())
            .unwrap_or(443);
        let real = TcpStream::connect((host, port)).await?;
        let (mut cr, mut cw) = tokio::io::split(stream);
        let (mut sr, mut sw) = tokio::io::split(real);
        tokio::select! {
            _ = tokio::io::copy(&mut cr, &mut sw) => {}
            _ = tokio::io::copy(&mut sr, &mut cw) => {}
        }
        Ok(())
    }
}

async fn intercept_tls(
    client_tcp: TcpStream,
    host: &str,
    ca: Arc<LocalCa>,
    secret_sink: Option<Arc<dyn SecretSink>>,
) -> Result<()> {
    // Accept TLS from the AI tool using a dynamically-generated leaf cert.
    let resolver = Arc::new(DynamicCertResolver::new(ca));
    let server_cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
    let client_tls = acceptor
        .accept(client_tcp)
        .await
        .context("TLS accept from client")?;

    // Connect to the real AI API server with its actual TLS cert.
    let real_tcp = TcpStream::connect((host, 443u16))
        .await
        .context("connect to upstream")?;
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let client_cfg = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_cfg));
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|e| anyhow::anyhow!("invalid server name {host}: {e}"))?;
    let server_tls = connector
        .connect(server_name, real_tcp)
        .await
        .context("TLS connect to upstream")?;

    relay_http(
        TokioIo::new(client_tls),
        TokioIo::new(server_tls),
        host.to_string(),
        secret_sink,
    )
    .await
}

fn body_is_rewritable(headers: &hyper::HeaderMap) -> bool {
    let content_encoding = headers
        .get(CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_ascii_lowercase());
    if !matches!(content_encoding.as_deref(), None | Some("identity")) {
        return false;
    }

    let Some(content_type) = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return true;
    };
    let content_type = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
        .to_ascii_lowercase();
    matches!(
        content_type.as_str(),
        "application/json"
            | "application/x-www-form-urlencoded"
            | "application/xml"
            | "text/plain"
            | "text/html"
            | "text/css"
            | "text/javascript"
    ) || content_type.ends_with("+json")
}

fn event_stream(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or(value)
                .trim()
                .eq_ignore_ascii_case("text/event-stream")
        })
        .unwrap_or(false)
}

fn set_rewritten_body_headers(headers: &mut hyper::HeaderMap, len: usize) {
    headers.remove(CONTENT_LENGTH);
    headers.remove(TRANSFER_ENCODING);
    headers.insert(
        CONTENT_LENGTH,
        hyper::header::HeaderValue::from_str(&len.to_string()).expect("valid content length"),
    );
}

fn boxed_full(bytes: Bytes) -> BoxBody<Bytes, hyper::Error> {
    Full::new(bytes)
        .map_err(|never: Infallible| match never {})
        .boxed()
}

async fn relay_http<C, S>(
    client_io: C,
    server_io: S,
    host: String,
    secret_sink: Option<Arc<dyn SecretSink>>,
) -> Result<()>
where
    C: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    S: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    use hyper::client::conn::http1 as client_h1;
    use hyper::server::conn::http1 as server_h1;

    // Establish the outbound connection to the real AI server (we act as client).
    let (sender, server_conn) = client_h1::Builder::new()
        .preserve_header_case(true)
        .handshake::<S, Full<Bytes>>(server_io)
        .await
        .context("upstream HTTP/1.1 handshake")?;

    // Wrap the sender in Arc<Mutex> so it can be shared across multiple requests
    // in the service_fn closure — hyper's SendRequest is not Clone.
    let sender = Arc::new(Mutex::new(sender));

    tokio::spawn(async move {
        if let Err(e) = server_conn.await {
            warn!(error = %e, "upstream connection error");
        }
    });

    // Serve incoming requests from the AI tool, intercepting each one.
    let service = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
        let sender = sender.clone();
        let host = host.clone();
        let secret_sink = secret_sink.clone();
        async move {
            let (mut parts, body) = req.into_parts();
            let body_bytes = body
                .collect()
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?
                .to_bytes();

            let safe_body = if body_is_rewritable(&parts.headers) {
                let body_str = String::from_utf8_lossy(&body_bytes);
                let sealed_req = seal_text(&body_str, SealOptions::default());
                let sealed_req_count = sealed_req.findings.iter().filter(|f| f.should_seal).count();
                if sealed_req_count > 0 {
                    if let Some(sink) = &secret_sink {
                        sink.save_findings("proxy/request", &sealed_req.findings)
                            .map_err(|e| anyhow::anyhow!("{e}"))?;
                    }
                    info!(
                        host = %host,
                        sealed = sealed_req_count,
                        "sealed secrets in outbound AI API request"
                    );
                }
                let safe_body = Bytes::from(sealed_req.safe_text.into_bytes());
                set_rewritten_body_headers(&mut parts.headers, safe_body.len());
                safe_body
            } else {
                body_bytes
            };
            let upstream_req = Request::from_parts(parts, Full::new(safe_body));

            // Forward to the real server.
            let upstream_resp = {
                let mut s = sender.lock().await;
                s.send_request(upstream_req)
                    .await
                    .map_err(|e| anyhow::anyhow!("{e}"))?
            };

            let (mut resp_parts, resp_body) = upstream_resp.into_parts();
            if !body_is_rewritable(&resp_parts.headers) || event_stream(&resp_parts.headers) {
                return Ok::<Response<BoxBody<Bytes, hyper::Error>>, anyhow::Error>(
                    Response::from_parts(resp_parts, resp_body.boxed()),
                );
            }
            let resp_bytes = resp_body
                .collect()
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?
                .to_bytes();

            // Scan and seal secrets in the inbound response body.
            let resp_str = String::from_utf8_lossy(&resp_bytes);
            let sealed_resp = seal_text(&resp_str, SealOptions::default());
            let sealed_resp_count = sealed_resp
                .findings
                .iter()
                .filter(|f| f.should_seal)
                .count();
            if sealed_resp_count > 0 {
                if let Some(sink) = &secret_sink {
                    sink.save_findings("proxy/response", &sealed_resp.findings)
                        .map_err(|e| anyhow::anyhow!("{e}"))?;
                }
                info!(
                    host = %host,
                    sealed = sealed_resp_count,
                    "sealed secrets in AI API response"
                );
            }
            let safe_resp_bytes = Bytes::from(sealed_resp.safe_text.into_bytes());
            set_rewritten_body_headers(&mut resp_parts.headers, safe_resp_bytes.len());

            Ok::<Response<BoxBody<Bytes, hyper::Error>>, anyhow::Error>(Response::from_parts(
                resp_parts,
                boxed_full(safe_resp_bytes),
            ))
        }
    });

    // Drive the inbound connection from the AI tool.
    server_h1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(client_io, service)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::CaStore;
    use hyper::HeaderMap;
    use hyper::header::HeaderValue;

    #[test]
    fn body_is_rewritable_rejects_compressed_payloads() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));

        assert!(!body_is_rewritable(&headers));
    }

    #[test]
    fn body_is_rewritable_rejects_event_streams() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));

        assert!(!body_is_rewritable(&headers));
        assert!(event_stream(&headers));
    }

    #[test]
    fn set_rewritten_body_headers_replaces_length_and_transfer_encoding() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("999"));
        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));

        set_rewritten_body_headers(&mut headers, 42);

        assert_eq!(headers.get(CONTENT_LENGTH).unwrap(), "42");
        assert!(!headers.contains_key(TRANSFER_ENCODING));
    }

    #[tokio::test]
    async fn run_proxy_rejects_non_loopback_listen_without_explicit_allow() {
        let ca = Arc::new(LocalCa::new(CaStore::generate().unwrap()));
        let err = run_proxy(ProxyConfig {
            listen_addr: "0.0.0.0:0".parse().unwrap(),
            ca,
            allow_non_loopback: false,
            secret_sink: None,
        })
        .await
        .unwrap_err();

        assert!(err.to_string().contains("refusing to bind proxy"));
    }
}
