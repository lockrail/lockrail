//! Sealer network server (PLAN.md section 3.1, Phase 5a).
//!
//! - Plain-HTTP CONNECT proxy on loopback. The CONNECT head is capped at 16 KiB and must be a
//!   single CONNECT; anything else is answered 405 and closed (no request smuggling into a tunnel).
//! - MITM only for [`SEALER_MITM_HOSTS`] on port 443; every other CONNECT is a blind tunnel, so
//!   sign-in, policy fetches and other hosts are never decrypted.
//! - One shared leaf-certificate resolver for the process (D14).
//! - Upstream TLS verified against the platform trust store (`rustls-platform-verifier`, m4), so a
//!   corporate TLS-inspection root that the OS trusts keeps working.
//! - Under launchd the listening socket comes from `launch_activate_socket` (m11): launchd owns
//!   `127.0.0.1:8789` while the sealer restarts, so the port is never free to squat.

use crate::ca::DynamicCertResolver;
use crate::sealer::{Memo, SEALER_MITM_HOSTS, SealerConfig};
use crate::sealer_relay::{ReportSink, relay_sealed};
use anyhow::{Context, Result, anyhow};
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, ServerConfig};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const MAX_CONNECT_HEAD: usize = 16 * 1024;
/// C7: bounds on a single connection and on the process.
const HEAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const UPSTREAM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const MAX_CONNECTIONS: usize = 1024;
/// U-B: a blind tunnel lives at most this long, so stalled tunnels cannot hold slots forever.
const TUNNEL_LIFETIME: std::time::Duration = std::time::Duration::from_secs(4 * 3600);

pub struct SealerServer {
    pub resolver: Arc<DynamicCertResolver>,
    /// Per-host configuration (a host's tool decides `baa`). Hosts not listed are tunnelled.
    pub configs: Vec<(String, Arc<SealerConfig>)>,
    pub memo: Arc<Memo>,
    pub reports: Option<ReportSink>,
    pub upstream_tls: Arc<ClientConfig>,
    /// Key for the health proof ([`health_proof`]): hooks check that the process on the proxy
    /// port is this sealer, not a plain proxy an agent started in its place.
    pub health_key: [u8; 32],
}

const HEALTH_PREFIX: &str = "GET http://lockrail.health/";

/// What the real sealer answers for `nonce`: an HMAC under the machine's key over a
/// domain-separated message. A process without the key cannot produce it.
pub fn health_proof(key: &[u8; 32], nonce: &str) -> String {
    lockrail_engine::handle::keyed_fingerprint(key, &format!("lockrail-sealer-health:{nonce}"))
}

/// `GET http://lockrail.health/<nonce> HTTP/1.1`, nonce 32-64 hex characters.
fn parse_health(head: &[u8]) -> Option<&str> {
    let line = std::str::from_utf8(head).ok()?.lines().next()?;
    let rest = line.strip_prefix(HEALTH_PREFIX)?;
    let (nonce, version) = rest.split_once(' ')?;
    ((32..=64).contains(&nonce.len())
        && nonce.bytes().all(|b| b.is_ascii_hexdigit())
        && version.starts_with("HTTP/1."))
    .then_some(nonce)
}

/// Client side of the health check (blocking, for hooks): true only when the listener at `addr`
/// answers `nonce` with the proof for `key`. A caller supplies a fresh random nonce each time.
pub fn health_check(
    addr: std::net::SocketAddr,
    key: &[u8; 32],
    nonce: &str,
    timeout: std::time::Duration,
) -> bool {
    use std::io::{Read, Write};
    let Ok(mut stream) = std::net::TcpStream::connect_timeout(&addr, timeout) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let request = format!("{HEALTH_PREFIX}{nonce} HTTP/1.1\r\nHost: lockrail.health\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return false;
    }
    let mut response = Vec::with_capacity(256);
    let _ = stream.take(4096).read_to_end(&mut response);
    let text = String::from_utf8_lossy(&response);
    let Some((head, body)) = text.split_once("\r\n\r\n") else {
        return false;
    };
    head.starts_with("HTTP/1.1 200 ") && body.trim() == health_proof(key, nonce)
}

impl SealerServer {
    fn config_for(&self, host: &str) -> Option<Arc<SealerConfig>> {
        self.configs
            .iter()
            .find(|(h, _)| h == host)
            .map(|(_, c)| c.clone())
    }
}

/// Upstream TLS with the platform verifier.
pub fn platform_client_config() -> Result<ClientConfig> {
    use rustls_platform_verifier::ConfigVerifierExt;
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    ClientConfig::with_platform_verifier().map_err(|e| anyhow!("platform verifier: {e}"))
}

pub async fn serve(listener: TcpListener, server: Arc<SealerServer>) -> Result<()> {
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        let permit = slots.clone().acquire_owned().await?;
        let (stream, _) = listener.accept().await?;
        let server = server.clone();
        tokio::spawn(async move {
            let _ = handle(stream, server).await;
            drop(permit);
        });
    }
}

/// Read the CONNECT head (request line + headers, up to the blank line), capped.
async fn read_head(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") && !head.ends_with(b"\n\n") {
        if head.len() >= MAX_CONNECT_HEAD {
            return Err(anyhow!("CONNECT head too large"));
        }
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            return Err(anyhow!("client closed before the CONNECT head ended"));
        }
        head.push(byte[0]);
    }
    Ok(head)
}

/// `CONNECT host:port HTTP/1.1` -> (host, port). Anything else is refused.
pub fn parse_connect(head: &[u8]) -> Option<(String, u16)> {
    let text = std::str::from_utf8(head).ok()?;
    let line = text.lines().next()?;
    let mut parts = line.split_whitespace();
    if parts.next()? != "CONNECT" {
        return None;
    }
    let target = parts.next()?;
    if !parts.next()?.starts_with("HTTP/1.") || parts.next().is_some() {
        return None;
    }
    let (host, port) = target.rsplit_once(':')?;
    // A trailing dot is the same name in DNS; without this, `api.anthropic.com.` would get a
    // blind tunnel instead of the sealer.
    let host = host.strip_suffix('.').unwrap_or(host);
    let port: u16 = port.parse().ok()?;
    if host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return None;
    }
    Some((host.to_ascii_lowercase(), port))
}

async fn handle(mut stream: TcpStream, server: Arc<SealerServer>) -> Result<()> {
    let head = tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut stream))
        .await
        .map_err(|_| anyhow!("CONNECT head timed out"))??;
    if let Some(nonce) = parse_health(&head) {
        let proof = health_proof(&server.health_key, nonce);
        let reply = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{proof}",
            proof.len()
        );
        stream.write_all(reply.as_bytes()).await?;
        return Ok(());
    }
    let Some((host, port)) = parse_connect(&head) else {
        stream
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    };
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    let mitm = port == 443 && SEALER_MITM_HOSTS.contains(&host.as_str());
    // Kill switch: a disabled host is a blind tunnel too (no TLS termination at all).
    let config = if mitm {
        server.config_for(&host).filter(|c| c.enabled)
    } else {
        None
    };
    let Some(config) = config else {
        // Blind tunnel: bytes are never inspected.
        let mut upstream =
            tokio::time::timeout(UPSTREAM_TIMEOUT, TcpStream::connect((host.as_str(), port)))
                .await
                .map_err(|_| anyhow!("tunnel connect timed out"))??;
        let _ = tokio::time::timeout(
            TUNNEL_LIFETIME,
            tokio::io::copy_bidirectional(&mut stream, &mut upstream),
        )
        .await;
        return Ok(());
    };

    let server_cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(server.resolver.clone());
    let client_tls = tokio::time::timeout(
        HEAD_TIMEOUT,
        TlsAcceptor::from(Arc::new(server_cfg)).accept(stream),
    )
    .await
    .map_err(|_| anyhow!("client TLS handshake timed out"))?
    .context("TLS accept from client")?;
    // C7: the TLS name must be the CONNECT host, so one tunnel cannot reach, or mint leaves for,
    // another name.
    if client_tls.get_ref().1.server_name() != Some(host.as_str()) {
        return Err(anyhow!("SNI does not match the CONNECT host"));
    }
    let upstream_tcp =
        tokio::time::timeout(UPSTREAM_TIMEOUT, TcpStream::connect((host.as_str(), 443)))
            .await
            .map_err(|_| anyhow!("upstream connect timed out"))?
            .context("connect upstream")?;
    let name = ServerName::try_from(host.clone()).map_err(|e| anyhow!("server name: {e}"))?;
    let upstream_tls = tokio::time::timeout(
        UPSTREAM_TIMEOUT,
        TlsConnector::from(server.upstream_tls.clone()).connect(name, upstream_tcp),
    )
    .await
    .map_err(|_| anyhow!("upstream TLS timed out"))?
    .context("TLS connect upstream")?;
    relay_sealed(
        TokioIo::new(client_tls),
        TokioIo::new(upstream_tls),
        host,
        config,
        server.memo.clone(),
        server.reports.clone(),
    )
    .await
}

/// The listening socket launchd created for this job (`Sockets` key `Listeners`).
#[cfg(target_os = "macos")]
pub fn launchd_listener(name: &str) -> Result<std::net::TcpListener> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd;
    unsafe extern "C" {
        fn launch_activate_socket(
            name: *const libc::c_char,
            fds: *mut *mut libc::c_int,
            cnt: *mut libc::size_t,
        ) -> libc::c_int;
    }
    let cname = CString::new(name)?;
    let mut fds: *mut libc::c_int = std::ptr::null_mut();
    let mut count: libc::size_t = 0;
    // SAFETY: valid C string and out-pointers; on success launchd allocates `fds` with malloc.
    let rc = unsafe { launch_activate_socket(cname.as_ptr(), &mut fds, &mut count) };
    if rc != 0 || count == 0 || fds.is_null() {
        return Err(anyhow!("launch_activate_socket({name}) failed: {rc}"));
    }
    // SAFETY: launchd returned `count` fds; we take the first and free the array.
    let fd = unsafe { *fds };
    unsafe { libc::free(fds.cast()) };
    let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
    listener.set_nonblocking(true)?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::{CaStore, LocalCa};
    use tokio_rustls::rustls::RootCertStore;

    #[test]
    fn connect_parsing_is_strict() {
        assert_eq!(
            parse_connect(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: x\r\n\r\n"),
            Some(("api.anthropic.com".into(), 443))
        );
        // A trailing dot is the same host: it must reach the sealer, not a blind tunnel.
        assert_eq!(
            parse_connect(b"CONNECT api.anthropic.com.:443 HTTP/1.1\r\n\r\n"),
            Some(("api.anthropic.com".into(), 443))
        );
        for bad in [
            &b"GET http://x/ HTTP/1.1\r\n\r\n"[..],
            b"CONNECT api.anthropic.com HTTP/1.1\r\n\r\n",
            b"CONNECT a b:443 HTTP/1.1\r\n\r\n",
            b"CONNECT evil\r\nInjected: 1:443 HTTP/1.1\r\n\r\n",
            b"CONNECT api.anthropic.com:443 HTTP/1.1 extra\r\n\r\n",
            b"CONNECT a_b.com:443 HTTP/1.1\r\n\r\n",
        ] {
            assert_eq!(
                parse_connect(bad),
                None,
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    /// GATE 5 (D14): 100 sequential TLS handshakes for one host generate one leaf key.
    #[tokio::test]
    async fn shared_resolver_generates_one_leaf_per_host() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let store = CaStore::generate().unwrap();
        let ca_pem = store.cert_pem().to_string();
        let resolver = Arc::new(DynamicCertResolver::new(Arc::new(LocalCa::new(store))));
        let server_cfg = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(resolver.clone()),
        );
        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile_certs(&ca_pem) {
            roots.add(cert).unwrap();
        }
        let client_cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );
        for _ in 0..100 {
            let (a, b) = tokio::io::duplex(64 * 1024);
            let acceptor = TlsAcceptor::from(server_cfg.clone());
            let server = tokio::spawn(async move { acceptor.accept(a).await.map(|_| ()) });
            let name = ServerName::try_from("api.anthropic.com").unwrap();
            TlsConnector::from(client_cfg.clone())
                .connect(name, b)
                .await
                .expect("client trusts the constrained leaf");
            // The client finished the handshake (that proves the leaf validates under the CA's name
            // constraints); the server may then see a broken pipe writing TLS 1.3 tickets.
            let _ = server.await;
        }
        assert_eq!(resolver.generated(), 1);
    }

    /// C7: no leaf for a name Lockrail does not intercept, so the cache cannot grow per SNI.
    #[tokio::test]
    async fn resolver_refuses_unknown_names() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let store = CaStore::generate().unwrap();
        let resolver = Arc::new(DynamicCertResolver::new(Arc::new(LocalCa::new(store))));
        let server_cfg = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(resolver.clone()),
        );
        let client_cfg = Arc::new(
            ClientConfig::builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth(),
        );
        let (a, b) = tokio::io::duplex(64 * 1024);
        let acceptor = TlsAcceptor::from(server_cfg);
        let server = tokio::spawn(async move { acceptor.accept(a).await.is_err() });
        let _ = TlsConnector::from(client_cfg)
            .connect(ServerName::try_from("evil.example.com").unwrap(), b)
            .await;
        assert!(
            server.await.unwrap(),
            "handshake for an unknown name succeeded"
        );
        assert_eq!(resolver.generated(), 0);
    }

    fn rustls_pemfile_certs(
        pem: &str,
    ) -> Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>> {
        use tokio_rustls::rustls::pki_types::{CertificateDer, pem::PemObject};
        CertificateDer::pem_slice_iter(pem.as_bytes())
            .map(|c| c.unwrap())
            .collect()
    }

    /// Architecture review: the hook trusted any listener on the proxy port. Only the real sealer
    /// (holding the machine key) passes the health check; an impostor answering 200 does not.
    #[tokio::test]
    async fn only_the_real_sealer_passes_the_health_check() {
        let key = [9u8; 32];
        let server = Arc::new(SealerServer {
            resolver: Arc::new(DynamicCertResolver::new(Arc::new(LocalCa::new(
                CaStore::generate().unwrap(),
            )))),
            configs: Vec::new(),
            memo: Arc::new(Memo::new(1 << 20)),
            reports: None,
            upstream_tls: Arc::new(platform_client_config().unwrap()),
            health_key: key,
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(listener, server));
        let nonce = "0123456789abcdef0123456789abcdef";
        let t = std::time::Duration::from_secs(2);
        let ok = tokio::task::spawn_blocking(move || health_check(addr, &key, nonce, t))
            .await
            .unwrap();
        assert!(ok, "real sealer");
        let wrong = tokio::task::spawn_blocking(move || health_check(addr, &[1u8; 32], nonce, t))
            .await
            .unwrap();
        assert!(!wrong, "wrong key");

        // An impostor plain proxy that says 200 with a made-up body.
        let fake = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let fake_addr = fake.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            if let Ok((mut c, _)) = fake.accept() {
                let mut buf = [0u8; 512];
                let _ = c.read(&mut buf);
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 34\r\n\r\nh_00000000000000000000000000000000");
            }
        });
        let impostor = tokio::task::spawn_blocking(move || health_check(fake_addr, &key, nonce, t))
            .await
            .unwrap();
        assert!(!impostor, "impostor accepted");
        assert_eq!(
            parse_health(b"GET http://lockrail.health/zz HTTP/1.1\r\n\r\n"),
            None
        );
    }
}
