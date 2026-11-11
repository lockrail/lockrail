//! Sealer HTTP relay (PLAN.md Phase 5a): one TLS-terminated client connection on a model host,
//! each request decided by [`crate::sealer::decide`], forwarded to the real upstream.
//!
//! Generic over the client and upstream I/O so tests can drive it over in-memory pipes with a
//! recording upstream (GATE 5), and the server wraps it with real TLS.

use crate::sealer::{Memo, Outcome, Report, SealerConfig, decide};
use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Bytes;
use hyper::header::{
    CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, HeaderValue, TRANSFER_ENCODING, UPGRADE,
};
use hyper::{Request, Response, StatusCode};
use std::convert::Infallible;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Receives one [`Report`] per request: counters only, never values (R-8).
pub type ReportSink = Arc<dyn Fn(&str, &Report) + Send + Sync>;

/// C7: request bodies larger than this are refused with 413 before decoding.
pub const MAX_REQUEST_BODY: usize = 32 * 1024 * 1024;
/// U-B: a request body must arrive within this time.
pub const BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

fn error_response(
    status: u16,
    kind: &str,
    message: &str,
    retry: bool,
) -> Response<BoxBody<Bytes, hyper::Error>> {
    let body = serde_json::json!({"error": {"type": kind, "message": message}}).to_string();
    let mut resp = Response::new(full(body));
    *resp.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    let h = resp.headers_mut();
    h.insert("content-type", HeaderValue::from_static("application/json"));
    h.insert("x-lockrail", HeaderValue::from_static("blocked"));
    if status >= 500 {
        // N1: the upstream side of this connection is gone; close the client side too so the
        // retry opens a fresh connection (and a fresh upstream).
        h.insert(CONNECTION, HeaderValue::from_static("close"));
    }
    if retry {
        h.insert("x-should-retry", HeaderValue::from_static("true"));
        h.insert("retry-after", HeaderValue::from_static("1"));
    }
    resp
}

fn full(bytes: impl Into<Bytes>) -> BoxBody<Bytes, hyper::Error> {
    Full::new(bytes.into())
        .map_err(|never: Infallible| match never {})
        .boxed()
}

fn is_websocket_upgrade(headers: &hyper::HeaderMap) -> bool {
    let upgrade = headers
        .get(UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    let connection = headers
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().contains("upgrade"));
    upgrade || connection && headers.contains_key("sec-websocket-key")
}

pub async fn relay_sealed<C, S>(
    client_io: C,
    server_io: S,
    host: String,
    config: Arc<SealerConfig>,
    memo: Arc<Memo>,
    reports: Option<ReportSink>,
) -> Result<()>
where
    C: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    S: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    use hyper::client::conn::http1 as client_h1;
    use hyper::server::conn::http1 as server_h1;

    let (sender, upstream) = client_h1::Builder::new()
        .preserve_header_case(true)
        .handshake::<S, BoxBody<Bytes, hyper::Error>>(server_io)
        .await
        .context("upstream HTTP/1.1 handshake")?;
    let sender = Arc::new(Mutex::new(sender));
    tokio::spawn(async move {
        let _ = upstream.await;
    });

    let service = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
        let sender = sender.clone();
        let host = host.clone();
        let config = config.clone();
        let memo = memo.clone();
        let reports = reports.clone();
        async move {
            let (mut parts, body) = req.into_parts();
            // Kill switch: a pure pass-through, streamed and never buffered.
            if !config.enabled {
                let upstream_req = Request::from_parts(parts, body.boxed());
                let mut s = sender.lock().await;
                return match s.send_request(upstream_req).await {
                    Ok(r) => {
                        let (rp, rb) = r.into_parts();
                        Ok(Response::from_parts(rp, rb.boxed()))
                    }
                    Err(_) => Ok(error_response(
                        502,
                        "lockrail_upstream_unavailable",
                        "the model API connection closed; retry",
                        true,
                    )),
                };
            }
            // C7: bodies are capped before buffering and must arrive within BODY_TIMEOUT.
            let collected = tokio::time::timeout(
                BODY_TIMEOUT,
                http_body_util::Limited::new(body, MAX_REQUEST_BODY).collect(),
            )
            .await;
            let body = match collected {
                Ok(Ok(c)) => c.to_bytes(),
                Ok(Err(e))
                    if e.downcast_ref::<http_body_util::LengthLimitError>()
                        .is_some() =>
                {
                    return Ok(error_response(
                        413,
                        "lockrail_body_too_large",
                        "request body exceeds 32 MiB",
                        false,
                    ));
                }
                Ok(Err(_)) => {
                    return Ok(error_response(
                        400,
                        "lockrail_bad_body",
                        "the request body could not be read",
                        false,
                    ));
                }
                Err(_) => {
                    return Ok(error_response(
                        408,
                        "lockrail_body_timeout",
                        "the request body did not arrive in time",
                        false,
                    ));
                }
            };
            let path = parts
                .uri
                .path_and_query()
                .map(|p| p.as_str().to_string())
                .unwrap_or_default();
            let encoding = parts
                .headers
                .get(CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let content_type = parts
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let (outcome, report) = {
                let config = config.clone();
                let memo = memo.clone();
                let websocket = is_websocket_upgrade(&parts.headers);
                let method = parts.method.to_string();
                let path = path.clone();
                let body = body.clone();
                // CPU-bound: off the async workers.
                tokio::task::spawn_blocking(move || {
                    decide(
                        &crate::sealer::Request {
                            method: &method,
                            content_type: content_type.as_deref(),
                            path_and_query: &path,
                            content_encoding: encoding.as_deref(),
                            websocket_upgrade: websocket,
                            body: &body,
                        },
                        &config,
                        &memo,
                    )
                })
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?
            };
            if let Some(sink) = &reports {
                sink(&host, &report);
            }
            let forward_body = match outcome {
                Outcome::Respond {
                    status,
                    body,
                    retry,
                } => {
                    let mut resp = Response::new(full(body));
                    *resp.status_mut() =
                        StatusCode::from_u16(status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
                    let h = resp.headers_mut();
                    h.insert("content-type", HeaderValue::from_static("application/json"));
                    h.insert("x-lockrail", HeaderValue::from_static("blocked"));
                    if retry {
                        h.insert("x-should-retry", HeaderValue::from_static("true"));
                        h.insert("retry-after", HeaderValue::from_static("1"));
                    }
                    return Ok::<_, anyhow::Error>(resp);
                }
                Outcome::Unchanged => body,
                Outcome::Rewritten(new_body) => {
                    parts.headers.remove(CONTENT_ENCODING);
                    parts.headers.remove(TRANSFER_ENCODING);
                    parts.headers.insert(
                        CONTENT_LENGTH,
                        HeaderValue::from_str(&new_body.len().to_string()).expect("length"),
                    );
                    Bytes::from(new_body)
                }
            };
            let upstream_req = Request::from_parts(parts, full(forward_body));
            let response = {
                let mut s = sender.lock().await;
                match s.send_request(upstream_req).await {
                    Ok(r) => r,
                    // U3: an upstream that closed is answered, not dropped, so the client retries.
                    Err(_) => {
                        return Ok(error_response(
                            502,
                            "lockrail_upstream_unavailable",
                            "the model API connection closed; retry",
                            true,
                        ));
                    }
                }
            };
            let (resp_parts, resp_body) = response.into_parts();
            Ok(Response::from_parts(resp_parts, resp_body.boxed()))
        }
    });

    server_h1::Builder::new()
        .preserve_header_case(true)
        .serve_connection(client_io, service)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sealer::{FailMode, PhiMode};
    use hyper_util::rt::TokioIo;
    use std::io::Write;
    use std::time::Duration;

    fn config(enabled: bool) -> Arc<SealerConfig> {
        Arc::new(SealerConfig {
            enabled,
            fp_key: [1u8; 32],
            phi_mode: PhiMode::Block,
            baa: false,
            phi_block_request: false,
            fail_mode: FailMode::Closed,
            deadline: Duration::from_millis(45),
        })
    }

    /// Start relay_sealed between an in-memory client and a recording upstream. Returns a
    /// client sender and the list of bodies the upstream received.
    /// Requests the recording upstream received: (path, body).
    type Recorded = Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>>;

    async fn harness(
        enabled: bool,
    ) -> (
        hyper::client::conn::http1::SendRequest<Full<Bytes>>,
        Recorded,
    ) {
        let (client_side, relay_client_side) = tokio::io::duplex(1 << 20);
        let (relay_upstream_side, upstream_side) = tokio::io::duplex(1 << 20);
        let recorded: Recorded = Arc::default();
        let rec = recorded.clone();
        tokio::spawn(async move {
            let service = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                let rec = rec.clone();
                async move {
                    let path = req
                        .uri()
                        .path_and_query()
                        .map(|p| p.to_string())
                        .unwrap_or_default();
                    let body = req.into_body().collect().await.unwrap().to_bytes().to_vec();
                    rec.lock().unwrap().push((path, body));
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                        b"{\"ok\":true}",
                    ))))
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(upstream_side), service)
                .await;
        });
        tokio::spawn(relay_sealed(
            TokioIo::new(relay_client_side),
            TokioIo::new(relay_upstream_side),
            "api.anthropic.com".into(),
            config(enabled),
            Arc::new(Memo::new(64 << 20)),
            None,
        ));
        let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client_side))
            .await
            .unwrap();
        tokio::spawn(conn);
        (sender, recorded)
    }

    fn canary() -> String {
        ["AKIA", "Q7ZK3M9B2N4P6R8T"].concat()
    }

    fn body() -> String {
        serde_json::json!({"model":"m","messages":[{"role":"user","content":format!("deploy with {}", canary())}]}).to_string()
    }

    fn encodings() -> Vec<(Option<&'static str>, Vec<u8>)> {
        let b = body();
        let gz = {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(b.as_bytes()).unwrap();
            e.finish().unwrap()
        };
        let br = {
            let mut out = Vec::new();
            brotli::BrotliCompress(&mut b.as_bytes(), &mut out, &Default::default()).unwrap();
            out
        };
        let zs = ruzstd::encoding::compress_to_vec(
            b.as_bytes(),
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        vec![
            (None, b.into_bytes()),
            (Some("gzip"), gz),
            (Some("br"), br),
            (Some("zstd"), zs),
        ]
    }

    #[tokio::test]
    async fn recording_upstream_sees_handles_never_the_canary() {
        let (mut client, recorded) = harness(true).await;
        for path in [
            "/v1/messages?beta=true",
            "/v1/messages/count_tokens",
            "/backend-api/codex/responses",
        ] {
            for (enc, bytes) in encodings() {
                let body = if path.contains("codex") {
                    serde_json::json!({"model":"m","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":format!("use {}", canary())}]}]}).to_string().into_bytes()
                } else {
                    bytes
                };
                let enc = if path.contains("codex") { None } else { enc };
                let mut req = Request::post(path).header("host", "api.anthropic.com");
                if let Some(e) = enc {
                    req = req.header("content-encoding", e);
                }
                let resp = client
                    .send_request(req.body(Full::new(Bytes::from(body))).unwrap())
                    .await
                    .unwrap();
                assert_eq!(resp.status(), 200);
            }
        }
        let rec = recorded.lock().unwrap();
        assert_eq!(rec.len(), 12);
        for (path, body) in rec.iter() {
            let text = String::from_utf8_lossy(body);
            assert!(
                !text.contains(&canary()),
                "canary reached upstream on {path}: {text}"
            );
            assert!(
                text.contains("lockrail://secret/aws-access-key-id/h_"),
                "{path}: {text}"
            );
        }
    }

    #[tokio::test]
    async fn positive_control_with_sealing_off_sees_the_canary() {
        let (mut client, recorded) = harness(false).await;
        let req = Request::post("/v1/messages")
            .body(Full::new(Bytes::from(body())))
            .unwrap();
        client.send_request(req).await.unwrap();
        let rec = recorded.lock().unwrap();
        assert!(
            String::from_utf8_lossy(&rec[0].1).contains(&canary()),
            "the recorder can see a canary"
        );
    }

    /// N1: when the upstream closes, the 502 also closes the client connection, so the client's
    /// retry opens a new connection instead of failing on a dead one.
    #[tokio::test]
    async fn upstream_close_closes_the_client_connection() {
        let (client_side, relay_client_side) = tokio::io::duplex(1 << 20);
        let (relay_upstream_side, upstream_side) = tokio::io::duplex(1 << 20);
        // A normal keep-alive upstream (no `connection: close` on its response), dropped later
        // the way a laptop sleep or an idle timeout drops it.
        let upstream = tokio::spawn(async move {
            let service =
                hyper::service::service_fn(|_req: Request<hyper::body::Incoming>| async {
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"{}"))))
                });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(upstream_side), service)
                .await;
        });
        tokio::spawn(relay_sealed(
            TokioIo::new(relay_client_side),
            TokioIo::new(relay_upstream_side),
            "api.anthropic.com".into(),
            config(true),
            Arc::new(Memo::new(1 << 20)),
            None,
        ));
        let (mut client, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client_side))
            .await
            .unwrap();
        let conn = tokio::spawn(conn);
        let ok = client
            .send_request(
                Request::post("/v1/messages")
                    .body(Full::new(Bytes::from_static(b"{}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ok.status(), 200);
        assert!(
            ok.headers().get("connection").is_none(),
            "upstream asked to close by itself"
        );
        upstream.abort();
        tokio::time::sleep(Duration::from_millis(50)).await;
        if let Ok(resp) = client
            .send_request(
                Request::post("/v1/messages")
                    .body(Full::new(Bytes::from_static(b"{}")))
                    .unwrap(),
            )
            .await
        {
            assert_eq!(resp.status(), 502);
            assert_eq!(resp.headers().get("connection").unwrap(), "close");
            assert_eq!(resp.headers().get("x-should-retry").unwrap(), "true");
        }
        // Either way the client connection ends instead of staying open on a dead upstream.
        tokio::time::timeout(Duration::from_secs(2), conn)
            .await
            .expect("client connection stayed open")
            .unwrap()
            .ok();
    }

    #[tokio::test]
    async fn oversized_body_is_refused_413_and_never_forwarded() {
        let (mut client, recorded) = harness(true).await;
        let big = vec![b'a'; MAX_REQUEST_BODY + 1];
        let resp = client
            .send_request(
                Request::post("/v1/messages")
                    .body(Full::new(Bytes::from(big)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 413);
        assert!(recorded.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn blocked_paths_never_reach_upstream_and_websocket_gets_426() {
        let (mut client, recorded) = harness(true).await;
        let resp = client
            .send_request(
                Request::post("/v1/files")
                    .body(Full::new(Bytes::from(format!(
                        "{{\"x\":\"{}\"}}",
                        canary()
                    ))))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
        let resp = client
            .send_request(
                Request::get("/backend-api/codex/responses")
                    .header("upgrade", "websocket")
                    .header("connection", "Upgrade")
                    .header("sec-websocket-key", "x")
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), 426);
        assert!(
            recorded.lock().unwrap().is_empty(),
            "a blocked request reached upstream"
        );
    }

    /// Claude Code-shaped history: many turns of code and tool output, each turn distinct (a turn
    /// number and a varying line), as a real session's history is.
    fn realistic_messages(target: usize) -> Vec<serde_json::Value> {
        let mut messages = Vec::new();
        let mut size = 0;
        let mut i = 0;
        while size < target {
            let code = format!(
                "fn handler_{i}(req: Request) -> Result<Response> {{\n    let user = db.find(req.id + {i})?;\n    Ok(Response::json(&user))\n}}\n"
            )
            .repeat(8);
            let turn = [
                serde_json::json!({"role":"user","content":[{"type":"text","text":format!("step {i}: refactor this\n{code}")}]}),
                serde_json::json!({"role":"assistant","content":[{"type":"text","text":"Here is the change."},{"type":"tool_use","id":format!("t{i}"),"name":"Edit","input":{"file_path":"src/main.rs","old_string":code,"new_string":code}}]}),
                serde_json::json!({"role":"user","content":[{"type":"tool_result","tool_use_id":format!("t{i}"),"content":format!("ok\n{code}")}]}),
            ];
            for m in turn {
                size += m.to_string().len();
                messages.push(m);
            }
            i += 1;
        }
        messages
    }

    /// GATE 5: sealer-added latency p95 < 50 ms, 200 runs, through the relay with sealing on vs
    /// the same relay with sealing off (a pass-through baseline over the same pipes). Each run
    /// appends a new user turn, as a real prompt does; the history is memoised after the first
    /// run, which is the steady state the memo exists for. Every response must be 200.
    /// `cargo test --release -p lockrail-proxy -- --ignored sealer_added_latency --nocapture`
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn sealer_added_latency_p95_under_50ms() {
        for size in [128 * 1024, 1024 * 1024] {
            let history = realistic_messages(size);
            let (mut via, recorded) = harness(true).await;
            let (mut direct, _) = harness(false).await;
            let mut added = Vec::new();
            let mut first = Duration::ZERO;
            let mut bytes = 0;
            for run in 0..200 {
                let mut messages = history.clone();
                messages.push(serde_json::json!({"role":"user","content":format!("new prompt {run} {}", canary())}));
                let body = serde_json::to_vec(&serde_json::json!({"model":"m","system":"You are a coding agent.","messages":messages})).unwrap();
                bytes = body.len();
                let t = std::time::Instant::now();
                let r = direct
                    .send_request(
                        Request::post("/v1/messages")
                            .body(Full::new(Bytes::from(body.clone())))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(r.status(), 200);
                let d = t.elapsed();
                let t = std::time::Instant::now();
                let r = via
                    .send_request(
                        Request::post("/v1/messages")
                            .body(Full::new(Bytes::from(body)))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(r.status(), 200, "sealed request failed");
                let v = t.elapsed();
                if run == 0 {
                    first = v.saturating_sub(d);
                }
                added.push(v.saturating_sub(d));
            }
            assert!(
                !String::from_utf8_lossy(&recorded.lock().unwrap().last().unwrap().1)
                    .contains(&canary())
            );
            added.sort();
            let (p50, p95) = (added[100], added[189]);
            eprintln!(
                "body {} KiB: sealer-added p50 {p50:?} p95 {p95:?}; first run (cold memo) {first:?}",
                bytes / 1024
            );
            assert!(p95 < Duration::from_millis(50), "p95 {p95:?}");
        }
    }
}
