use anyhow::{Context, Result, anyhow};
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use core::fmt;
use fs2::FileExt;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use lockrail_audit::AuditLog;
use lockrail_protocol::{
    AccessProof, CapabilityToken, Receipt, body_hash, enforce_body_size, enforce_content_type,
    enforce_request, seal::redact_for_logs, seal::seal_text,
};
use lockrail_vault::{Vault, VaultError};

#[derive(Clone)]
pub struct RelayState {
    pub vault: Arc<Mutex<Vault>>,
    pub audit: AuditLog,
    pub replay_store: Arc<dyn ReplayStore>,
    pub usage_store: Arc<dyn UsageStore>,
    pub client: reqwest::Client,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RelayRequest {
    pub capability: String,
    pub method: String,
    pub upstream: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub json: Option<serde_json::Value>,
    #[serde(default)]
    pub data: Option<String>,
    #[serde(default)]
    pub proof: Option<AccessProof>,
}

impl fmt::Debug for RelayRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayRequest")
            .field("capability", &"[REDACTED]")
            .field("method", &self.method)
            .field("upstream", &self.upstream)
            .field("headers", &"[REDACTED]")
            .field("json", &"[REDACTED]")
            .field("data", &"[REDACTED]")
            .field("proof", &self.proof.as_ref().map(|_| "[PRESENT]"))
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RelayResponse {
    pub status_code: u16,
    pub headers: BTreeMap<String, String>,
    pub body: String,
    pub lockrail_receipt: Receipt,
}

pub trait ReplayStore: Send + Sync {
    fn check_and_store(
        &self,
        capability_hash: &str,
        agent_id: &str,
        nonce: &str,
        expires_at: i64,
    ) -> Result<()>;
}

pub trait UsageStore: Send + Sync {
    fn record_use(&self, capability_hash: &str, max_uses: Option<u64>) -> Result<u64>;
}

#[derive(Clone, Default)]
pub struct InMemoryReplayStore {
    inner: Arc<Mutex<BTreeMap<String, i64>>>,
}

impl ReplayStore for InMemoryReplayStore {
    fn check_and_store(
        &self,
        capability_hash: &str,
        agent_id: &str,
        nonce: &str,
        expires_at: i64,
    ) -> Result<()> {
        let key = format!("{capability_hash}:{agent_id}:{nonce}");
        let now = lockrail_protocol::now_unix();
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| anyhow!("replay store poisoned"))?;
        inner.retain(|_, expiry| *expiry >= now);
        if inner.contains_key(&key) {
            return Err(VaultError::ReplayDetected.into());
        }
        inner.insert(key, expires_at);
        Ok(())
    }
}

#[derive(Clone)]
pub struct FileReplayStore {
    path: PathBuf,
}

impl FileReplayStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl ReplayStore for FileReplayStore {
    fn check_and_store(
        &self,
        capability_hash: &str,
        agent_id: &str,
        nonce: &str,
        expires_at: i64,
    ) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let lock_path = self.path.with_extension("lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        lock.lock_exclusive()?;
        let now = lockrail_protocol::now_unix();
        let mut map: BTreeMap<String, i64> = if self.path.exists() {
            serde_json::from_slice(&fs::read(&self.path)?)?
        } else {
            BTreeMap::new()
        };
        map.retain(|_, expiry| *expiry >= now);
        let key = format!("{capability_hash}:{agent_id}:{nonce}");
        if map.contains_key(&key) {
            return Err(VaultError::ReplayDetected.into());
        }
        map.insert(key, expires_at);
        fs::write(&self.path, serde_json::to_vec(&map)?)?;
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct InMemoryUsageStore {
    inner: Arc<Mutex<BTreeMap<String, u64>>>,
}

impl UsageStore for InMemoryUsageStore {
    fn record_use(&self, capability_hash: &str, max_uses: Option<u64>) -> Result<u64> {
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| anyhow!("usage store poisoned"))?;
        let current = *inner.get(capability_hash).unwrap_or(&0);
        if let Some(max) = max_uses
            && current >= max
        {
            return Err(VaultError::UsageLimitExceeded.into());
        }
        let next = current + 1;
        inner.insert(capability_hash.to_string(), next);
        Ok(next)
    }
}

#[derive(Clone)]
pub struct FileUsageStore {
    path: PathBuf,
}

impl FileUsageStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl UsageStore for FileUsageStore {
    fn record_use(&self, capability_hash: &str, max_uses: Option<u64>) -> Result<u64> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let lock_path = self.path.with_extension("lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;
        lock.lock_exclusive()?;
        let mut map: BTreeMap<String, u64> = if self.path.exists() {
            serde_json::from_slice(&fs::read(&self.path)?)?
        } else {
            BTreeMap::new()
        };
        let current = *map.get(capability_hash).unwrap_or(&0);
        if let Some(max) = max_uses
            && current >= max
        {
            return Err(VaultError::UsageLimitExceeded.into());
        }
        let next = current + 1;
        map.insert(capability_hash.to_string(), next);
        fs::write(&self.path, serde_json::to_vec(&map)?)?;
        Ok(next)
    }
}

fn body_bytes(req: &RelayRequest) -> Result<Vec<u8>> {
    if let Some(json) = &req.json {
        Ok(serde_json::to_vec(json)?)
    } else if let Some(data) = &req.data {
        Ok(data.as_bytes().to_vec())
    } else {
        Ok(Vec::new())
    }
}

fn content_type(req: &RelayRequest) -> Option<&str> {
    req.headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.as_str())
        .or_else(|| req.json.as_ref().map(|_| "application/json"))
}

fn scan_response_body(body: &str) -> (String, usize) {
    let sealed = seal_text(body, Default::default());
    let sealed_count = sealed
        .findings
        .iter()
        .filter(|finding| finding.should_seal)
        .count();
    (sealed.safe_text, sealed_count)
}

fn inject_secret(
    req: &RelayRequest,
    claims: &lockrail_protocol::CapabilityClaims,
    secret: &str,
) -> Result<(HeaderMap, Option<String>)> {
    let mut headers = HeaderMap::new();
    for (key, value) in &req.headers {
        headers.insert(
            HeaderName::from_bytes(key.as_bytes())?,
            HeaderValue::from_str(value)?,
        );
    }
    headers.insert(
        HeaderName::from_bytes(claims.inject_header.as_bytes())?,
        HeaderValue::from_str(&format!("{}{}", claims.inject_prefix, secret))?,
    );
    Ok((headers, None))
}

pub async fn perform_relay(state: RelayState, req: RelayRequest) -> Result<RelayResponse> {
    let body = body_bytes(&req)?;
    let body_hash = body_hash(&body);

    let (claims, proof_payload, capability_digest, receipt_signer, secret) = {
        let mut vault = state
            .vault
            .lock()
            .map_err(|_| anyhow!("vault lock poisoned"))?;
        let token = CapabilityToken::verify(
            &req.capability,
            &vault.issuer_public_key()?,
            &vault.revoked_list(),
        )?;

        let proof_payload = if token.claims.require_proof || token.claims.agent_public_key.is_some()
        {
            let proof = req.proof.as_ref().ok_or(VaultError::MissingCredential)?;
            let agent_public_key = token
                .claims
                .agent_public_key
                .as_ref()
                .ok_or(VaultError::PolicyDenied)?;
            proof.verify(
                agent_public_key,
                &req.capability,
                &req.method,
                &req.upstream,
                &body_hash,
                &token.claims.task_id,
                &token.claims.purpose,
            )?;
            Some(proof.payload.clone())
        } else {
            None
        };

        let signer = vault.signing_key()?;
        let secret = vault.use_key(&token.claims.key)?;
        (
            token.claims,
            proof_payload,
            lockrail_protocol::capability_hash(&req.capability),
            signer,
            secret,
        )
    };

    let url = enforce_request(&claims, &req.method, &req.upstream)?;
    enforce_body_size(&claims, body.len())?;
    enforce_content_type(&claims, content_type(&req))?;

    // DNS rebinding defence: resolve the hostname NOW and reject any resolved
    // address that maps to a private/loopback range.  This prevents an attacker
    // from using a short-TTL DNS record that points at an external IP during
    // the protocol check but resolves to an internal address when the TCP
    // connection is actually made.
    let resolved_addrs = {
        use std::net::IpAddr;
        let host = url.host_str().unwrap_or_default();
        let port = url.port_or_known_default().unwrap_or(443);
        let addrs = tokio::net::lookup_host((host, port))
            .await?
            .collect::<Vec<_>>();
        if addrs.is_empty() {
            return Err(anyhow!("DNS resolution returned no addresses for {host}"));
        }
        for addr in &addrs {
            let ip: IpAddr = addr.ip();
            if ip.is_loopback()
                || ip.is_unspecified()
                || matches!(ip, IpAddr::V4(v4) if
                    v4.is_private()
                    || v4.is_link_local()
                    || v4 == std::net::Ipv4Addr::new(169, 254, 169, 254))
                || matches!(ip, IpAddr::V6(v6) if
                    v6.is_unique_local() || v6.is_unicast_link_local())
            {
                return Err(anyhow!(
                    "DNS rebinding blocked: {host} resolved to private address {ip}"
                ));
            }
        }
        addrs
    };

    if let Some(proof) = &proof_payload {
        state.replay_store.check_and_store(
            &capability_digest,
            &proof.agent_id,
            &proof.nonce,
            claims.exp,
        )?;
    } else if claims.require_proof {
        return Err(VaultError::PolicyDenied.into());
    }

    state
        .usage_store
        .record_use(&capability_digest, claims.max_uses)?;

    let (headers, _body_override) = inject_secret(&req, &claims, &secret)?;

    state.audit.append(
        "relay.request",
        url.as_str(),
        serde_json::json!({
            "cap_id": claims.cap_id,
            "key": claims.key,
            "method": req.method,
            "proof_agent_id": proof_payload.as_ref().map(|proof| proof.agent_id.clone()),
        }),
    )?;

    let method = req.method.parse()?;
    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("validated upstream URL has no host"))?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(host, &resolved_addrs)
        .build()?;
    let mut builder = client
        .request(method, url.clone())
        .headers(headers)
        .timeout(Duration::from_secs(30));
    if let Some(json) = &req.json {
        builder = builder.json(json);
    } else if let Some(data) = &req.data {
        builder = builder.body(data.clone());
    }

    let response = builder.send().await?;
    let status_code = response.status().as_u16();
    let headers_out = response
        .headers()
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_str().unwrap_or("").to_string()))
        .collect::<BTreeMap<_, _>>();
    let raw_text = response
        .text()
        .await
        .context("failed to read upstream response body")?;
    let (safe_text, sealed_response_secrets) = scan_response_body(&raw_text);
    let receipt = Receipt::new(
        claims.cap_id,
        proof_payload.as_ref(),
        url.as_str(),
        status_code,
        &receipt_signer,
    )?;

    state.audit.append(
        "relay.response",
        url.as_str(),
        serde_json::json!({
            "cap_id": claims.cap_id,
            "status_code": status_code,
            "receipt_hash": receipt.receipt_hash,
            "sealed_response_secrets": sealed_response_secrets,
        }),
    )?;

    Ok(RelayResponse {
        status_code,
        headers: headers_out,
        body: safe_text,
        lockrail_receipt: receipt,
    })
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status":"ok"}))
}

async fn relay_handler(
    State(state): State<RelayState>,
    Json(req): Json<RelayRequest>,
) -> (axum::http::StatusCode, Json<serde_json::Value>) {
    match perform_relay(state.clone(), req).await {
        Ok(response) => {
            tracing::info!(
                status_code = response.status_code,
                receipt_hash = %response.lockrail_receipt.receipt_hash,
                "relay response ok"
            );
            match serde_json::to_value(response) {
                Ok(value) => (axum::http::StatusCode::OK, Json(value)),
                Err(error) => (
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": redact_for_logs(&error.to_string())})),
                ),
            }
        }
        Err(error) => {
            let safe_error = redact_for_logs(&error.to_string());
            tracing::warn!(error = %safe_error, "relay request denied");
            let _ =
                state
                    .audit
                    .append("relay.denied", "", serde_json::json!({"error": safe_error}));
            (
                axum::http::StatusCode::FORBIDDEN,
                Json(serde_json::json!({"error": safe_error})),
            )
        }
    }
}

pub async fn serve(state: RelayState, addr: SocketAddr) -> Result<()> {
    let app = Router::new()
        .route("/healthz", get(health))
        .route("/relay", post(relay_handler))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lockrail_protocol::{AgentKeypairDoc, CapabilityClaims, PathRule, QueryPolicy};
    use lockrail_vault::KdfParamsDoc;
    use secrecy::SecretString;

    #[test]
    fn replay_store_rejects_duplicate_nonce() {
        let store = InMemoryReplayStore::default();
        store
            .check_and_store("cap", "agent", "nonce", lockrail_protocol::now_unix() + 60)
            .unwrap();
        assert!(
            store
                .check_and_store("cap", "agent", "nonce", lockrail_protocol::now_unix() + 60)
                .is_err()
        );
    }

    #[test]
    fn usage_store_allows_exactly_one_use() {
        let store = InMemoryUsageStore::default();
        assert_eq!(store.record_use("cap", Some(1)).unwrap(), 1);
        assert!(store.record_use("cap", Some(1)).is_err());
    }

    #[test]
    fn usage_store_is_atomic_under_concurrency() {
        let store = Arc::new(InMemoryUsageStore::default());
        let handles = (0..8)
            .map(|_| {
                let store = store.clone();
                std::thread::spawn(move || store.record_use("cap", Some(1)).is_ok())
            })
            .collect::<Vec<_>>();
        let success = handles
            .into_iter()
            .filter_map(|handle| handle.join().ok())
            .filter(|ok| *ok)
            .count();
        assert_eq!(success, 1);
    }

    #[test]
    fn relay_ssrf_policy_examples_fail_in_protocol() {
        let claims = CapabilityClaims {
            allowed_hosts: vec!["api.github.com".to_string()],
            allowed_paths: vec![PathRule::wildcard("/*".to_string())],
            query_policy: QueryPolicy::None,
            ..CapabilityClaims::new(
                "github",
                5,
                vec!["api.github.com".into()],
                vec!["GET".into()],
                vec!["/*".into()],
                "Authorization",
                "Bearer ",
                Some(1),
                None,
                None,
                None,
            )
        };
        assert!(enforce_request(&claims, "GET", "https://127.0.0.1/").is_err());
        assert!(enforce_request(&claims, "GET", "https://[::1]/").is_err());
        assert!(enforce_request(&claims, "GET", "https://169.254.169.254/").is_err());
        assert!(enforce_request(&claims, "GET", "https://api.github.com./").is_err());
        assert!(enforce_request(&claims, "GET", "https://api.github.com@evil.com/").is_err());
        assert!(enforce_request(&claims, "GET", "https://api.github.com.evil.com/").is_err());
    }

    #[test]
    fn encrypted_agent_keys_stay_out_of_request_flow_tests() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lockrail");
        let mut vault =
            Vault::init(&path, SecretString::from("pw"), KdfParamsDoc::test_fast()).unwrap();
        let agent = AgentKeypairDoc::generate("claude", "claude-code");
        vault.save_agent(&agent, tmp.path().join("agents")).unwrap();
        let raw = fs::read_to_string(path).unwrap();
        assert!(!raw.contains(&agent.private_key));
    }

    #[tokio::test]
    async fn relay_rejects_missing_proof_when_required() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lockrail");
        let mut vault =
            Vault::init(&path, SecretString::from("pw"), KdfParamsDoc::test_fast()).unwrap();
        vault
            .add_key(
                "sealed/openai/fp_demo".into(),
                "sk-proj-LOCKRAILTEST-fakesecretvalue".into(),
            )
            .unwrap();
        let agent = AgentKeypairDoc::generate("codex", "codex");
        let claims = CapabilityClaims::new(
            "sealed/openai/fp_demo",
            5,
            vec!["api.openai.com".into()],
            vec!["POST".into()],
            vec!["/v1/*".into()],
            "Authorization",
            "Bearer ",
            Some(1),
            Some(agent.public_key.clone()),
            Some("task-1".into()),
            Some("demo".into()),
        );
        let capability = CapabilityToken::issue(claims, &vault.signing_key().unwrap()).unwrap();
        let state = RelayState {
            vault: Arc::new(Mutex::new(vault)),
            audit: AuditLog::new(tmp.path().join("audit.jsonl")),
            replay_store: Arc::new(InMemoryReplayStore::default()),
            usage_store: Arc::new(InMemoryUsageStore::default()),
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
        };
        let request = RelayRequest {
            capability,
            method: "POST".into(),
            upstream: "https://api.openai.com/v1/chat/completions".into(),
            headers: BTreeMap::new(),
            json: Some(serde_json::json!({"model":"gpt-4.1-mini"})),
            data: None,
            proof: None,
        };
        let error = perform_relay(state, request).await.unwrap_err();
        let msg = redact_for_logs(&error.to_string());
        assert!(
            msg.contains("missing credential")
                || msg.contains("secret not found")
                || msg.contains("policy denied"),
            "unexpected error: {msg}"
        );
    }
}
