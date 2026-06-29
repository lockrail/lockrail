pub mod presets;
pub mod seal;

use base64ct::{Base64UrlUnpadded, Encoding};
use core::fmt;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use time::OffsetDateTime;
use url::{Host, Url};
use uuid::Uuid;
use zeroize::Zeroize;

pub const LRAP_VERSION: &str = "LRAP/0.3";
pub const TOKEN_PREFIX: &str = "lrap3";
pub const MAX_PROOF_SKEW_SECONDS: i64 = 120;
pub const DEFAULT_AUDIENCE: &str = "lockrail-relay";

#[derive(thiserror::Error, Debug)]
pub enum ProtocolError {
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64 error")]
    Base64,
    #[error("invalid signature")]
    Signature,
    #[error("malformed token")]
    MalformedToken,
    #[error("unsupported token prefix")]
    UnsupportedTokenPrefix,
    #[error("capability expired")]
    CapabilityExpired,
    #[error("capability not yet valid")]
    CapabilityNotYetValid,
    #[error("capability issued in the future")]
    CapabilityIssuedInFuture,
    #[error("capability revoked")]
    CapabilityRevoked,
    #[error("capability audience mismatch")]
    AudienceMismatch,
    #[error("missing proof")]
    MissingProof,
    #[error("proof version mismatch")]
    ProofVersion,
    #[error("proof payload does not match request")]
    ProofRequestMismatch,
    #[error("proof timestamp outside allowed skew")]
    ProofSkew,
    #[error("proof task mismatch")]
    ProofTaskMismatch,
    #[error("proof purpose mismatch")]
    ProofPurposeMismatch,
    #[error("url error: {0}")]
    Url(#[from] url::ParseError),
    #[error("key error")]
    Key,
    #[error("scheme not allowed: {0}")]
    SchemeNotAllowed(String),
    #[error("host not allowed: {0}")]
    HostNotAllowed(String),
    #[error("ip not allowed: {0}")]
    IpNotAllowed(String),
    #[error("port not allowed: {0}")]
    PortNotAllowed(u16),
    #[error("method not allowed: {0}")]
    MethodNotAllowed(String),
    #[error("path not allowed: {0}")]
    PathNotAllowed(String),
    #[error("query not allowed")]
    QueryNotAllowed,
    #[error("content type not allowed: {0}")]
    ContentTypeNotAllowed(String),
    #[error("body too large")]
    BodyTooLarge,
}

pub type Result<T> = std::result::Result<T, ProtocolError>;

fn canonical_json_value(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted = serde_json::Map::new();
            for (key, value) in map {
                sorted.insert(key.clone(), canonical_json_value(value));
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(canonical_json_value).collect::<Vec<_>>())
        }
        _ => value.clone(),
    }
}

pub fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let json = serde_json::to_value(value)?;
    Ok(serde_json::to_vec(&canonical_json_value(&json))?)
}

#[must_use]
pub fn b64e(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

pub fn b64d(s: &str) -> Result<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(s).map_err(|_| ProtocolError::Base64)
}

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    out.push_str(&hex::encode(h.finalize()));
    out
}

pub fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentKeypairDoc {
    pub version: u8,
    pub agent_id: String,
    pub name: String,
    pub kind: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub public_key: String,
    pub private_key: String,
}

impl AgentKeypairDoc {
    pub fn generate(name: impl Into<String>, kind: impl Into<String>) -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        let now = now_unix();
        Self {
            version: 1,
            agent_id: format!("agt_{}", Uuid::new_v4().simple()),
            name: name.into(),
            kind: kind.into(),
            created_at: now,
            updated_at: now,
            public_key: b64e(verifying.as_bytes()),
            private_key: b64e(&signing.to_bytes()),
        }
    }

    pub fn signing_key(&self) -> Result<SigningKey> {
        let raw = b64d(&self.private_key)?;
        let arr: [u8; 32] = raw.try_into().map_err(|_| ProtocolError::Key)?;
        Ok(SigningKey::from_bytes(&arr))
    }

    pub fn public_view(&self) -> AgentPublicDoc {
        AgentPublicDoc {
            version: self.version,
            agent_id: self.agent_id.clone(),
            name: self.name.clone(),
            kind: self.kind.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            public_key: self.public_key.clone(),
            revoked: false,
        }
    }
}

impl Drop for AgentKeypairDoc {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl fmt::Debug for AgentKeypairDoc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AgentKeypairDoc")
            .field("version", &self.version)
            .field("agent_id", &self.agent_id)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("public_key", &self.public_key)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentPublicDoc {
    pub version: u8,
    pub agent_id: String,
    pub name: String,
    pub kind: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub public_key: String,
    pub revoked: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PathPolicy {
    Exact,
    Prefix,
    Wildcard,
    Any,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathRule {
    pub policy: PathPolicy,
    pub value: String,
}

impl PathRule {
    pub fn exact(value: impl Into<String>) -> Self {
        Self {
            policy: PathPolicy::Exact,
            value: value.into(),
        }
    }

    pub fn prefix(value: impl Into<String>) -> Self {
        Self {
            policy: PathPolicy::Prefix,
            value: value.into(),
        }
    }

    pub fn wildcard(value: impl Into<String>) -> Self {
        Self {
            policy: PathPolicy::Wildcard,
            value: value.into(),
        }
    }

    pub fn any() -> Self {
        Self {
            policy: PathPolicy::Any,
            value: "*".to_string(),
        }
    }

    fn matches(&self, path: &str) -> bool {
        match self.policy {
            PathPolicy::Any => true,
            PathPolicy::Exact => path == self.value,
            PathPolicy::Prefix => path.starts_with(&self.value),
            PathPolicy::Wildcard => wildcard_match(&self.value, path),
        }
    }
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let parts = pattern.split('*').collect::<Vec<_>>();
    if parts.len() == 1 {
        return pattern == value;
    }
    let mut cursor = 0usize;
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if index == 0 && !pattern.starts_with('*') {
            if !value[cursor..].starts_with(part) {
                return false;
            }
            cursor += part.len();
            continue;
        }
        if index == parts.len() - 1 && !pattern.ends_with('*') {
            return value[cursor..].ends_with(part);
        }
        if let Some(pos) = value[cursor..].find(part) {
            cursor += pos + part.len();
        } else {
            return false;
        }
    }
    true
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueryPolicy {
    Any,
    None,
    Exact,
    Prefix,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityClaims {
    pub version: String,
    pub cap_id: Uuid,
    pub key: String,
    pub aud: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    pub allowed_schemes: Vec<String>,
    pub allowed_hosts: Vec<String>,
    pub allowed_ports: Vec<u16>,
    pub allowed_methods: Vec<String>,
    pub allowed_paths: Vec<PathRule>,
    pub query_policy: QueryPolicy,
    pub allowed_query_prefixes: Vec<String>,
    pub content_type_allowlist: Vec<String>,
    pub max_body_size: Option<u64>,
    pub inject_header: String,
    pub inject_prefix: String,
    pub max_uses: Option<u64>,
    pub require_proof: bool,
    pub agent_public_key: Option<String>,
    pub task_id: Option<String>,
    pub purpose: Option<String>,
    pub revoked: bool,
    pub labels: BTreeMap<String, String>,
}

impl CapabilityClaims {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: impl Into<String>,
        minutes: i64,
        allowed_hosts: Vec<String>,
        allowed_methods: Vec<String>,
        allowed_paths: Vec<String>,
        inject_header: impl Into<String>,
        inject_prefix: impl Into<String>,
        max_uses: Option<u64>,
        agent_public_key: Option<String>,
        task_id: Option<String>,
        purpose: Option<String>,
    ) -> Self {
        let now = now_unix();
        Self {
            version: LRAP_VERSION.to_string(),
            cap_id: Uuid::new_v4(),
            key: key.into(),
            aud: DEFAULT_AUDIENCE.to_string(),
            iat: now,
            nbf: now,
            exp: now + minutes * 60,
            allowed_schemes: vec!["https".to_string()],
            allowed_hosts: allowed_hosts
                .into_iter()
                .map(|host| host.to_ascii_lowercase())
                .collect(),
            allowed_ports: vec![443],
            allowed_methods: allowed_methods
                .into_iter()
                .map(|method| method.to_ascii_uppercase())
                .collect(),
            allowed_paths: allowed_paths
                .into_iter()
                .map(|path| {
                    if path == "*" {
                        PathRule::any()
                    } else if path.contains('*') {
                        PathRule::wildcard(path)
                    } else if path.ends_with('/') {
                        PathRule::prefix(path)
                    } else {
                        PathRule::exact(path)
                    }
                })
                .collect(),
            query_policy: QueryPolicy::Any,
            allowed_query_prefixes: Vec::new(),
            content_type_allowlist: vec![
                "application/json".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ],
            max_body_size: Some(1024 * 1024),
            inject_header: inject_header.into(),
            inject_prefix: inject_prefix.into(),
            max_uses,
            require_proof: agent_public_key.is_some(),
            agent_public_key,
            task_id,
            purpose,
            revoked: false,
            labels: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityToken {
    pub claims: CapabilityClaims,
    pub signature: String,
}

impl CapabilityToken {
    pub fn issue(claims: CapabilityClaims, issuer: &SigningKey) -> Result<String> {
        let payload = canonical(&claims)?;
        let sig = issuer.sign(&payload);
        Ok(format!(
            "{}.{}.{}",
            TOKEN_PREFIX,
            b64e(&payload),
            b64e(&sig.to_bytes())
        ))
    }

    pub fn verify(token: &str, issuer_public: &VerifyingKey, revoked: &[Uuid]) -> Result<Self> {
        let parts = token.split('.').collect::<Vec<_>>();
        if parts.len() != 3 {
            return Err(ProtocolError::MalformedToken);
        }
        if parts[0] != TOKEN_PREFIX {
            return Err(ProtocolError::UnsupportedTokenPrefix);
        }
        let payload = b64d(parts[1])?;
        let sig_bytes = b64d(parts[2])?;
        let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| ProtocolError::Signature)?;
        let sig = Signature::from_bytes(&sig_arr);
        issuer_public
            .verify(&payload, &sig)
            .map_err(|_| ProtocolError::Signature)?;
        let claims: CapabilityClaims = serde_json::from_slice(&payload)?;
        let now = now_unix();
        if claims.aud != DEFAULT_AUDIENCE {
            return Err(ProtocolError::AudienceMismatch);
        }
        if claims.iat > now + MAX_PROOF_SKEW_SECONDS {
            return Err(ProtocolError::CapabilityIssuedInFuture);
        }
        if claims.nbf > now {
            return Err(ProtocolError::CapabilityNotYetValid);
        }
        if claims.exp < now {
            return Err(ProtocolError::CapabilityExpired);
        }
        if claims.revoked || revoked.contains(&claims.cap_id) {
            return Err(ProtocolError::CapabilityRevoked);
        }
        Ok(Self {
            claims,
            signature: parts[2].to_string(),
        })
    }
}

pub fn verifying_key_from_b64(public_key: &str) -> Result<VerifyingKey> {
    let raw = b64d(public_key)?;
    let arr: [u8; 32] = raw.try_into().map_err(|_| ProtocolError::Key)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| ProtocolError::Key)
}

fn host_allowed(rule: &str, host: &str) -> bool {
    let rule = rule.trim_end_matches('.').to_ascii_lowercase();
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if let Some(stripped) = rule.strip_prefix("*.") {
        return host.ends_with(&rule[1..]) && host != stripped;
    }
    rule == host
}

fn host_is_private(host: &Host<&str>) -> bool {
    match host {
        Host::Domain(domain) => {
            let normalized = domain.trim_end_matches('.').to_ascii_lowercase();
            normalized == "localhost"
                || normalized.ends_with(".local")
                || normalized.ends_with(".internal")
                || normalized.ends_with(".lan")
        }
        Host::Ipv4(ip) => is_blocked_ip(&IpAddr::V4(*ip)),
        Host::Ipv6(ip) => is_blocked_ip(&IpAddr::V6(*ip)),
    }
}

fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || *ip == Ipv4Addr::UNSPECIFIED
                || *ip == Ipv4Addr::new(169, 254, 169, 254)
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_unicast_link_local()
                || ip.is_unique_local()
                || *ip == Ipv6Addr::LOCALHOST
        }
    }
}

pub fn enforce_request(claims: &CapabilityClaims, method: &str, upstream: &str) -> Result<Url> {
    let url = Url::parse(upstream)?;
    let scheme = url.scheme().to_ascii_lowercase();
    if !claims
        .allowed_schemes
        .iter()
        .any(|allowed| allowed == &scheme)
    {
        return Err(ProtocolError::SchemeNotAllowed(scheme));
    }
    if !matches!(scheme.as_str(), "https" | "http") {
        return Err(ProtocolError::SchemeNotAllowed(scheme));
    }
    let host = url
        .host()
        .ok_or_else(|| ProtocolError::HostNotAllowed(String::new()))?;
    if url.username() != "" || url.password().is_some() {
        return Err(ProtocolError::HostNotAllowed(
            url.host_str().unwrap_or_default().to_string(),
        ));
    }
    if host_is_private(&host) {
        return Err(ProtocolError::IpNotAllowed(host.to_string()));
    }
    let host_str = url.host_str().unwrap_or_default().to_ascii_lowercase();
    if host_str.ends_with('.') {
        return Err(ProtocolError::HostNotAllowed(host_str));
    }
    let host_str = host_str.trim_end_matches('.').to_string();
    if !claims
        .allowed_hosts
        .iter()
        .any(|allowed| host_allowed(allowed, &host_str))
    {
        return Err(ProtocolError::HostNotAllowed(host_str));
    }
    let port = url.port_or_known_default().unwrap_or(443);
    if !claims.allowed_ports.contains(&port) {
        return Err(ProtocolError::PortNotAllowed(port));
    }
    let method = method.to_ascii_uppercase();
    if !claims
        .allowed_methods
        .iter()
        .any(|allowed| allowed == &method)
    {
        return Err(ProtocolError::MethodNotAllowed(method));
    }
    let path = url.path();
    if !claims.allowed_paths.iter().any(|rule| rule.matches(path)) {
        return Err(ProtocolError::PathNotAllowed(path.to_string()));
    }
    match claims.query_policy {
        QueryPolicy::Any => {}
        QueryPolicy::None => {
            if url.query().is_some() {
                return Err(ProtocolError::QueryNotAllowed);
            }
        }
        QueryPolicy::Exact => {
            let query = url.query().unwrap_or_default();
            if !claims
                .allowed_query_prefixes
                .iter()
                .any(|allowed| allowed == query)
            {
                return Err(ProtocolError::QueryNotAllowed);
            }
        }
        QueryPolicy::Prefix => {
            let query = url.query().unwrap_or_default();
            if !claims
                .allowed_query_prefixes
                .iter()
                .any(|allowed| query.starts_with(allowed))
            {
                return Err(ProtocolError::QueryNotAllowed);
            }
        }
    }
    Ok(url)
}

pub fn enforce_content_type(claims: &CapabilityClaims, content_type: Option<&str>) -> Result<()> {
    if let Some(content_type) = content_type {
        let normalized = content_type
            .split(';')
            .next()
            .unwrap_or(content_type)
            .trim()
            .to_ascii_lowercase();
        if !claims
            .content_type_allowlist
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&normalized))
        {
            return Err(ProtocolError::ContentTypeNotAllowed(normalized));
        }
    }
    Ok(())
}

pub fn enforce_body_size(claims: &CapabilityClaims, size: usize) -> Result<()> {
    if let Some(max) = claims.max_body_size
        && size as u64 > max
    {
        return Err(ProtocolError::BodyTooLarge);
    }
    Ok(())
}

pub fn capability_hash(token: &str) -> String {
    sha256_hex(token.as_bytes())
}

pub fn body_hash(body: &[u8]) -> String {
    sha256_hex(body)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessProofPayload {
    pub version: String,
    pub agent_id: String,
    pub capability_hash: String,
    pub method: String,
    pub upstream: String,
    pub body_hash: String,
    pub nonce: String,
    pub timestamp: i64,
    pub task_id: Option<String>,
    pub purpose: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccessProof {
    pub payload: AccessProofPayload,
    pub signature: String,
}

impl AccessProof {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        agent: &AgentKeypairDoc,
        capability: &str,
        method: &str,
        upstream: &str,
        body_hash: &str,
        task_id: Option<String>,
        purpose: Option<String>,
    ) -> Result<Self> {
        let payload = AccessProofPayload {
            version: LRAP_VERSION.to_string(),
            agent_id: agent.agent_id.clone(),
            capability_hash: capability_hash(capability),
            method: method.to_ascii_uppercase(),
            upstream: upstream.to_string(),
            body_hash: body_hash.to_string(),
            nonce: Uuid::new_v4().simple().to_string(),
            timestamp: now_unix(),
            task_id,
            purpose,
        };
        let sig = agent.signing_key()?.sign(&canonical(&payload)?);
        Ok(Self {
            payload,
            signature: b64e(&sig.to_bytes()),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        agent_public_key: &str,
        capability: &str,
        method: &str,
        upstream: &str,
        body_hash: &str,
        expected_task_id: &Option<String>,
        expected_purpose: &Option<String>,
    ) -> Result<()> {
        if self.payload.version != LRAP_VERSION {
            return Err(ProtocolError::ProofVersion);
        }
        let expected = AccessProofPayload {
            version: LRAP_VERSION.to_string(),
            agent_id: self.payload.agent_id.clone(),
            capability_hash: capability_hash(capability),
            method: method.to_ascii_uppercase(),
            upstream: upstream.to_string(),
            body_hash: body_hash.to_string(),
            nonce: self.payload.nonce.clone(),
            timestamp: self.payload.timestamp,
            task_id: self.payload.task_id.clone(),
            purpose: self.payload.purpose.clone(),
        };
        if self.payload != expected {
            return Err(ProtocolError::ProofRequestMismatch);
        }
        let skew = (now_unix() - self.payload.timestamp).abs();
        if skew > MAX_PROOF_SKEW_SECONDS {
            return Err(ProtocolError::ProofSkew);
        }
        if expected_task_id.is_some() && &self.payload.task_id != expected_task_id {
            return Err(ProtocolError::ProofTaskMismatch);
        }
        if expected_purpose.is_some() && &self.payload.purpose != expected_purpose {
            return Err(ProtocolError::ProofPurposeMismatch);
        }
        let vk = verifying_key_from_b64(agent_public_key)?;
        let sig_bytes = b64d(&self.signature)?;
        let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| ProtocolError::Signature)?;
        let sig = Signature::from_bytes(&sig_arr);
        vk.verify(&canonical(&self.payload)?, &sig)
            .map_err(|_| ProtocolError::Signature)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptBody {
    pub version: String,
    pub typ: String,
    pub cap_id: Uuid,
    pub proof_hash: Option<String>,
    pub upstream: String,
    pub status_code: u16,
    pub issued_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Receipt {
    pub body: ReceiptBody,
    pub receipt_hash: String,
    pub signature: String,
}

impl Receipt {
    pub fn new(
        cap_id: Uuid,
        proof: Option<&AccessProofPayload>,
        upstream: &str,
        status_code: u16,
        signer: &SigningKey,
    ) -> Result<Self> {
        let proof_hash = match proof {
            Some(payload) => Some(sha256_hex(&canonical(payload)?)),
            None => None,
        };
        let body = ReceiptBody {
            version: LRAP_VERSION.to_string(),
            typ: "lockrail.receipt".to_string(),
            cap_id,
            proof_hash,
            upstream: upstream.to_string(),
            status_code,
            issued_at: now_unix(),
        };
        let canonical_body = canonical(&body)?;
        let receipt_hash = sha256_hex(&canonical_body);
        let signature = b64e(&signer.sign(&canonical_body).to_bytes());
        Ok(Self {
            body,
            receipt_hash,
            signature,
        })
    }

    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<()> {
        let body = canonical(&self.body)?;
        if self.receipt_hash != sha256_hex(&body) {
            return Err(ProtocolError::Signature);
        }
        let sig_bytes = b64d(&self.signature)?;
        let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| ProtocolError::Signature)?;
        let sig = Signature::from_bytes(&sig_arr);
        verifying_key
            .verify(&body, &sig)
            .map_err(|_| ProtocolError::Signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_and_proof_roundtrip() {
        let issuer = SigningKey::generate(&mut OsRng);
        let agent = AgentKeypairDoc::generate("claude", "claude-code");
        let claims = CapabilityClaims::new(
            "openai",
            5,
            vec!["api.openai.com".into()],
            vec!["POST".into()],
            vec!["/v1/*".into()],
            "Authorization",
            "Bearer ",
            Some(2),
            Some(agent.public_key.clone()),
            Some("task1".into()),
            Some("test".into()),
        );
        let token = CapabilityToken::issue(claims, &issuer).unwrap();
        let verified = CapabilityToken::verify(&token, &issuer.verifying_key(), &[]).unwrap();
        enforce_request(
            &verified.claims,
            "POST",
            "https://api.openai.com/v1/chat/completions",
        )
        .unwrap();
        let bh = body_hash(br#"{"x":1}"#);
        let proof = AccessProof::sign(
            &agent,
            &token,
            "POST",
            "https://api.openai.com/v1/chat/completions",
            &bh,
            Some("task1".into()),
            Some("test".into()),
        )
        .unwrap();
        proof
            .verify(
                verified.claims.agent_public_key.as_ref().unwrap(),
                &token,
                "POST",
                "https://api.openai.com/v1/chat/completions",
                &bh,
                &verified.claims.task_id,
                &verified.claims.purpose,
            )
            .unwrap();
        let receipt = Receipt::new(
            verified.claims.cap_id,
            Some(&proof.payload),
            "https://api.openai.com/v1/chat/completions",
            200,
            &issuer,
        )
        .unwrap();
        receipt.verify(&issuer.verifying_key()).unwrap();
    }

    #[test]
    fn path_policy_exact_is_not_prefix() {
        let claims = CapabilityClaims {
            allowed_paths: vec![PathRule::exact("/v1/messages".to_string())],
            ..CapabilityClaims::new(
                "anthropic",
                5,
                vec!["api.anthropic.com".into()],
                vec!["POST".into()],
                vec!["/v1/messages".into()],
                "x-api-key",
                "",
                Some(1),
                None,
                None,
                None,
            )
        };
        assert!(enforce_request(&claims, "POST", "https://api.anthropic.com/v1/messages").is_ok());
        assert!(
            enforce_request(
                &claims,
                "POST",
                "https://api.anthropic.com/v1/messages/extra"
            )
            .is_err()
        );
    }

    #[test]
    fn blocks_ssrf_hosts() {
        let claims = CapabilityClaims::new(
            "k",
            5,
            vec!["localhost".into(), "api.github.com".into()],
            vec!["GET".into()],
            vec!["/*".into()],
            "Authorization",
            "Bearer ",
            None,
            None,
            None,
            None,
        );
        assert!(enforce_request(&claims, "GET", "https://localhost/").is_err());
        assert!(enforce_request(&claims, "GET", "https://127.0.0.1/").is_err());
        assert!(enforce_request(&claims, "GET", "https://[::1]/").is_err());
        assert!(enforce_request(&claims, "GET", "https://10.0.0.1/").is_err());
        assert!(enforce_request(&claims, "GET", "https://169.254.169.254/").is_err());
        assert!(enforce_request(&claims, "GET", "https://api.github.com@evil.com/").is_err());
        assert!(enforce_request(&claims, "GET", "https://API.GITHUB.COM./").is_err());
        assert!(enforce_request(&claims, "GET", "https://api.github.com.evil.com/").is_err());
        assert!(enforce_request(&claims, "GET", "https://evilapi.github.com/").is_err());
    }

    #[test]
    fn rejects_wrong_audience_expired_future_iat_and_nbf() {
        let issuer = SigningKey::generate(&mut OsRng);
        let mut claims = CapabilityClaims::new(
            "openai",
            5,
            vec!["api.openai.com".into()],
            vec!["POST".into()],
            vec!["/v1/*".into()],
            "Authorization",
            "Bearer ",
            Some(1),
            None,
            None,
            None,
        );

        claims.aud = "other-relay".into();
        let token = CapabilityToken::issue(claims.clone(), &issuer).unwrap();
        assert!(matches!(
            CapabilityToken::verify(&token, &issuer.verifying_key(), &[]),
            Err(ProtocolError::AudienceMismatch)
        ));

        claims.aud = DEFAULT_AUDIENCE.into();
        claims.exp = now_unix() - 1;
        let token = CapabilityToken::issue(claims.clone(), &issuer).unwrap();
        assert!(matches!(
            CapabilityToken::verify(&token, &issuer.verifying_key(), &[]),
            Err(ProtocolError::CapabilityExpired)
        ));

        claims.exp = now_unix() + 60;
        claims.iat = now_unix() + MAX_PROOF_SKEW_SECONDS + 10;
        let token = CapabilityToken::issue(claims.clone(), &issuer).unwrap();
        assert!(matches!(
            CapabilityToken::verify(&token, &issuer.verifying_key(), &[]),
            Err(ProtocolError::CapabilityIssuedInFuture)
        ));

        claims.iat = now_unix();
        claims.nbf = now_unix() + 60;
        let token = CapabilityToken::issue(claims, &issuer).unwrap();
        assert!(matches!(
            CapabilityToken::verify(&token, &issuer.verifying_key(), &[]),
            Err(ProtocolError::CapabilityNotYetValid)
        ));
    }

    #[test]
    fn rejects_revoked_capability_and_proof_mismatches() {
        let issuer = SigningKey::generate(&mut OsRng);
        let agent = AgentKeypairDoc::generate("claude", "claude-code");
        let claims = CapabilityClaims::new(
            "openai",
            5,
            vec!["api.openai.com".into()],
            vec!["POST".into()],
            vec!["/v1/*".into()],
            "Authorization",
            "Bearer ",
            Some(1),
            Some(agent.public_key.clone()),
            Some("task1".into()),
            Some("purpose1".into()),
        );
        let revoked = vec![claims.cap_id];
        let token = CapabilityToken::issue(claims.clone(), &issuer).unwrap();
        assert!(matches!(
            CapabilityToken::verify(&token, &issuer.verifying_key(), &revoked),
            Err(ProtocolError::CapabilityRevoked)
        ));

        let bh = body_hash(br#"{"x":1}"#);
        let proof = AccessProof::sign(
            &agent,
            &token,
            "POST",
            "https://api.openai.com/v1/chat/completions",
            &bh,
            Some("task1".into()),
            Some("purpose1".into()),
        )
        .unwrap();

        assert!(matches!(
            proof.verify(
                &agent.public_key,
                &token,
                "POST",
                "https://api.openai.com/v1/other",
                &bh,
                &claims.task_id,
                &claims.purpose,
            ),
            Err(ProtocolError::ProofRequestMismatch)
        ));
        assert!(matches!(
            proof.verify(
                &agent.public_key,
                &token,
                "POST",
                "https://api.openai.com/v1/chat/completions",
                &bh,
                &Some("wrong".into()),
                &claims.purpose,
            ),
            Err(ProtocolError::ProofTaskMismatch)
        ));
        assert!(matches!(
            proof.verify(
                &agent.public_key,
                &token,
                "POST",
                "https://api.openai.com/v1/chat/completions",
                &bh,
                &claims.task_id,
                &Some("wrong".into()),
            ),
            Err(ProtocolError::ProofPurposeMismatch)
        ));
    }

    #[test]
    fn receipt_tamper_is_rejected_and_debug_hides_private_key() {
        let issuer = SigningKey::generate(&mut OsRng);
        let agent = AgentKeypairDoc::generate("claude", "claude-code");
        let debug = format!("{agent:?}");
        assert!(!debug.contains(&agent.private_key));
        let receipt = Receipt::new(
            Uuid::new_v4(),
            None,
            "https://api.openai.com/v1/chat/completions",
            200,
            &issuer,
        )
        .unwrap();
        let mut tampered = receipt;
        tampered.body.status_code = 500;
        assert!(tampered.verify(&issuer.verifying_key()).is_err());
    }
}
