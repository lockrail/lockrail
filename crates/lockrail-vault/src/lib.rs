use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64ct::{Base64UrlUnpadded, Encoding};
use core::fmt;
use ed25519_dalek::SigningKey;
use fs2::FileExt;
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

pub use lockrail_protocol::{AgentKeypairDoc, AgentPublicDoc};
use lockrail_protocol::{b64d, b64e, now_unix, sha256_hex};

pub const VAULT_VERSION: u8 = 2;
const AGENT_SECRET_PREFIX: &str = "agent-private/";

#[derive(thiserror::Error, Debug)]
pub enum VaultError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("cryptographic verification failed")]
    Crypto,
    #[error("wrong password — check LOCKRAIL_PASSWORD or re-run with the correct password")]
    WrongPassword,
    #[error("unsupported vault version {0}")]
    Version(u8),
    #[error("vault already exists at this path")]
    Exists,
    #[error("vault not found — run 'lockrail init' to set up Lockrail first")]
    Missing,
    #[error("secret not found — run 'lockrail secret list' to see available secrets")]
    MissingCredential,
    #[error("a secret with this name already exists — use 'lockrail secret set' to update it")]
    CredentialExists,
    #[error("invalid secret name — names must not be empty, contain spaces, or contain '..'")]
    InvalidName,
    #[error("usage limit exceeded")]
    UsageLimitExceeded,
    #[error("replay detected")]
    ReplayDetected,
    #[error("policy denied")]
    PolicyDenied,
    #[error("revoked capability or agent")]
    Revoked,
    #[error("protocol: {0}")]
    Protocol(#[from] lockrail_protocol::ProtocolError),
}

pub type Result<T> = std::result::Result<T, VaultError>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParamsDoc {
    pub name: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub output_len: usize,
}

impl Default for KdfParamsDoc {
    fn default() -> Self {
        Self {
            name: "argon2id".into(),
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 1,
            output_len: 32,
        }
    }
}

impl KdfParamsDoc {
    pub fn test_fast() -> Self {
        Self {
            memory_kib: 1024,
            iterations: 1,
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultEnvelope {
    pub version: u8,
    pub kdf: KdfParamsDoc,
    pub salt: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretMetadata {
    pub name: String,
    pub kind: String,
    pub fingerprint: String,
    pub redacted_preview: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_used_at: Option<i64>,
    pub tags: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretRecord {
    pub value: String,
    pub metadata: SecretMetadata,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentRecord {
    pub public: AgentPublicDoc,
    pub updated_at: i64,
    pub revoked: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct VaultData {
    pub version: u8,
    pub created_at: i64,
    pub keys: BTreeMap<String, SecretRecord>,
    pub signing_private_key: String,
    pub revoked_capabilities: BTreeSet<uuid::Uuid>,
    pub revoked_agents: BTreeSet<String>,
    pub capability_usage: BTreeMap<uuid::Uuid, u64>,
    pub agents: BTreeMap<String, AgentRecord>,
}

impl Drop for VaultData {
    fn drop(&mut self) {
        self.signing_private_key.zeroize();
        for record in self.keys.values_mut() {
            record.value.zeroize();
        }
    }
}

pub struct Vault {
    pub path: PathBuf,
    pub password: SecretString,
    pub kdf: KdfParamsDoc,
    pub data: VaultData,
}

impl fmt::Debug for SecretRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretRecord")
            .field("value", &"[REDACTED]")
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl fmt::Debug for VaultData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultData")
            .field("version", &self.version)
            .field("created_at", &self.created_at)
            .field("keys", &self.keys)
            .field("signing_private_key", &"[REDACTED]")
            .field("revoked_capabilities", &self.revoked_capabilities)
            .field("revoked_agents", &self.revoked_agents)
            .field("capability_usage", &self.capability_usage)
            .field("agents", &self.agents)
            .finish()
    }
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("password", &"[REDACTED]")
            .field("kdf", &self.kdf)
            .field("data", &self.data)
            .finish()
    }
}

pub fn default_home() -> PathBuf {
    std::env::var("LOCKRAIL_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".lockrail")
        })
}

pub fn default_vault_path() -> PathBuf {
    default_home().join("vault.lockrail")
}

pub fn default_agents_dir() -> PathBuf {
    default_home().join("agents")
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name.chars().any(char::is_whitespace) || name.contains("..") {
        return Err(VaultError::InvalidName);
    }
    Ok(())
}

fn redacted_preview(value: &str) -> String {
    lockrail_protocol::seal::scan_text(value, Default::default())
        .first()
        .map(|finding| finding.preview.clone())
        .unwrap_or_else(|| {
            let chars = value.chars().collect::<Vec<_>>();
            match chars.len() {
                0 => String::new(),
                1..=8 => "***".to_string(),
                len => format!(
                    "{}***{}",
                    chars[..4].iter().collect::<String>(),
                    chars[len - 4..].iter().collect::<String>()
                ),
            }
        })
}

fn classify_kind(name: &str) -> String {
    if let Some((prefix, _)) = name.split_once('/') {
        prefix.to_string()
    } else {
        "generic".to_string()
    }
}

fn secret_metadata(name: &str, value: &str, tags: Vec<String>) -> SecretMetadata {
    let now = now_unix();
    SecretMetadata {
        name: name.to_string(),
        kind: classify_kind(name),
        fingerprint: format!("fp_{}", &sha256_hex(value.as_bytes())[7..23]),
        redacted_preview: redacted_preview(value),
        created_at: now,
        updated_at: now,
        last_used_at: None,
        tags,
    }
}

fn derive_key(password: &SecretString, salt: &[u8], params: &KdfParamsDoc) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    let p = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(params.output_len),
    )
    .map_err(|_| VaultError::Crypto)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    argon
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut key)
        .map_err(|_| VaultError::Crypto)?;
    Ok(key)
}

fn lock_file(path: &Path) -> Result<File> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    let lock_path = path.with_extension("lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    file.lock_exclusive()?;
    Ok(file)
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    let tmp = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn legacy_to_v2(mut data: serde_json::Value) -> VaultData {
    let created_at = data
        .get("created_at")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or_else(now_unix);
    let signing_private_key = data
        .get("signing_private_key")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    let revoked_capabilities = serde_json::from_value(
        data.get("revoked_capabilities")
            .cloned()
            .unwrap_or_else(|| serde_json::json!([])),
    )
    .unwrap_or_default();
    let capability_usage = serde_json::from_value(
        data.get("capability_usage")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
    )
    .unwrap_or_default();
    let mut keys = BTreeMap::new();
    if let Some(old_keys) = data
        .get_mut("keys")
        .and_then(serde_json::Value::as_object_mut)
    {
        for (name, value) in old_keys.iter_mut() {
            if let Some(record) = value.as_object() {
                if record.contains_key("metadata") {
                    let parsed: SecretRecord =
                        serde_json::from_value(serde_json::Value::Object(record.clone()))
                            .unwrap_or_else(|_| SecretRecord {
                                value: String::new(),
                                metadata: secret_metadata(name, "", Vec::new()),
                            });
                    keys.insert(name.clone(), parsed);
                } else {
                    let raw_value = record
                        .get("value")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default()
                        .to_string();
                    keys.insert(
                        name.clone(),
                        SecretRecord {
                            value: raw_value.clone(),
                            metadata: secret_metadata(name, &raw_value, Vec::new()),
                        },
                    );
                }
            }
        }
    }
    VaultData {
        version: VAULT_VERSION,
        created_at,
        keys,
        signing_private_key,
        revoked_capabilities,
        revoked_agents: BTreeSet::new(),
        capability_usage,
        agents: BTreeMap::new(),
    }
}

impl Vault {
    pub fn init(
        path: impl Into<PathBuf>,
        password: SecretString,
        kdf: KdfParamsDoc,
    ) -> Result<Self> {
        let path = path.into();
        if path.exists() {
            return Err(VaultError::Exists);
        }
        let signing = SigningKey::generate(&mut OsRng);
        let data = VaultData {
            version: VAULT_VERSION,
            created_at: now_unix(),
            keys: BTreeMap::new(),
            signing_private_key: b64e(&signing.to_bytes()),
            revoked_capabilities: BTreeSet::new(),
            revoked_agents: BTreeSet::new(),
            capability_usage: BTreeMap::new(),
            agents: BTreeMap::new(),
        };
        let vault = Self {
            path,
            password,
            kdf,
            data,
        };
        vault.save()?;
        Ok(vault)
    }

    pub fn open(path: impl Into<PathBuf>, password: SecretString) -> Result<Self> {
        let path = path.into();
        if !path.exists() {
            return Err(VaultError::Missing);
        }
        let _lock = lock_file(&path)?;
        let env: VaultEnvelope = serde_json::from_slice(&fs::read(&path)?)?;
        let salt = Base64UrlUnpadded::decode_vec(&env.salt).map_err(|_| VaultError::Crypto)?;
        let nonce_bytes =
            Base64UrlUnpadded::decode_vec(&env.nonce).map_err(|_| VaultError::Crypto)?;
        let ciphertext =
            Base64UrlUnpadded::decode_vec(&env.ciphertext).map_err(|_| VaultError::Crypto)?;
        let mut key = derive_key(&password, &salt, &env.kdf)?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| VaultError::Crypto)?;
        let aad = serde_json::to_vec(
            &serde_json::json!({ "version": env.version, "kdf": env.kdf, "salt": env.salt }),
        )?;
        let mut plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                aes_gcm::aead::Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| VaultError::WrongPassword)?;
        key.zeroize();
        let raw: serde_json::Value = serde_json::from_slice(&plaintext)?;
        let data = match env.version {
            1 => legacy_to_v2(raw),
            2 => serde_json::from_value(raw)?,
            other => return Err(VaultError::Version(other)),
        };
        plaintext.zeroize();
        Ok(Self {
            path,
            password,
            kdf: env.kdf,
            data,
        })
    }

    pub fn save(&self) -> Result<()> {
        let _lock = lock_file(&self.path)?;
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let mut key = derive_key(&self.password, &salt, &self.kdf)?;
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| VaultError::Crypto)?;
        let salt_b64 = b64e(&salt);
        let aad = serde_json::to_vec(
            &serde_json::json!({ "version": VAULT_VERSION, "kdf": self.kdf, "salt": salt_b64 }),
        )?;
        let mut plaintext = serde_json::to_vec(&self.data)?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                aes_gcm::aead::Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| VaultError::Crypto)?;
        let env = VaultEnvelope {
            version: VAULT_VERSION,
            kdf: self.kdf.clone(),
            salt: salt_b64,
            nonce: b64e(&nonce),
            ciphertext: b64e(&ciphertext),
        };
        plaintext.zeroize();
        key.zeroize();
        write_private_atomic(&self.path, &serde_json::to_vec_pretty(&env)?)
    }

    pub fn add_key(&mut self, name: String, value: String) -> Result<()> {
        validate_name(&name)?;
        if self.data.keys.contains_key(&name) {
            return Err(VaultError::CredentialExists);
        }
        self.data.keys.insert(
            name.clone(),
            SecretRecord {
                value: value.clone(),
                metadata: secret_metadata(&name, &value, Vec::new()),
            },
        );
        self.save()
    }

    pub fn upsert_key(&mut self, name: String, value: String, tags: Vec<String>) -> Result<()> {
        validate_name(&name)?;
        let now = now_unix();
        let created_at = self
            .data
            .keys
            .get(&name)
            .map(|record| record.metadata.created_at)
            .unwrap_or(now);
        self.data.keys.insert(
            name.clone(),
            SecretRecord {
                value: value.clone(),
                metadata: SecretMetadata {
                    created_at,
                    updated_at: now,
                    ..secret_metadata(&name, &value, tags)
                },
            },
        );
        self.save()
    }

    pub fn remove_key(&mut self, name: &str) -> Result<bool> {
        let existed = self.data.keys.remove(name).is_some();
        self.save()?;
        Ok(existed)
    }

    pub fn list_secret_metadata(&self) -> Vec<SecretMetadata> {
        self.data
            .keys
            .values()
            .map(|record| record.metadata.clone())
            .collect()
    }

    pub fn secret_metadata(&self, name: &str) -> Result<SecretMetadata> {
        self.data
            .keys
            .get(name)
            .map(|record| record.metadata.clone())
            .ok_or(VaultError::MissingCredential)
    }

    pub fn use_key(&mut self, name: &str) -> Result<String> {
        let record = self
            .data
            .keys
            .get_mut(name)
            .ok_or(VaultError::MissingCredential)?;
        let now = now_unix();
        record.metadata.last_used_at = Some(now);
        record.metadata.updated_at = now;
        let value = record.value.clone();
        self.save()?;
        Ok(value)
    }

    pub fn signing_key(&self) -> Result<SigningKey> {
        let raw = b64d(&self.data.signing_private_key)?;
        let arr: [u8; 32] = raw.try_into().map_err(|_| VaultError::Crypto)?;
        Ok(SigningKey::from_bytes(&arr))
    }

    pub fn issuer_public_key(&self) -> Result<ed25519_dalek::VerifyingKey> {
        Ok(self.signing_key()?.verifying_key())
    }

    pub fn revoke(&mut self, cap_id: uuid::Uuid) -> Result<()> {
        self.data.revoked_capabilities.insert(cap_id);
        self.save()
    }

    pub fn revoked_list(&self) -> Vec<uuid::Uuid> {
        self.data.revoked_capabilities.iter().copied().collect()
    }

    pub fn record_use(&mut self, cap_id: uuid::Uuid, max_uses: Option<u64>) -> Result<u64> {
        let current = *self.data.capability_usage.get(&cap_id).unwrap_or(&0);
        if let Some(max) = max_uses
            && current >= max
        {
            return Err(VaultError::UsageLimitExceeded);
        }
        let next = current + 1;
        self.data.capability_usage.insert(cap_id, next);
        self.save()?;
        Ok(next)
    }

    pub fn save_agent(&mut self, doc: &AgentKeypairDoc, dir: impl AsRef<Path>) -> Result<()> {
        validate_name(&doc.name)?;
        let public = doc.public_view();
        self.upsert_key(
            format!("{AGENT_SECRET_PREFIX}{}", public.agent_id),
            doc.private_key.clone(),
            vec!["agent".to_string(), public.kind.clone()],
        )?;
        self.data.agents.insert(
            public.agent_id.clone(),
            AgentRecord {
                public: public.clone(),
                updated_at: now_unix(),
                revoked: false,
            },
        );
        self.save()?;
        write_public_agent_doc(&public, dir)
    }

    pub fn load_agent(&mut self, agent_id: &str) -> Result<AgentKeypairDoc> {
        let record = self
            .data
            .agents
            .get(agent_id)
            .cloned()
            .ok_or(VaultError::MissingCredential)?;
        if record.revoked || self.data.revoked_agents.contains(agent_id) {
            return Err(VaultError::Revoked);
        }
        let private_key = self.use_key(&format!("{AGENT_SECRET_PREFIX}{agent_id}"))?;
        Ok(AgentKeypairDoc {
            version: record.public.version,
            agent_id: record.public.agent_id.clone(),
            name: record.public.name.clone(),
            kind: record.public.kind.clone(),
            created_at: record.public.created_at,
            updated_at: record.public.updated_at,
            public_key: record.public.public_key,
            private_key,
        })
    }

    pub fn list_agents(&self) -> Vec<AgentPublicDoc> {
        self.data
            .agents
            .values()
            .map(|record| {
                let mut public = record.public.clone();
                public.revoked =
                    record.revoked || self.data.revoked_agents.contains(&public.agent_id);
                public
            })
            .collect()
    }

    pub fn agent_public(&self, agent_id: &str) -> Result<AgentPublicDoc> {
        self.data
            .agents
            .get(agent_id)
            .map(|record| record.public.clone())
            .ok_or(VaultError::MissingCredential)
    }

    pub fn revoke_agent(&mut self, agent_id: &str, dir: impl AsRef<Path>) -> Result<()> {
        let record = self
            .data
            .agents
            .get_mut(agent_id)
            .ok_or(VaultError::MissingCredential)?;
        record.revoked = true;
        let mut public = record.public.clone();
        self.data.revoked_agents.insert(agent_id.to_string());
        self.save()?;
        public.revoked = true;
        write_public_agent_doc(&public, dir)
    }

    /// Store a secret tagged with an environment.  Environment is stored as a tag "env:<env>".
    pub fn set_secret(
        &mut self,
        name: String,
        value: String,
        environment: &str,
        extra_tags: Vec<String>,
    ) -> Result<()> {
        validate_name(&name)?;
        let mut tags = extra_tags;
        let env_tag = format!("env:{environment}");
        if !tags.contains(&env_tag) {
            tags.push(env_tag);
        }
        let now = now_unix();
        let created_at = self
            .data
            .keys
            .get(&name)
            .map(|r| r.metadata.created_at)
            .unwrap_or(now);
        self.data.keys.insert(
            name.clone(),
            SecretRecord {
                value: value.clone(),
                metadata: SecretMetadata {
                    created_at,
                    updated_at: now,
                    ..secret_metadata(&name, &value, tags)
                },
            },
        );
        self.save()
    }

    /// Return all secrets for a given environment (None = all secrets).
    pub fn secrets_for_env(&self, environment: Option<&str>) -> Vec<(&String, &SecretRecord)> {
        self.data
            .keys
            .iter()
            .filter(|(_, r)| match environment {
                None => true,
                Some(env) => r.metadata.tags.iter().any(|t| t == &format!("env:{env}")),
            })
            .collect()
    }

    /// List distinct environment names across all secrets.
    pub fn list_environments(&self) -> Vec<String> {
        let mut envs: std::collections::BTreeSet<String> = self
            .data
            .keys
            .values()
            .flat_map(|r| r.metadata.tags.iter())
            .filter_map(|t| t.strip_prefix("env:").map(str::to_string))
            .collect();
        envs.insert("default".to_string());
        envs.into_iter().collect()
    }

    /// Delete a secret by name.  Returns an error if the name belongs to an internal agent key.
    pub fn delete_secret(&mut self, name: &str) -> Result<bool> {
        if name.starts_with(AGENT_SECRET_PREFIX) {
            return Err(VaultError::InvalidName);
        }
        self.remove_key(name)
    }
}

fn write_public_agent_doc(public: &AgentPublicDoc, dir: impl AsRef<Path>) -> Result<()> {
    let path = dir.as_ref().join(format!("{}.agent.json", public.agent_id));
    write_private_atomic(&path, &serde_json::to_vec_pretty(public)?)
}

pub fn load_agent_public(agent_id: &str, dir: impl AsRef<Path>) -> Result<AgentPublicDoc> {
    let path = dir.as_ref().join(format!("{}.agent.json", agent_id));
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

pub fn public_agent_docs(dir: impl AsRef<Path>) -> Result<Vec<AgentPublicDoc>> {
    let dir = dir.as_ref();
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) == Some("json") {
            let public: AgentPublicDoc = serde_json::from_slice(&fs::read(path)?)?;
            out.push(public);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;

    #[test]
    fn vault_roundtrip_and_no_plaintext_secret() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lockrail");
        let mut vault =
            Vault::init(&path, SecretString::from("pw"), KdfParamsDoc::test_fast()).unwrap();
        vault
            .add_key("openai/demo".into(), "sk-secret-123456789".into())
            .unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("sk-secret-123456789"));
        let mut opened = Vault::open(&path, SecretString::from("pw")).unwrap();
        assert_eq!(
            opened.use_key("openai/demo").unwrap(),
            "sk-secret-123456789"
        );
        assert!(matches!(
            Vault::open(&path, SecretString::from("wrong")).unwrap_err(),
            VaultError::WrongPassword
        ));
    }

    #[test]
    fn agent_private_key_not_written_plaintext_to_agents_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lockrail");
        let agents_dir = tmp.path().join("agents");
        let mut vault =
            Vault::init(&path, SecretString::from("pw"), KdfParamsDoc::test_fast()).unwrap();
        let agent = AgentKeypairDoc::generate("claude", "claude-code");
        let private_key = agent.private_key.clone();
        vault.save_agent(&agent, &agents_dir).unwrap();
        let agent_file = agents_dir.join(format!("{}.agent.json", agent.agent_id));
        let raw = fs::read_to_string(agent_file).unwrap();
        assert!(!raw.contains(&private_key));
        let vault_raw = fs::read_to_string(path).unwrap();
        assert!(!vault_raw.contains(&private_key));
        let loaded = vault.load_agent(&agent.agent_id).unwrap();
        assert_eq!(loaded.private_key, private_key);
    }

    #[test]
    fn debug_output_redacts_secret_values() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lockrail");
        let mut vault =
            Vault::init(&path, SecretString::from("pw"), KdfParamsDoc::test_fast()).unwrap();
        vault
            .add_key("openai/demo".into(), "sk-secret-123456789".into())
            .unwrap();
        let debug = format!("{vault:?}");
        assert!(!debug.contains("sk-secret-123456789"));
        assert!(!debug.contains("pw"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn tampered_vault_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lockrail");
        let mut vault =
            Vault::init(&path, SecretString::from("pw"), KdfParamsDoc::test_fast()).unwrap();
        vault
            .add_key("openai/demo".into(), "sk-secret-123456789".into())
            .unwrap();

        let mut envelope: VaultEnvelope =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        envelope.ciphertext.push('A');
        fs::write(&path, serde_json::to_vec_pretty(&envelope).unwrap()).unwrap();

        assert!(matches!(
            Vault::open(&path, SecretString::from("pw")).unwrap_err(),
            VaultError::WrongPassword | VaultError::Json(_) | VaultError::Crypto
        ));
    }
}
