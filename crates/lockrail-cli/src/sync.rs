#![allow(dead_code)]

use anyhow::{Context, Result, anyhow};
use base64ct::{Base64, Encoding};
use crypto_box::{PublicKey, aead::OsRng};
use lockrail_vault::Vault;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Return the secrets from the vault that belong to the given environment.
///
/// Convention: secrets are tagged with `env:<name>`.  The default environment
/// is stored under the tag `env:default`.  If `environment` is `None` the
/// caller wants `env:default`.
fn secrets_for_env<'a>(vault: &'a Vault, environment: Option<&str>) -> Vec<(&'a str, &'a str)> {
    let env_tag = format!("env:{}", environment.unwrap_or("default"));
    vault
        .data
        .keys
        .iter()
        .filter(|(_, record)| record.metadata.tags.iter().any(|t| t == &env_tag))
        .map(|(name, record)| (name.as_str(), record.value.as_str()))
        .collect()
}

// ---------------------------------------------------------------------------
// GitHub Actions sync
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct GhPublicKey {
    key_id: String,
    key: String,
}

#[derive(Serialize)]
struct GhSecretBody {
    encrypted_value: String,
    key_id: String,
}

/// Sync vault secrets to GitHub Actions repository secrets.
///
/// Uses the X25519 sealed-box encryption required by the GitHub REST API.
/// Returns the number of secrets pushed.
pub async fn sync_github(
    vault: &mut Vault,
    owner: &str,
    repo: &str,
    token: &str,
    environment: Option<&str>,
) -> Result<usize> {
    let client = Client::builder()
        .user_agent("lockrail")
        .build()
        .context("failed to build HTTP client")?;

    // a) Fetch the repo's Actions public key
    let pk_url = format!("https://api.github.com/repos/{owner}/{repo}/actions/secrets/public-key");
    let gh_key: GhPublicKey = client
        .get(&pk_url)
        .bearer_auth(token)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
        .context("GET public key failed")?
        .error_for_status()
        .context("GET public key: non-2xx response")?
        .json()
        .await
        .context("GET public key: JSON decode failed")?;

    // Decode the base64-encoded X25519 public key
    let pk_bytes = Base64::decode_vec(&gh_key.key)
        .map_err(|_| anyhow!("GitHub public key is not valid base64"))?;
    let pk_arr: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| anyhow!("GitHub public key must be exactly 32 bytes"))?;
    let public_key = PublicKey::from(pk_arr);

    // b) Collect and encrypt secrets
    let pairs: Vec<(String, String)> = secrets_for_env(vault, environment)
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let mut count = 0usize;
    for (name, value) in &pairs {
        // Encrypt with X25519 sealed box (crypto_box_seal equivalent)
        let ciphertext = public_key
            .seal(&mut OsRng, value.as_bytes())
            .map_err(|_| anyhow!("encryption failed for secret '{name}'"))?;

        let encrypted_b64 = Base64::encode_string(&ciphertext);

        // c) PUT secret
        let put_url = format!("https://api.github.com/repos/{owner}/{repo}/actions/secrets/{name}");
        let body = GhSecretBody {
            encrypted_value: encrypted_b64,
            key_id: gh_key.key_id.clone(),
        };
        client
            .put(&put_url)
            .bearer_auth(token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&body)
            .send()
            .await
            .with_context(|| format!("PUT secret '{name}' failed"))?
            .error_for_status()
            .with_context(|| format!("PUT secret '{name}': non-2xx response"))?;

        count += 1;
    }

    Ok(count)
}

// ---------------------------------------------------------------------------
// Vercel sync
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct VercelEnvVar {
    id: String,
    key: String,
}

#[derive(Deserialize)]
struct VercelEnvList {
    envs: Vec<VercelEnvVar>,
}

#[derive(Serialize)]
struct VercelEnvBody {
    key: String,
    value: String,
    #[serde(rename = "type")]
    kind: String,
    target: Vec<String>,
}

/// Sync vault secrets to a Vercel project as encrypted env vars.
///
/// Returns the number of secrets pushed.
pub async fn sync_vercel(
    vault: &mut Vault,
    project_id: &str,
    token: &str,
    environment: Option<&str>,
) -> Result<usize> {
    let client = Client::builder()
        .user_agent("lockrail")
        .build()
        .context("failed to build HTTP client")?;

    // a) List existing env vars
    let list_url = format!("https://api.vercel.com/v9/projects/{project_id}/env?limit=100");
    let existing: VercelEnvList = client
        .get(&list_url)
        .bearer_auth(token)
        .send()
        .await
        .context("GET Vercel env list failed")?
        .error_for_status()
        .context("GET Vercel env list: non-2xx response")?
        .json()
        .await
        .context("GET Vercel env list: JSON decode failed")?;

    // Build map of key -> env_id for existing vars
    let existing_map: std::collections::HashMap<String, String> =
        existing.envs.into_iter().map(|v| (v.key, v.id)).collect();

    let pairs: Vec<(String, String)> = secrets_for_env(vault, environment)
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let mut count = 0usize;
    for (name, value) in &pairs {
        // b) Delete existing entry if present
        if let Some(env_id) = existing_map.get(name.as_str()) {
            let del_url = format!("https://api.vercel.com/v9/projects/{project_id}/env/{env_id}");
            client
                .delete(&del_url)
                .bearer_auth(token)
                .send()
                .await
                .with_context(|| format!("DELETE Vercel env '{name}' failed"))?
                .error_for_status()
                .with_context(|| format!("DELETE Vercel env '{name}': non-2xx response"))?;
        }

        // POST the new value
        let post_url = format!("https://api.vercel.com/v10/projects/{project_id}/env");
        let body = VercelEnvBody {
            key: name.clone(),
            value: value.clone(),
            kind: "encrypted".to_string(),
            target: vec![
                "production".to_string(),
                "preview".to_string(),
                "development".to_string(),
            ],
        };
        client
            .post(&post_url)
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("POST Vercel env '{name}' failed"))?
            .error_for_status()
            .with_context(|| format!("POST Vercel env '{name}': non-2xx response"))?;

        count += 1;
    }

    Ok(count)
}

// ---------------------------------------------------------------------------
// Export functions
// ---------------------------------------------------------------------------

/// Export vault secrets for the given environment as a dotenv-formatted string.
pub fn export_dotenv(vault: &Vault, environment: Option<&str>) -> String {
    let mut out = String::new();
    for (name, value) in secrets_for_env(vault, environment) {
        // Escape the value: wrap in double quotes, escaping inner quotes and
        // backslashes so the output is a valid .env file.
        let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
        out.push_str(&format!("{name}=\"{escaped}\"\n"));
    }
    out
}

/// Export vault secrets for the given environment as a JSON object (key → value).
pub fn export_json(vault: &Vault, environment: Option<&str>) -> Value {
    let map: serde_json::Map<String, Value> = secrets_for_env(vault, environment)
        .into_iter()
        .map(|(k, v)| (k.to_string(), Value::String(v.to_string())))
        .collect();
    Value::Object(map)
}

/// Export vault secrets for the given environment as a simple YAML string.
///
/// Format: one `key: value` pair per line.  Values that need quoting (contain
/// `:`, `#`, leading/trailing whitespace, or other YAML-special characters)
/// are wrapped in double quotes.
pub fn export_yaml(vault: &Vault, environment: Option<&str>) -> String {
    let mut out = String::new();
    for (name, value) in secrets_for_env(vault, environment) {
        let needs_quotes = value.contains(':')
            || value.contains('#')
            || value.contains('"')
            || value.contains('\'')
            || value.contains('\n')
            || value.starts_with(' ')
            || value.ends_with(' ')
            || value.is_empty();
        if needs_quotes {
            let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
            out.push_str(&format!("{name}: \"{escaped}\"\n"));
        } else {
            out.push_str(&format!("{name}: {value}\n"));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

/// Parse a dotenv-formatted string into (key, value) pairs.
///
/// Handles:
/// - `KEY=value`
/// - `KEY="value"` (double-quoted, with escape sequences `\\` and `\"`)
/// - `KEY='value'` (single-quoted, no escape processing)
/// - Lines starting with `#` are ignored (comments)
/// - Blank lines are ignored
/// - Inline `#` comments after an unquoted value are stripped
pub fn import_dotenv(text: &str) -> Vec<(String, String)> {
    let mut result = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        // Skip blank lines and comment lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Must contain '='
        let Some(eq_pos) = line.find('=') else {
            continue;
        };
        let key = line[..eq_pos].trim().to_string();
        if key.is_empty() {
            continue;
        }
        let raw_value = line[eq_pos + 1..].trim();

        let value = if raw_value.starts_with('"') {
            // Double-quoted: process escape sequences, stop at closing quote
            parse_double_quoted(raw_value)
        } else if raw_value.starts_with('\'') {
            // Single-quoted: no escape processing
            parse_single_quoted(raw_value)
        } else {
            // Unquoted: strip inline comment
            let v = if let Some(hash_pos) = raw_value.find(" #") {
                raw_value[..hash_pos].trim()
            } else {
                raw_value
            };
            v.to_string()
        };

        result.push((key, value));
    }
    result
}

fn parse_double_quoted(s: &str) -> String {
    // s starts with '"'
    let inner = &s[1..]; // strip leading "
    let mut out = String::new();
    let mut chars = inner.chars();
    loop {
        match chars.next() {
            None | Some('"') => break,
            Some('\\') => match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some(c) => out.push(c),
                None => break,
            },
            Some(c) => out.push(c),
        }
    }
    out
}

fn parse_single_quoted(s: &str) -> String {
    // s starts with '\''
    let inner = &s[1..]; // strip leading '
    // Stop at the closing '
    if let Some(end) = inner.find('\'') {
        inner[..end].to_string()
    } else {
        inner.to_string()
    }
}
