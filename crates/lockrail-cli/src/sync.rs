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

const GITHUB_API: &str = "https://api.github.com";
const VERCEL_API: &str = "https://api.vercel.com";

/// D15: percent-encode one URL path segment (everything except RFC 3986 unreserved
/// characters), so a name such as `a/b?c` cannot change the request path or add a query.
pub fn path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// D15: one-line value escaping for dotenv and YAML double-quoted strings.
fn escape_double_quoted(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

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
    sync_github_at(GITHUB_API, vault, owner, repo, token, environment).await
}

pub(crate) async fn sync_github_at(
    api: &str,
    vault: &mut Vault,
    owner: &str,
    repo: &str,
    token: &str,
    environment: Option<&str>,
) -> Result<usize> {
    let (owner, repo) = (path_segment(owner), path_segment(repo));
    let client = Client::builder()
        .user_agent("lockrail")
        .build()
        .context("failed to build HTTP client")?;

    // a) Fetch the repo's Actions public key
    let pk_url = format!("{api}/repos/{owner}/{repo}/actions/secrets/public-key");
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
        let put_url = format!(
            "{api}/repos/{owner}/{repo}/actions/secrets/{}",
            path_segment(name)
        );
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
    sync_vercel_at(VERCEL_API, vault, project_id, token, environment).await
}

/// D15: one create call per variable with `upsert=true`. 0.3.7 deleted the existing variable
/// and then created it, so a failed create left the project without the variable.
pub(crate) async fn sync_vercel_at(
    api: &str,
    vault: &mut Vault,
    project_id: &str,
    token: &str,
    environment: Option<&str>,
) -> Result<usize> {
    let project_id = path_segment(project_id);
    let client = Client::builder()
        .user_agent("lockrail")
        .build()
        .context("failed to build HTTP client")?;

    let pairs: Vec<(String, String)> = secrets_for_env(vault, environment)
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

    let mut count = 0usize;
    for (name, value) in &pairs {
        let post_url = format!("{api}/v10/projects/{project_id}/env?upsert=true");
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
        let escaped = escape_double_quoted(value);
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
            let escaped = escape_double_quoted(value);
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::extract::{OriginalUri, State};
    use axum::http::StatusCode;
    use axum::routing::any;
    use secrecy::SecretString;
    use std::sync::{Arc, Mutex};

    type Log = Arc<Mutex<Vec<String>>>;

    fn vault_with(secrets: &[(&str, &str)]) -> (tempfile::TempDir, Vault) {
        let tmp = tempfile::tempdir().unwrap();
        let mut vault = Vault::init(
            tmp.path().join("vault.lockrail"),
            SecretString::from("pw"),
            lockrail_vault::KdfParamsDoc::test_fast(),
        )
        .unwrap();
        for (name, value) in secrets {
            vault
                .set_secret(name.to_string(), value.to_string(), "default", vec![])
                .unwrap();
        }
        (tmp, vault)
    }

    async fn serve(fail_post_after: usize) -> (String, Log) {
        let log: Log = Arc::default();
        let app = Router::new()
            .fallback(any(
                |State((log, fail_after)): State<(Log, usize)>,
                 method: axum::http::Method,
                 OriginalUri(uri): OriginalUri| async move {
                    let mut log = log.lock().unwrap();
                    log.push(format!("{method} {uri}"));
                    let posts = log.iter().filter(|l| l.starts_with("POST")).count();
                    if method == axum::http::Method::POST && posts > fail_after {
                        return (StatusCode::INTERNAL_SERVER_ERROR, "boom".to_string());
                    }
                    if uri.path().ends_with("/public-key") {
                        return (
                            StatusCode::OK,
                            serde_json::json!({"key_id": "k1", "key": Base64::encode_string(&[7u8; 32])}).to_string(),
                        );
                    }
                    (StatusCode::OK, "{}".to_string())
                },
            ))
            .with_state((log.clone(), fail_post_after));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{addr}"), log)
    }

    #[tokio::test]
    async fn vercel_failure_never_deletes_the_existing_variable() {
        let (_tmp, mut vault) = vault_with(&[("A_KEY", "one"), ("B_KEY", "two")]);
        let (api, log) = serve(1).await;
        let result = sync_vercel_at(&api, &mut vault, "prj_1", "t", None).await;
        assert!(result.is_err(), "second create should fail");
        let log = log.lock().unwrap();
        assert!(
            log.iter().all(|l| !l.starts_with("DELETE")),
            "a variable was deleted: {log:?}"
        );
        assert!(
            log.iter()
                .all(|l| !l.starts_with("POST") || l.contains("upsert=true")),
            "{log:?}"
        );
    }

    #[tokio::test]
    async fn names_are_percent_encoded_in_paths() {
        let (_tmp, mut vault) = vault_with(&[("a/b?c", "v")]);
        let (api, log) = serve(usize::MAX).await;
        sync_github_at(&api, &mut vault, "own er", "re/po", "t", None)
            .await
            .unwrap();
        let log = log.lock().unwrap();
        assert!(
            log.iter()
                .any(|l| l == "PUT /repos/own%20er/re%2Fpo/actions/secrets/a%2Fb%3Fc"),
            "{log:?}"
        );
    }

    #[test]
    fn dotenv_and_yaml_values_stay_on_one_line() {
        let (_tmp, vault) = vault_with(&[("MULTI", "line1\nline2\r\n\"q\" \\")]);
        let dotenv = export_dotenv(&vault, None);
        assert_eq!(dotenv.lines().count(), 1, "{dotenv}");
        assert_eq!(
            import_dotenv(&dotenv),
            vec![("MULTI".to_string(), "line1\nline2\r\n\"q\" \\".to_string())]
        );
        assert_eq!(export_yaml(&vault, None).lines().count(), 1);
    }
}
