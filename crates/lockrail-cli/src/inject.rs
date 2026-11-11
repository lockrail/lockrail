#![allow(dead_code)]

use anyhow::{Context, Result};
use lockrail_vault::Vault;
use std::collections::BTreeMap;
use std::process::Command;

/// Sanitize a secret name into an environment-variable-safe key.
///
/// Rules:
/// - Uppercase all characters
/// - Replace any character that is not A-Z or 0-9 with `_`
/// - Prepend `SECRET_` if the result starts with a digit
fn sanitize_env_key(name: &str) -> String {
    let mut key: String = name
        .chars()
        .map(|ch| {
            let upper = ch.to_ascii_uppercase();
            if upper.is_ascii_alphanumeric() {
                upper
            } else {
                '_'
            }
        })
        .collect();

    if key.starts_with(|ch: char| ch.is_ascii_digit()) {
        key.insert_str(0, "SECRET_");
    }

    key
}

/// Environment variables a secret may never set in a child process (D18). Overriding them lets a
/// stored "secret" hijack what the child executes or loads (`PATH`, `DYLD_INSERT_LIBRARIES`,
/// `NODE_OPTIONS=--require ...`) instead of just carrying a value.
const RESERVED_ENV_NAMES: &[&str] = &[
    "PATH",
    "HOME",
    "SHELL",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "PWD",
    "IFS",
    "ENV",
    "BASH_ENV",
    "ZDOTDIR",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PYTHONPATH",
    "PYTHONHOME",
    "PYTHONSTARTUP",
    "RUBYOPT",
    "RUBYLIB",
    "PERL5LIB",
    "PERL5OPT",
    "JAVA_TOOL_OPTIONS",
    "GIT_SSH_COMMAND",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
];
const RESERVED_ENV_PREFIXES: &[&str] = &["DYLD_", "LD_", "LOCKRAIL_"];

/// Refuse any env key that would override a reserved variable (case-insensitive, because some
/// tools also honour the lowercase forms such as `https_proxy`).
pub fn check_reserved_env_names<'a>(keys: impl IntoIterator<Item = &'a String>) -> Result<()> {
    for key in keys {
        let upper = key.to_ascii_uppercase();
        if RESERVED_ENV_NAMES.contains(&upper.as_str())
            || RESERVED_ENV_PREFIXES.iter().any(|p| upper.starts_with(p))
        {
            anyhow::bail!(
                "reserved_env_name: refusing to set {key} from a secret; rename the secret"
            );
        }
    }
    Ok(())
}

/// Build a map of env-var-safe key → secret value for all secrets in an environment.
///
/// Secrets are matched by the tag `"env:<environment>"` where `environment` is the
/// provided value, or `"env:default"` when `None` is passed.
///
/// Secret names are uppercased and non-alphanumeric chars are replaced with `_`.
/// Names that start with a digit are prefixed with `SECRET_`.
pub fn build_env_map(vault: &Vault, environment: Option<&str>) -> BTreeMap<String, String> {
    let env_tag = format!("env:{}", environment.unwrap_or("default"));

    vault
        .data
        .keys
        .iter()
        .filter(|(_name, record)| record.metadata.tags.iter().any(|tag| tag == &env_tag))
        .map(|(name, record)| (sanitize_env_key(name), record.value.clone()))
        .collect()
}

/// Spawn a shell (from `$SHELL` env var, falling back to `sh`) with vault secrets injected.
///
/// Blocks until the shell exits. Returns the exit code.
pub fn run_shell(vault: &Vault, environment: Option<&str>) -> Result<i32> {
    #[cfg(windows)]
    let shell = std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_string());
    #[cfg(not(windows))]
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "sh".to_string());
    run_injected(vault, environment, &[shell])
}

/// Run an arbitrary command with vault secrets injected as env vars.
///
/// `command[0]` is the executable; remaining elements are arguments.
/// `LOCKRAIL_PASSWORD` is filtered out of the child environment for safety.
///
/// Returns the exit code (defaults to `1` if the process was killed by a signal).
pub fn run_injected(vault: &Vault, environment: Option<&str>, command: &[String]) -> Result<i32> {
    let executable = command
        .first()
        .context("command must have at least one element")?;

    let env_map = build_env_map(vault, environment);
    check_reserved_env_names(env_map.keys())?;

    let status = Command::new(executable)
        .args(&command[1..])
        .envs(&env_map)
        .env_remove("LOCKRAIL_PASSWORD")
        .status()
        .with_context(|| format!("failed to spawn command: {executable}"))?;

    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_env_names_are_refused() {
        for name in [
            "PATH",
            "path",
            "DYLD_INSERT_LIBRARIES",
            "LD_PRELOAD",
            "NODE_OPTIONS",
            "https_proxy",
            "LOCKRAIL_PASSWORD",
        ] {
            let keys = [name.to_string()];
            let err = check_reserved_env_names(keys.iter()).unwrap_err();
            assert!(err.to_string().contains("reserved_env_name"), "{name}");
        }
        let ok = ["OPENAI_API_KEY".to_string(), "DATABASE_URL".to_string()];
        check_reserved_env_names(ok.iter()).unwrap();
    }

    #[test]
    fn run_injected_refuses_secret_named_path() {
        use lockrail_vault::{KdfParamsDoc, Vault};
        use secrecy::SecretString;
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lockrail");
        let mut vault =
            Vault::init(&path, SecretString::from("pw"), KdfParamsDoc::test_fast()).unwrap();
        vault
            .set_secret("path".into(), "/tmp/evil".into(), "default", vec![])
            .unwrap();
        let err = run_injected(&vault, None, &["true".to_string()]).unwrap_err();
        assert!(err.to_string().contains("reserved_env_name"));
    }

    #[test]
    fn sanitize_basic() {
        assert_eq!(sanitize_env_key("my-secret"), "MY_SECRET");
        assert_eq!(sanitize_env_key("openai/key"), "OPENAI_KEY");
        assert_eq!(sanitize_env_key("API_KEY"), "API_KEY");
    }

    #[test]
    fn sanitize_starts_with_digit() {
        assert_eq!(sanitize_env_key("1secret"), "SECRET_1SECRET");
        assert_eq!(sanitize_env_key("42foo"), "SECRET_42FOO");
    }

    #[test]
    fn sanitize_unicode_and_spaces() {
        assert_eq!(sanitize_env_key("my secret"), "MY_SECRET");
        assert_eq!(sanitize_env_key("héllo"), "H_LLO");
    }

    #[test]
    fn build_env_map_filters_by_env_tag() {
        use lockrail_vault::{KdfParamsDoc, Vault};
        use secrecy::SecretString;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lockrail");
        let mut vault =
            Vault::init(&path, SecretString::from("pw"), KdfParamsDoc::test_fast()).unwrap();

        vault
            .upsert_key(
                "MY_API_KEY".to_string(),
                "secret-value".to_string(),
                vec!["env:production".to_string()],
            )
            .unwrap();
        vault
            .upsert_key(
                "OTHER_KEY".to_string(),
                "other-value".to_string(),
                vec!["env:staging".to_string()],
            )
            .unwrap();

        let map = build_env_map(&vault, Some("production"));
        assert_eq!(map.get("MY_API_KEY"), Some(&"secret-value".to_string()));
        assert!(!map.contains_key("OTHER_KEY"));

        let map_staging = build_env_map(&vault, Some("staging"));
        assert_eq!(
            map_staging.get("OTHER_KEY"),
            Some(&"other-value".to_string())
        );
        assert!(!map_staging.contains_key("MY_API_KEY"));
    }

    #[test]
    fn build_env_map_default_env() {
        use lockrail_vault::{KdfParamsDoc, Vault};
        use secrecy::SecretString;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("vault.lockrail");
        let mut vault =
            Vault::init(&path, SecretString::from("pw"), KdfParamsDoc::test_fast()).unwrap();

        vault
            .upsert_key(
                "DEFAULT_SECRET".to_string(),
                "default-value".to_string(),
                vec!["env:default".to_string()],
            )
            .unwrap();

        let map = build_env_map(&vault, None);
        assert_eq!(
            map.get("DEFAULT_SECRET"),
            Some(&"default-value".to_string())
        );
    }
}
