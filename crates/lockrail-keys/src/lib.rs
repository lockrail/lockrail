//! Key custody (PLAN.md section 3.3, Phase 2A).
//!
//! Keys are split so ordinary operations never prompt:
//! - `fp_key`: HMAC key for handle fingerprints (Phase 3 uses it).
//! - `audit_key`: HMAC key for the v2 event chain.
//! - `device-signing-key`: Ed25519 key that signs event anchors (Phase 7).
//! - `vault-key`: the 0.3.7 vault password, moved out of `~/.lockrail/vault.key` on managed machines.
//!
//! Two stores:
//! - [`Backend::Keychain`]: the macOS login Keychain, one generic-password item per key, with no
//!   presence requirement. Used on managed machines (`org.pub` installed) with the default home.
//! - [`Backend::File`]: `0600` files in a `0700` directory. Used on unmanaged machines, under a
//!   non-default `LOCKRAIL_HOME`, in CI and on Linux. This is the 0.3.7 posture, so an unmanaged
//!   laptop sees no new prompts (an unsigned binary gets a new code identity on every upgrade, and
//!   the Keychain would ask again each time).
//!
//! A debug-only `Backend::Dir` stands in for the Keychain in tests: it lives outside the home, so
//! migration semantics (the key leaves `LOCKRAIL_HOME`) can be exercised without touching the
//! real Keychain.

use anyhow::{Context, Result, anyhow};
use rand_core::RngCore;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const FP_KEY: &str = "fp-key";
pub const AUDIT_KEY: &str = "audit-key";
pub const DEVICE_SIGNING_KEY: &str = "device-signing-key";
pub const VAULT_KEY: &str = "vault-key";

/// Every item name this crate manages. `status` reports presence only, never values.
pub const ITEMS: [&str; 4] = [FP_KEY, AUDIT_KEY, DEVICE_SIGNING_KEY, VAULT_KEY];

const KEYCHAIN_SERVICE: &str = "dev.lockrail";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Backend {
    /// `0600` files under this directory.
    File(PathBuf),
    /// macOS login Keychain; `scope` keeps different homes apart. The Keychain has no create-only
    /// call, so first-use key creation is serialised by a lock file in `lock_dir`.
    Keychain { scope: String, lock_dir: PathBuf },
    /// Test stand-in for the Keychain (debug builds only).
    Dir(PathBuf),
}

impl Backend {
    pub fn name(&self) -> &'static str {
        match self {
            Backend::File(_) => "file",
            Backend::Keychain { .. } => "keychain",
            Backend::Dir(_) => "dir",
        }
    }

    /// True when the store lives outside `LOCKRAIL_HOME`, so a legacy `vault.key` should move.
    pub fn is_external(&self) -> bool {
        !matches!(self, Backend::File(_))
    }
}

/// How the backend was chosen; reported by `keys status` and `doctor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Selection {
    EnvOverride,
    ManagedDefaultHome,
    Unmanaged,
    NonDefaultHome,
    NotMacos,
}

impl Selection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Selection::EnvOverride => "env_override",
            Selection::ManagedDefaultHome => "managed_default_home",
            Selection::Unmanaged => "unmanaged",
            Selection::NonDefaultHome => "non_default_home",
            Selection::NotMacos => "not_macos",
        }
    }
}

/// Choose the store for `home`.
///
/// `LOCKRAIL_KEYSTORE` (`file`, `keychain`, or `dir:<path>` in debug builds) overrides the default.
/// The override cannot widen access: a process that points the CLI at a different store only gets
/// a different, empty set of keys.
pub fn select_backend(
    home: &Path,
    is_default_home: bool,
    managed: bool,
) -> Result<(Backend, Selection)> {
    let file = Backend::File(home.join("keys"));
    if let Ok(value) = std::env::var("LOCKRAIL_KEYSTORE") {
        let value = value.trim();
        return match value {
            "file" => Ok((file, Selection::EnvOverride)),
            "keychain" => {
                if cfg!(target_os = "macos") {
                    Ok((
                        Backend::Keychain {
                            scope: scope_for(home),
                            lock_dir: home.join("keys"),
                        },
                        Selection::EnvOverride,
                    ))
                } else {
                    Err(anyhow!(
                        "LOCKRAIL_KEYSTORE=keychain is only available on macOS"
                    ))
                }
            }
            other if other.starts_with("dir:") && cfg!(debug_assertions) => Ok((
                Backend::Dir(PathBuf::from(&other[4..])),
                Selection::EnvOverride,
            )),
            other => Err(anyhow!("unknown LOCKRAIL_KEYSTORE value: {other}")),
        };
    }
    if !cfg!(target_os = "macos") {
        return Ok((file, Selection::NotMacos));
    }
    if !managed {
        return Ok((file, Selection::Unmanaged));
    }
    if !is_default_home {
        return Ok((file, Selection::NonDefaultHome));
    }
    Ok((
        Backend::Keychain {
            scope: scope_for(home),
            lock_dir: home.join("keys"),
        },
        Selection::ManagedDefaultHome,
    ))
}

fn scope_for(home: &Path) -> String {
    let digest = Sha256::digest(home.to_string_lossy().as_bytes());
    hex::encode(&digest[..8])
}

#[derive(Clone, Debug)]
pub struct KeyStore {
    backend: Backend,
}

impl KeyStore {
    pub fn new(backend: Backend) -> Self {
        Self { backend }
    }

    pub fn backend(&self) -> &Backend {
        &self.backend
    }

    pub fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        check_name(name)?;
        match &self.backend {
            Backend::File(dir) | Backend::Dir(dir) => {
                let path = dir.join(name);
                match fs::read(&path) {
                    Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(e).with_context(|| format!("read key item {name}")),
                }
            }
            Backend::Keychain { scope, .. } => keychain::get(&account(name, scope)),
        }
    }

    pub fn put(&self, name: &str, value: &[u8]) -> Result<()> {
        check_name(name)?;
        match &self.backend {
            Backend::File(dir) | Backend::Dir(dir) => write_private_file(dir, name, value),
            Backend::Keychain { scope, .. } => keychain::set(&account(name, scope), value),
        }
    }

    pub fn delete(&self, name: &str) -> Result<bool> {
        check_name(name)?;
        match &self.backend {
            Backend::File(dir) | Backend::Dir(dir) => match fs::remove_file(dir.join(name)) {
                Ok(()) => Ok(true),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(e) => Err(e).with_context(|| format!("delete key item {name}")),
            },
            Backend::Keychain { scope, .. } => keychain::delete(&account(name, scope)),
        }
    }

    pub fn contains(&self, name: &str) -> Result<bool> {
        Ok(self.get(name)?.is_some())
    }

    /// Fetch a 32-byte random key, creating it on first use. Creation holds a lock so two
    /// processes starting together agree on one key.
    pub fn get_or_create_32(&self, name: &str) -> Result<Zeroizing<[u8; 32]>> {
        if let Some(existing) = self.get(name)? {
            return to_32(name, &existing);
        }
        let _guard = self.creation_lock()?;
        if let Some(existing) = self.get(name)? {
            return to_32(name, &existing);
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        rand_core::OsRng.fill_bytes(bytes.as_mut());
        self.put(name, bytes.as_ref())?;
        Ok(bytes)
    }

    pub fn audit_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        self.get_or_create_32(AUDIT_KEY)
    }

    pub fn fp_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        self.get_or_create_32(FP_KEY)
    }

    pub fn device_signing_key(&self) -> Result<ed25519_dalek::SigningKey> {
        let seed = self.get_or_create_32(DEVICE_SIGNING_KEY)?;
        Ok(ed25519_dalek::SigningKey::from_bytes(&seed))
    }

    /// Presence of each managed item, without reading values into the report.
    pub fn status(&self) -> Result<Vec<(&'static str, bool)>> {
        ITEMS
            .iter()
            .map(|name| Ok((*name, self.contains(name)?)))
            .collect()
    }

    fn creation_lock(&self) -> Result<Option<fs::File>> {
        use fs2::FileExt;
        let dir = match &self.backend {
            Backend::File(dir) | Backend::Dir(dir) | Backend::Keychain { lock_dir: dir, .. } => {
                dir.clone()
            }
        };
        ensure_private_dir(&dir)?;
        let file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(dir.join(".lock"))?;
        file.lock_exclusive()?;
        Ok(Some(file))
    }
}

fn to_32(name: &str, bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("key item {name} has length {}, expected 32", bytes.len()))?;
    Ok(Zeroizing::new(array))
}

fn account(name: &str, scope: &str) -> String {
    format!("{name}@{scope}")
}

fn check_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(anyhow!("invalid key item name"));
    }
    Ok(())
}

fn ensure_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("create key directory {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write `value` to `dir/name` with mode `0600`, atomically (temp file in the same directory,
/// fsync, rename), so a crash never leaves a truncated key.
pub fn write_private_file(dir: &Path, name: &str, value: &[u8]) -> Result<()> {
    ensure_private_dir(dir)?;
    let mut tmp_name = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut tmp_name);
    let tmp = dir.join(format!(".{name}.{}.tmp", hex::encode(tmp_name)));
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&tmp)
            .with_context(|| format!("create key item {name}"))?;
        file.write_all(value)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, dir.join(name)).with_context(|| format!("store key item {name}"))?;
    Ok(())
}

#[cfg(target_os = "macos")]
mod keychain {
    use super::KEYCHAIN_SERVICE;
    use anyhow::{Context, Result};
    use security_framework::passwords::{
        delete_generic_password, get_generic_password, set_generic_password,
    };
    use zeroize::Zeroizing;

    // errSecItemNotFound
    const NOT_FOUND: i32 = -25300;

    pub fn get(account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match get_generic_password(KEYCHAIN_SERVICE, account) {
            Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
            Err(e) if e.code() == NOT_FOUND => Ok(None),
            Err(e) => Err(e).context("read Keychain item"),
        }
    }

    pub fn set(account: &str, value: &[u8]) -> Result<()> {
        set_generic_password(KEYCHAIN_SERVICE, account, value).context("write Keychain item")
    }

    pub fn delete(account: &str) -> Result<bool> {
        match delete_generic_password(KEYCHAIN_SERVICE, account) {
            Ok(()) => Ok(true),
            Err(e) if e.code() == NOT_FOUND => Ok(false),
            Err(e) => Err(e).context("delete Keychain item"),
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod keychain {
    use anyhow::{Result, anyhow};
    use zeroize::Zeroizing;

    pub fn get(_account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Err(anyhow!("the Keychain store is only available on macOS"))
    }

    pub fn set(_account: &str, _value: &[u8]) -> Result<()> {
        Err(anyhow!("the Keychain store is only available on macOS"))
    }

    pub fn delete(_account: &str) -> Result<bool> {
        Err(anyhow!("the Keychain store is only available on macOS"))
    }
}

/// Outcome of moving a legacy `vault.key` into an external store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Migration {
    /// No `vault.key` file: nothing to do.
    NothingToMigrate,
    /// The store is the home's own file store, so the key stays where 0.3.7 expects it.
    StoreIsLocal,
    /// The key now lives only in the external store.
    Migrated,
    /// The store already held the same key; the file was removed.
    AlreadyMigrated,
}

/// Move `<home>/vault.key` into `store` as [`VAULT_KEY`].
///
/// Order is copy, read back and compare, `check` (the caller opens the vault with the stored
/// key), then remove the file. Any failure before removal leaves the file in place, so the vault
/// stays readable by 0.3.7.
pub fn migrate_legacy_vault_key(
    store: &KeyStore,
    legacy_path: &Path,
    check: impl FnOnce(&str) -> Result<()>,
) -> Result<Migration> {
    if !store.backend().is_external() {
        return Ok(Migration::StoreIsLocal);
    }
    let raw = match fs::read_to_string(legacy_path) {
        Ok(text) => Zeroizing::new(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Migration::NothingToMigrate);
        }
        Err(e) => return Err(e).context("read legacy vault.key"),
    };
    let key = raw.trim();
    if key.is_empty() {
        return Err(anyhow!("legacy vault.key is empty; refusing to migrate"));
    }
    let outcome = match store.get(VAULT_KEY)? {
        Some(existing) if existing.as_slice() == key.as_bytes() => Migration::AlreadyMigrated,
        Some(_) => {
            return Err(anyhow!(
                "the key store already holds a different vault key; refusing to overwrite it"
            ));
        }
        None => {
            store.put(VAULT_KEY, key.as_bytes())?;
            Migration::Migrated
        }
    };
    let stored = store
        .get(VAULT_KEY)?
        .ok_or_else(|| anyhow!("vault key not readable after store"))?;
    if stored.as_slice() != key.as_bytes() {
        return Err(anyhow!("vault key read back differs; legacy file kept"));
    }
    check(key)?;
    fs::remove_file(legacy_path).context("remove legacy vault.key")?;
    Ok(outcome)
}

/// Write the stored vault key back to `legacy_path` (mode `0600`) so a 0.3.7 binary can open
/// the vault: the Phase 2 rollback path. Refuses to overwrite an existing file.
pub fn export_legacy_vault_key(store: &KeyStore, legacy_path: &Path) -> Result<()> {
    let key = store
        .get(VAULT_KEY)?
        .ok_or_else(|| anyhow!("no vault key in the key store"))?;
    if legacy_path.exists() {
        return Err(anyhow!(
            "{} already exists; refusing to overwrite it",
            legacy_path.display()
        ));
    }
    let dir = legacy_path
        .parent()
        .ok_or_else(|| anyhow!("vault.key path has no parent"))?;
    let name = legacy_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("vault.key path has no file name"))?;
    let mut line = Zeroizing::new(key.to_vec());
    line.push(b'\n');
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    fs::create_dir_all(dir)?;
    let mut file = options.open(dir.join(name)).context("create vault.key")?;
    file.write_all(&line)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir_store(dir: &Path) -> KeyStore {
        KeyStore::new(Backend::Dir(dir.to_path_buf()))
    }

    #[test]
    fn get_or_create_is_stable_and_private() {
        let tmp = tempfile::tempdir().unwrap();
        let store = KeyStore::new(Backend::File(tmp.path().join("keys")));
        let a = store.audit_key().unwrap();
        let b = store.audit_key().unwrap();
        assert_eq!(a.as_ref(), b.as_ref());
        assert_ne!(store.fp_key().unwrap().as_ref(), a.as_ref());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(tmp.path().join("keys").join(AUDIT_KEY))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
            let dir_mode = fs::metadata(tmp.path().join("keys"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(dir_mode & 0o777, 0o700);
        }
    }

    #[test]
    fn device_key_is_stable() {
        let tmp = tempfile::tempdir().unwrap();
        let store = KeyStore::new(Backend::File(tmp.path().to_path_buf()));
        let a = store.device_signing_key().unwrap().verifying_key();
        let b = store.device_signing_key().unwrap().verifying_key();
        assert_eq!(a, b);
    }

    #[test]
    fn concurrent_creation_agrees_on_one_key() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("keys");
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let dir = dir.clone();
                std::thread::spawn(move || {
                    KeyStore::new(Backend::File(dir))
                        .audit_key()
                        .unwrap()
                        .to_vec()
                })
            })
            .collect();
        let keys: Vec<Vec<u8>> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert!(keys.windows(2).all(|w| w[0] == w[1]));
    }

    #[test]
    fn bad_names_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let store = dir_store(tmp.path());
        for name in ["", "../x", "A", "a/b", "a.b"] {
            assert!(store.get(name).is_err(), "{name:?} accepted");
        }
    }

    #[test]
    fn migration_moves_the_key_and_export_restores_it() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let legacy = home.join("vault.key");
        fs::write(&legacy, "abc123\n").unwrap();
        let store = dir_store(&tmp.path().join("external"));

        let outcome = migrate_legacy_vault_key(&store, &legacy, |k| {
            assert_eq!(k, "abc123");
            Ok(())
        })
        .unwrap();
        assert_eq!(outcome, Migration::Migrated);
        assert!(!legacy.exists());
        assert_eq!(store.get(VAULT_KEY).unwrap().unwrap().as_slice(), b"abc123");

        export_legacy_vault_key(&store, &legacy).unwrap();
        assert_eq!(fs::read_to_string(&legacy).unwrap(), "abc123\n");
        assert!(
            export_legacy_vault_key(&store, &legacy).is_err(),
            "overwrote vault.key"
        );
    }

    #[test]
    fn failed_check_keeps_the_legacy_file() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy = tmp.path().join("vault.key");
        fs::write(&legacy, "abc123\n").unwrap();
        let store = dir_store(&tmp.path().join("external"));
        let result = migrate_legacy_vault_key(&store, &legacy, |_| Err(anyhow!("cannot open")));
        assert!(result.is_err());
        assert!(
            legacy.exists(),
            "legacy key removed although the check failed"
        );
    }

    #[test]
    fn different_stored_key_is_never_overwritten() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy = tmp.path().join("vault.key");
        fs::write(&legacy, "abc123\n").unwrap();
        let store = dir_store(&tmp.path().join("external"));
        store.put(VAULT_KEY, b"other").unwrap();
        assert!(migrate_legacy_vault_key(&store, &legacy, |_| Ok(())).is_err());
        assert!(legacy.exists());
        assert_eq!(store.get(VAULT_KEY).unwrap().unwrap().as_slice(), b"other");
    }

    #[test]
    fn file_store_never_migrates() {
        let tmp = tempfile::tempdir().unwrap();
        let legacy = tmp.path().join("vault.key");
        fs::write(&legacy, "abc123\n").unwrap();
        let store = KeyStore::new(Backend::File(tmp.path().join("keys")));
        assert_eq!(
            migrate_legacy_vault_key(&store, &legacy, |_| Ok(())).unwrap(),
            Migration::StoreIsLocal
        );
        assert!(legacy.exists());
    }

    /// Touches the real login Keychain under a test-only account, then deletes it.
    /// Run by hand: `cargo test -p lockrail-keys -- --ignored keychain_roundtrip`.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore]
    fn keychain_roundtrip() {
        let store = KeyStore::new(Backend::Keychain {
            scope: "lockrail-selftest".into(),
            lock_dir: std::env::temp_dir().join("lockrail-selftest-keys"),
        });
        let _ = store.delete(AUDIT_KEY);
        let key = store.audit_key().unwrap();
        assert_eq!(store.audit_key().unwrap().as_ref(), key.as_ref());
        assert!(store.delete(AUDIT_KEY).unwrap());
        assert!(store.get(AUDIT_KEY).unwrap().is_none());
    }

    /// The Keychain overwrites on `set`, so without a creation lock two processes starting
    /// together could each keep a different key (last writer wins). The lock must exist.
    #[test]
    fn keychain_backend_takes_a_creation_lock() {
        let dir = tempfile::tempdir().unwrap();
        let store = KeyStore::new(Backend::Keychain {
            scope: "t".into(),
            lock_dir: dir.path().join("keys"),
        });
        assert!(store.creation_lock().unwrap().is_some());
    }
}
