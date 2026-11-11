//! `lockrail keys`, `lockrail policy` and `lockrail events` (PLAN.md Phase 2).
//!
//! Key custody, signed org policy and the v2 event chain. Every command here is additive: on an
//! unmanaged machine with no `org.pub`, nothing in this module changes 0.3.7 behaviour.

use crate::{Cli, home, print_value, vault_key_path, vault_path};
use anyhow::{Context, Result, anyhow};
use clap::Subcommand;
use lockrail_audit::events::{Event, EventLog, KeyItem};
use lockrail_keys::{Backend, KeyStore, Migration, Selection, VAULT_KEY, select_backend};
use lockrail_policy::{Paths, Source};
use lockrail_vault::{Vault, default_home};
use secrecy::SecretString;
use std::fs;
use std::path::PathBuf;

#[derive(Subcommand)]
pub enum KeysCommands {
    #[command(about = "Show which key store is in use and which key items exist (never values)")]
    Status,
    #[command(
        about = "Move a legacy vault.key into the key store (managed machines; no-op for the file store)"
    )]
    Migrate,
    #[command(
        about = "Write the vault key back to vault.key so a 0.3.7 binary can open the vault (rollback)"
    )]
    ExportLegacy,
}

#[derive(Subcommand)]
pub enum PolicyCommands {
    #[command(about = "Generate an org signing key; prints the org.pub line to install on laptops")]
    Keygen {
        #[arg(
            long,
            help = "Where to write the private signing key (created with mode 0600)"
        )]
        out: PathBuf,
    },
    #[command(about = "Sign a policy.json; writes <policy>.sig next to it")]
    Sign {
        #[arg(long, help = "Org signing key written by `policy keygen`")]
        key: PathBuf,
        policy: PathBuf,
    },
    #[command(about = "Verify a policy.json and its .sig against an org.pub")]
    Verify {
        #[arg(long = "org-pub", help = "The org.pub file")]
        org_pub: PathBuf,
        policy: PathBuf,
    },
    #[command(about = "Show the effective policy on this machine and where it came from")]
    Show,
}

#[derive(Subcommand)]
pub enum BrokerCommands {
    #[command(about = "Run the broker in the foreground (the LaunchAgent runs this)")]
    Serve,
    #[command(about = "Show whether the broker is running, its presence kind and grant count")]
    Status,
    #[command(about = "Drop every cached grant now")]
    Revoke,
}

#[derive(Subcommand)]
pub enum SealerCommands {
    #[command(about = "Run the sealing proxy (the LaunchDaemon runs this with --launchd)")]
    Serve {
        #[arg(long, default_value = "127.0.0.1:8789")]
        listen: std::net::SocketAddr,
        #[arg(
            long,
            help = "Take the listening socket from launchd (Sockets key `Listeners`)"
        )]
        launchd: bool,
    },
}

#[derive(Subcommand)]
pub enum EventsCommands {
    #[command(about = "Verify the keyed v2 event chain under ~/.lockrail/events")]
    Verify,
}

#[derive(Subcommand)]
pub enum EvidenceCommands {
    #[command(about = "Sign the current event-chain head with the device key (an anchor)")]
    Anchor,
    #[command(
        about = "Build a digest of events since the last one, with unshipped anchors, into the outbox"
    )]
    Digest,
    #[command(
        about = "Ship outbox digests to a sink (dir: a directory; keetrust: the KeeTrust push API)"
    )]
    Ship {
        #[arg(long, value_parser = ["dir", "keetrust"])]
        sink: String,
        #[arg(long, help = "dir sink: target directory")]
        dir: Option<PathBuf>,
        #[arg(long, help = "keetrust: base URL, e.g. https://trust.example.com")]
        url: Option<String>,
        #[arg(long, help = "keetrust: control refs this evidence supports", num_args = 1..)]
        controls: Vec<String>,
    },
    #[command(about = "Verify the local event chain against the anchors that were shipped")]
    Verify {
        #[arg(long, value_parser = ["dir", "keetrust"])]
        sink: String,
        #[arg(long, help = "dir sink: the directory digests were shipped to")]
        dir: Option<PathBuf>,
        #[arg(long, help = "keetrust: base URL")]
        url: Option<String>,
        #[arg(long, help = "keetrust: the push token's name (pushed_by)")]
        token_name: Option<String>,
    },
}

fn is_default_home(cli: &Cli) -> bool {
    match &cli.home {
        None => true,
        Some(path) => *path == default_home(),
    }
}

pub fn key_store(cli: &Cli) -> Result<(KeyStore, Selection)> {
    let managed = Paths::system().is_managed();
    let (backend, selection) = select_backend(&home(cli), is_default_home(cli), managed)?;
    Ok((KeyStore::new(backend), selection))
}

/// The vault key from an external store (Keychain), if one is in use and holds it.
pub fn stored_vault_key(cli: &Cli) -> Result<Option<SecretString>> {
    let (store, _) = key_store(cli)?;
    if !store.backend().is_external() {
        return Ok(None);
    }
    match store.get(VAULT_KEY)? {
        Some(bytes) => {
            let text = String::from_utf8(bytes.to_vec())
                .map_err(|_| anyhow!("stored vault key is not UTF-8"))?;
            Ok(Some(SecretString::from(text)))
        }
        None => Ok(None),
    }
}

/// Create the vault key in the external store when one is in use (new installs on managed
/// machines never write `vault.key`). `None` means: use the 0.3.7 file path.
pub fn create_stored_vault_key(cli: &Cli, generated: &str) -> Result<Option<SecretString>> {
    let (store, _) = key_store(cli)?;
    if !store.backend().is_external() {
        return Ok(None);
    }
    store.put(VAULT_KEY, generated.as_bytes())?;
    Ok(Some(SecretString::from(generated.to_string())))
}

pub fn store_has_vault_key(cli: &Cli) -> bool {
    matches!(stored_vault_key(cli), Ok(Some(_)))
}

/// The handle key (Phase 3D). Personal mode keeps it in the key store; on managed machines the
/// sealer will serve HMACs over its socket instead (Phase 5), and this path is the fallback.
pub fn fp_key(cli: &Cli) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    let (store, _) = key_store(cli)?;
    store.fp_key()
}

pub(crate) fn events_log(cli: &Cli) -> EventLog {
    EventLog::new(home(cli).join("events"))
}

/// Append events to the v2 chain. A failure to record is reported on stderr and does not fail
/// the command: evidence problems must never stop an engineer's work (M5).
pub fn emit(cli: &Cli, events: &[Event]) {
    if events.is_empty() {
        return;
    }
    let result = (|| -> Result<()> {
        let (store, _) = key_store(cli)?;
        let audit_key = store.audit_key()?;
        let log = events_log(cli);
        for event in events {
            log.append(&audit_key, event.clone())?;
        }
        Ok(())
    })();
    if let Err(error) = result
        && !cli.quiet
    {
        eprintln!("lockrail: could not record event: {error:#}");
    }
}

fn backend_location(backend: &Backend) -> serde_json::Value {
    match backend {
        Backend::File(dir) | Backend::Dir(dir) => serde_json::json!(dir),
        Backend::Keychain { scope, .. } => serde_json::json!(format!(
            "login Keychain, service dev.lockrail, scope {scope}"
        )),
    }
}

pub fn run_keys(cli: &Cli, command: &KeysCommands) -> Result<()> {
    let (store, selection) = key_store(cli)?;
    match command {
        KeysCommands::Status => {
            let items: serde_json::Map<String, serde_json::Value> = store
                .status()?
                .into_iter()
                .map(|(name, present)| (name.to_string(), serde_json::json!(present)))
                .collect();
            print_value(
                cli,
                &serde_json::json!({
                    "backend": store.backend().name(),
                    "selected_because": selection.as_str(),
                    "location": backend_location(store.backend()),
                    "items": items,
                    "legacy_vault_key_file": vault_key_path(cli).exists(),
                }),
            )
        }
        KeysCommands::Migrate => {
            let outcome = migrate(cli, &store)?;
            print_value(
                cli,
                &serde_json::json!({
                    "backend": store.backend().name(),
                    "outcome": migration_name(&outcome),
                    "legacy_vault_key_file": vault_key_path(cli).exists(),
                }),
            )
        }
        KeysCommands::ExportLegacy => {
            // Writes the vault key in plaintext: always-presence, like `secret export`.
            require_presence(
                cli,
                "write the vault key back to vault.key (rollback to 0.3.7)",
            )?;
            lockrail_keys::export_legacy_vault_key(&store, &vault_key_path(cli))?;
            emit(
                cli,
                &[Event::KeyExportedLegacy {
                    item: KeyItem::VaultKey,
                }],
            );
            print_value(
                cli,
                &serde_json::json!({
                    "written": vault_key_path(cli),
                    "note": "0.3.7 reads this file; the key store copy is kept",
                }),
            )
        }
    }
}

/// Move the legacy key (verifying the vault opens with it first) and record the event.
fn migrate(cli: &Cli, store: &KeyStore) -> Result<Migration> {
    let vault = vault_path(cli);
    let outcome = lockrail_keys::migrate_legacy_vault_key(store, &vault_key_path(cli), |key| {
        if vault.exists() {
            Vault::open(&vault, SecretString::from(key.to_string()))
                .context("the vault does not open with the legacy key; nothing moved")?;
        }
        Ok(())
    })?;
    if outcome == Migration::Migrated || outcome == Migration::AlreadyMigrated {
        emit(
            cli,
            &[Event::KeyMigrated {
                item: KeyItem::VaultKey,
            }],
        );
    }
    Ok(outcome)
}

fn migration_name(outcome: &Migration) -> &'static str {
    match outcome {
        Migration::NothingToMigrate => "nothing_to_migrate",
        Migration::StoreIsLocal => "store_is_local",
        Migration::Migrated => "migrated",
        Migration::AlreadyMigrated => "already_migrated",
    }
}

/// Run on `setup` and on any command that needs the vault: a managed machine moves its legacy
/// key once. Unmanaged machines are untouched.
pub fn auto_migrate(cli: &Cli) -> Result<()> {
    let (store, _) = key_store(cli)?;
    if !store.backend().is_external() || !vault_key_path(cli).exists() {
        return Ok(());
    }
    migrate(cli, &store).map(|_| ())
}

pub fn run_policy(cli: &Cli, command: &PolicyCommands) -> Result<()> {
    match command {
        PolicyCommands::Keygen { out } => {
            if out.exists() {
                return Err(anyhow!(
                    "{} already exists; refusing to overwrite it",
                    out.display()
                ));
            }
            let key = lockrail_policy::generate_org_key();
            let dir = out
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            let name = out
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| anyhow!("--out needs a file name"))?;
            lockrail_keys::write_private_file(
                &dir,
                name,
                lockrail_policy::encode_signing_key(&key).as_bytes(),
            )?;
            print_value(
                cli,
                &serde_json::json!({
                    "signing_key_written": out,
                    "org_pub": lockrail_policy::encode_public_key(&key.verifying_key()),
                    "install": "write the org_pub value to /Library/Application Support/Lockrail/org.pub (root-owned) on each managed laptop",
                }),
            )
        }
        PolicyCommands::Sign { key, policy } => {
            let key_text =
                fs::read_to_string(key).with_context(|| format!("read {}", key.display()))?;
            let signing = lockrail_policy::decode_signing_key(&key_text)?;
            let bytes = fs::read(policy).with_context(|| format!("read {}", policy.display()))?;
            let sig = lockrail_policy::sign(&bytes, &signing)?;
            let sig_path = sig_path_for(policy);
            fs::write(&sig_path, format!("{sig}\n"))?;
            let parsed = lockrail_policy::parse(&bytes)?;
            print_value(
                cli,
                &serde_json::json!({"signed": policy, "signature": sig_path, "version": parsed.version}),
            )
        }
        PolicyCommands::Verify { org_pub, policy } => {
            let org = lockrail_policy::decode_public_key(&fs::read_to_string(org_pub)?)?;
            let bytes = fs::read(policy)?;
            let sig = fs::read_to_string(sig_path_for(policy)).context("read the .sig file")?;
            match lockrail_policy::verify(&bytes, &sig, &org) {
                Ok(parsed) => print_value(
                    cli,
                    &serde_json::json!({"ok": true, "version": parsed.version, "org": parsed.org}),
                ),
                Err(reason) => {
                    print_value(cli, &serde_json::json!({"ok": false, "reason": reason}))?;
                    std::process::exit(1);
                }
            }
        }
        PolicyCommands::Show => {
            let (effective, events) = lockrail_policy::evaluate(&Paths::system());
            emit(cli, &events);
            let source = match effective.source {
                Source::Personal => "personal",
                Source::Signed { .. } => "signed",
                Source::LastKnownGood { .. } => "last_known_good",
                Source::ManagedDefault => "managed_default",
            };
            print_value(
                cli,
                &serde_json::json!({
                    "managed": effective.managed,
                    "source": source,
                    "version": effective.policy.version,
                    "phi_mode": effective.policy.phi_mode,
                    "fail_mode": effective.policy.fail_mode,
                    "enabled": effective.policy.enabled,
                    "highest_accepted": effective.highest_accepted,
                    "state_writable": effective.state_writable,
                    "events": events,
                    "policy": effective.policy,
                }),
            )
        }
    }
}

fn sig_path_for(policy: &std::path::Path) -> PathBuf {
    let mut name = policy.as_os_str().to_owned();
    name.push(".sig");
    PathBuf::from(name)
}

pub fn run_events(cli: &Cli, command: &EventsCommands) -> Result<()> {
    match command {
        EventsCommands::Verify => {
            let (store, _) = key_store(cli)?;
            let audit_key = store.audit_key()?;
            let report = events_log(cli).verify(&audit_key)?;
            let ok = report.ok();
            print_value(cli, &serde_json::to_value(&report)?)?;
            if !ok {
                std::process::exit(1);
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Broker, presence and grants (Phase 4; D4, R-11, M4)
// ---------------------------------------------------------------------------------------------

/// On a managed machine the broker socket is always the user's default `~/.lockrail/broker.sock`:
/// `--home` / `LOCKRAIL_HOME` cannot point the CLI at a socket of the caller's choosing. The
/// answering process is also verified to be lockrail itself (`lockrail_broker::server::call`).
pub fn broker_socket(cli: &Cli) -> PathBuf {
    if Paths::system().is_managed() {
        return crate::default_home().join("broker.sock");
    }
    home(cli).join("broker.sock")
}

/// Grants and presence apply on a managed machine, or once the user runs the broker. An
/// unmanaged machine without a broker keeps 0.3.7 behaviour (I-4).
fn gating(cli: &Cli) -> Gating {
    let socket = broker_socket(cli);
    if socket.exists() {
        Gating::Broker(socket)
    } else if Paths::system().is_managed() {
        Gating::RequiredButAbsent
    } else {
        Gating::Off
    }
}

enum Gating {
    Off,
    Broker(PathBuf),
    RequiredButAbsent,
}

fn broker_call(socket: &std::path::Path, request: &lockrail_broker::server::Request) -> Result<()> {
    let response = lockrail_broker::server::call(socket, request)
        .map_err(|e| anyhow!("broker_unavailable: {e}"))?;
    if response.ok {
        Ok(())
    } else {
        Err(anyhow!(
            "{}",
            response.error.unwrap_or_else(|| "grant_required".into())
        ))
    }
}

/// R-11: resolving secrets into a command needs a grant for that command's fingerprint. The
/// broker computes the fingerprint itself and asks for presence on first use.
pub fn authorize_command(
    cli: &Cli,
    argv: &[String],
    env_file: Option<&std::path::Path>,
) -> Result<()> {
    match gating(cli) {
        Gating::Off => Ok(()),
        Gating::RequiredButAbsent => Err(anyhow!(
            "broker_unavailable: this machine is managed and the Lockrail broker is not running"
        )),
        Gating::Broker(socket) => broker_call(
            &socket,
            &lockrail_broker::server::Request::Authorize {
                argv: argv.to_vec(),
                cwd: std::env::current_dir()?,
                path: std::env::var("PATH").unwrap_or_default(),
                env_file: env_file.map(|p| p.canonicalize().unwrap_or_else(|_| p.to_path_buf())),
            },
        ),
    }
}

/// Always-presence operations (`secret export`, `shell`, `proxy install-ca`): never cached.
pub fn require_presence(cli: &Cli, reason: &str) -> Result<()> {
    match gating(cli) {
        Gating::Off => Ok(()),
        Gating::RequiredButAbsent => Err(anyhow!(
            "broker_unavailable: this machine is managed and the Lockrail broker is not running"
        )),
        Gating::Broker(socket) => broker_call(
            &socket,
            &lockrail_broker::server::Request::Presence {
                reason: reason.to_string(),
            },
        ),
    }
}

pub fn run_broker(cli: &Cli, command: &BrokerCommands) -> Result<()> {
    use lockrail_broker::server::{self, Broker, Request};
    let socket = broker_socket(cli);
    match command {
        BrokerCommands::Serve => {
            let presence = lockrail_broker::presence::system();
            let kind = presence.kind();
            let listener = server::bind(&socket)?;
            print_value(
                cli,
                &serde_json::json!({"status": "serving", "socket": socket, "presence": kind}),
            )?;
            server::serve(listener, std::sync::Arc::new(Broker::new(presence)))
        }
        BrokerCommands::Status => match server::call(&socket, &Request::Status) {
            Ok(response) => print_value(cli, &serde_json::to_value(response)?),
            Err(_) => print_value(
                cli,
                &serde_json::json!({"ok": false, "running": false, "socket": socket}),
            ),
        },
        BrokerCommands::Revoke => {
            let response = server::call(&socket, &Request::Revoke)
                .map_err(|e| anyhow!("broker_unavailable: {e}"))?;
            print_value(cli, &serde_json::to_value(response)?)
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Sealer (Phase 5)
// ---------------------------------------------------------------------------------------------

/// One sealing config per host the sealer opens. Built from `SEALER_MITM_HOSTS` itself: a host
/// on that list without a config would be opened and then blind-tunnelled, unsealed (the bug
/// this replaced: nine hosts were listed but only three configured). A BAA is recorded only for
/// the Anthropic (Claude Code) and OpenAI (Codex) policies; every other provider has none, so
/// PHI is withheld there.
fn sealer_configs(
    policy: &lockrail_policy::Policy,
    fp_key: [u8; 32],
) -> Vec<(String, std::sync::Arc<lockrail_proxy::sealer::SealerConfig>)> {
    lockrail_proxy::sealer::SEALER_MITM_HOSTS
        .iter()
        .map(|host| {
            let baa = match *host {
                "api.anthropic.com" => policy.tools.claude_code.baa,
                "chatgpt.com" | "api.openai.com" => policy.tools.codex.baa,
                _ => false,
            };
            (
                (*host).to_string(),
                std::sync::Arc::new(sealer_config(policy, baa, fp_key)),
            )
        })
        .collect()
}

fn sealer_config(
    policy: &lockrail_policy::Policy,
    baa: bool,
    fp_key: [u8; 32],
) -> lockrail_proxy::sealer::SealerConfig {
    use lockrail_proxy::sealer::{FailMode, PhiMode, SealerConfig};
    SealerConfig {
        enabled: policy.enabled,
        fp_key,
        phi_mode: match policy.phi_mode {
            lockrail_policy::PhiMode::Off => PhiMode::Off,
            lockrail_policy::PhiMode::Warn => PhiMode::Warn,
            lockrail_policy::PhiMode::Block | lockrail_policy::PhiMode::Seal => PhiMode::Block,
        },
        baa,
        phi_block_request: policy.phi_block_scope == lockrail_policy::PhiBlockScope::Request,
        fail_mode: match policy.fail_mode {
            lockrail_policy::FailMode::Open => FailMode::Open,
            lockrail_policy::FailMode::Closed => FailMode::Closed,
        },
        deadline: std::time::Duration::from_millis(u64::from(policy.scan_deadline_ms)),
    }
}

pub async fn run_sealer(cli: &Cli, command: &SealerCommands) -> Result<()> {
    use lockrail_audit::events::SealerHost;
    use lockrail_proxy::sealer::{Memo, Report};
    use lockrail_proxy::sealer_server::{SealerServer, platform_client_config, serve};
    use std::sync::Arc;
    let SealerCommands::Serve { listen, launchd } = command;
    if !listen.ip().is_loopback() {
        return Err(anyhow!("the sealer only listens on loopback"));
    }
    let (effective, events) = lockrail_policy::evaluate(&Paths::system());
    emit(cli, &events);
    let policy = effective.policy;
    let fp_key = *fp_key(cli)?;
    let ca = lockrail_proxy::CaStore::load(&crate::ca_path(cli))
        .map_err(|_| anyhow!("no CA: run `lockrail proxy install-ca` first"))?;
    let resolver = Arc::new(lockrail_proxy::ca::DynamicCertResolver::new(Arc::new(
        lockrail_proxy::LocalCa::new(ca),
    )));
    let configs = sealer_configs(&policy, fp_key);
    let (store, _) = key_store(cli)?;
    let audit_key = *store.audit_key()?;
    let log = Arc::new(events_log(cli));
    let reports: lockrail_proxy::sealer_relay::ReportSink =
        Arc::new(move |host: &str, r: &Report| {
            let host = SealerHost::from_host(host);
            let n = |v: usize| u32::try_from(v).unwrap_or(u32::MAX);
            let mut out = Vec::new();
            if r.blocked {
                out.push(Event::SealerBlocked { host });
            }
            if r.deadline_exceeded {
                out.push(Event::SealerDeadlineExceeded { host });
            }
            if r.fail_open {
                out.push(Event::SealerFailOpen { host });
            }
            if r.secrets_sealed + r.phi_withheld + r.phi_sealed + r.images_withheld > 0 {
                out.push(Event::SealerRequest {
                    host,
                    secrets_sealed: n(r.secrets_sealed),
                    phi_withheld: n(r.phi_withheld),
                    phi_sealed: n(r.phi_sealed),
                    images_withheld: n(r.images_withheld),
                    handles: r.handles.clone(),
                });
            }
            for e in out {
                let _ = log.append(&audit_key, e);
            }
        });
    let server = Arc::new(SealerServer {
        resolver,
        configs,
        memo: Arc::new(Memo::new(64 << 20)),
        reports: Some(reports),
        upstream_tls: Arc::new(platform_client_config()?),
        health_key: fp_key,
    });
    let listener = if *launchd {
        launchd_listener()?
    } else {
        tokio::net::TcpListener::bind(listen).await?
    };
    print_value(
        cli,
        &serde_json::json!({
            "status": "sealing",
            "listen": listener.local_addr()?.to_string(),
            "enabled": policy.enabled,
            "phi_mode": policy.phi_mode,
            "fail_mode": policy.fail_mode,
            "mitm_hosts": lockrail_proxy::sealer::SEALER_MITM_HOSTS,
            "pass_list_version": lockrail_proxy::sealer::PASS_LIST_VERSION,
        }),
    )?;
    serve(listener, server).await
}

#[cfg(target_os = "macos")]
fn launchd_listener() -> Result<tokio::net::TcpListener> {
    Ok(tokio::net::TcpListener::from_std(
        lockrail_proxy::sealer_server::launchd_listener("Listeners")?,
    )?)
}

#[cfg(not(target_os = "macos"))]
fn launchd_listener() -> Result<tokio::net::TcpListener> {
    Err(anyhow!("--launchd is macOS only"))
}

// ---------------------------------------------------------------------------------------------
// Evidence (Phase 7)
// ---------------------------------------------------------------------------------------------

fn evidence_dirs(cli: &Cli) -> (PathBuf, PathBuf, PathBuf) {
    let h = home(cli);
    (
        h.join("events").join("anchors.jsonl"),
        h.join("outbox"),
        h.join("shipped"),
    )
}

fn shipped_state(shipped: &std::path::Path) -> (u64, usize) {
    // (next from_seq, anchors already shipped)
    let text = fs::read_to_string(shipped.join("state.json")).unwrap_or_default();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
    (
        v["next_seq"].as_u64().unwrap_or(0),
        v["anchors_shipped"].as_u64().unwrap_or(0) as usize,
    )
}

fn write_json_private(path: &std::path::Path, value: &serde_json::Value) -> Result<()> {
    let dir = path.parent().ok_or_else(|| anyhow!("no parent"))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("no name"))?;
    lockrail_keys::write_private_file(dir, name, serde_json::to_vec_pretty(value)?.as_slice())
}

pub async fn run_evidence(cli: &Cli, command: &EvidenceCommands) -> Result<()> {
    use lockrail_audit::evidence::{self, Digest, KeeTrustPush};
    let (store, _) = key_store(cli)?;
    let audit_key = *store.audit_key()?;
    let device = store.device_signing_key()?;
    let log = events_log(cli);
    let (anchors_path, outbox, shipped) = evidence_dirs(cli);
    match command {
        EvidenceCommands::Anchor => {
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            match evidence::anchor_now(&log, &audit_key, &device, now)? {
                Some(anchor) => {
                    evidence::append_anchor(&anchors_path, &anchor)?;
                    print_value(
                        cli,
                        &serde_json::json!({"anchored_through_seq": anchor.through_seq}),
                    )
                }
                None => print_value(cli, &serde_json::json!({"anchored_through_seq": null})),
            }
        }
        EvidenceCommands::Digest => {
            let (next_seq, anchors_shipped) = shipped_state(&shipped);
            let anchors = evidence::read_anchors(&anchors_path)?;
            let fresh: Vec<_> = anchors.into_iter().skip(anchors_shipped).collect();
            let records = log.read_all()?;
            let digest = evidence::build_digest(&records, next_seq, fresh, &device.verifying_key());
            if digest.counts.is_empty() && digest.anchors.is_empty() {
                return print_value(cli, &serde_json::json!({"digest": null}));
            }
            let name = format!("{:012}-{:012}.json", digest.from_seq, digest.through_seq);
            write_json_private(&outbox.join(&name), &serde_json::to_value(&digest)?)?;
            let state = serde_json::json!({
                "next_seq": digest.through_seq + 1,
                "anchors_shipped": anchors_shipped + digest.anchors.len(),
            });
            write_json_private(&shipped.join("state.json"), &state)?;
            print_value(
                cli,
                &serde_json::json!({"digest": name, "anchors": digest.anchors.len()}),
            )
        }
        EvidenceCommands::Ship {
            sink,
            dir,
            url,
            controls,
        } => {
            let mut items: Vec<PathBuf> = match fs::read_dir(&outbox) {
                Ok(rd) => rd
                    .flatten()
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|e| e == "json"))
                    .collect(),
                Err(_) => vec![],
            };
            items.sort();
            let mut delivered = Vec::new();
            for item in items {
                let digest: Digest = serde_json::from_slice(&fs::read(&item)?)?;
                let name = item
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("digest.json")
                    .to_string();
                match sink.as_str() {
                    "dir" => {
                        let target = dir
                            .as_ref()
                            .ok_or_else(|| anyhow!("--dir is required for the dir sink"))?;
                        fs::create_dir_all(target)?;
                        fs::copy(&item, target.join(&name))?;
                    }
                    _ => {
                        let base = url
                            .as_ref()
                            .ok_or_else(|| anyhow!("--url is required for the keetrust sink"))?;
                        if controls.is_empty() {
                            return Err(anyhow!("--controls is required for the keetrust sink"));
                        }
                        let token = std::env::var("LOCKRAIL_KEETRUST_TOKEN").map_err(|_| {
                            anyhow!("set LOCKRAIL_KEETRUST_TOKEN (scope trust:evidence:write)")
                        })?;
                        let push = KeeTrustPush::from_digest(&digest, controls);
                        let response = reqwest::Client::new()
                            .post(format!(
                                "{}/api/v1/evidence/push",
                                base.trim_end_matches('/')
                            ))
                            .bearer_auth(token)
                            .json(&push.request_json())
                            .send()
                            .await?;
                        let status = response.status().as_u16();
                        let body: serde_json::Value = response.json().await.unwrap_or_default();
                        // T7: KeeTrust answers 201 even when it redacted something; that is a failure.
                        if status != 201 || body["redactions"].as_u64() != Some(0) {
                            return Err(anyhow!(
                                "keetrust_push_failed: status {status}, redactions {}; digest kept in the outbox",
                                body["redactions"]
                            ));
                        }
                        // T8: keep the exact payload the hash covers.
                        let kept = serde_json::json!({
                            "request": push.request_json(),
                            "sha256": body["sha256"],
                            "evidence_id": body["evidence_id"],
                        });
                        write_json_private(&shipped.join(format!("keetrust-{name}")), &kept)?;
                    }
                }
                fs::create_dir_all(&shipped)?;
                fs::rename(&item, shipped.join(&name))?;
                delivered.push(name);
            }
            print_value(cli, &serde_json::json!({"shipped": delivered}))
        }
        EvidenceCommands::Verify {
            sink,
            dir,
            url,
            token_name,
        } => {
            let mut anchors = Vec::new();
            let mut hash_problems = Vec::new();
            match sink.as_str() {
                "dir" => {
                    let target = dir
                        .as_ref()
                        .ok_or_else(|| anyhow!("--dir is required for the dir sink"))?;
                    for entry in fs::read_dir(target)?.flatten() {
                        if let Ok(d) = serde_json::from_slice::<Digest>(&fs::read(entry.path())?) {
                            anchors.extend(d.anchors);
                        }
                    }
                }
                _ => {
                    let base = url.as_ref().ok_or_else(|| anyhow!("--url is required"))?;
                    let token_name = token_name
                        .as_ref()
                        .ok_or_else(|| anyhow!("--token-name is required"))?;
                    let token = std::env::var("LOCKRAIL_KEETRUST_READ_TOKEN").map_err(|_| {
                        anyhow!("set LOCKRAIL_KEETRUST_READ_TOKEN (scope read:evidence)")
                    })?;
                    let listed: serde_json::Value = reqwest::Client::new()
                        .get(format!("{}/api/v1/evidence", base.trim_end_matches('/')))
                        .bearer_auth(token)
                        .send()
                        .await?
                        .json()
                        .await?;
                    let hashes: Vec<String> = listed
                        .as_array()
                        .or_else(|| listed["items"].as_array())
                        .into_iter()
                        .flatten()
                        .filter_map(|e| e["sha256"].as_str().map(str::to_string))
                        .collect();
                    for entry in fs::read_dir(&shipped)?.flatten() {
                        let fname = entry.file_name().to_string_lossy().to_string();
                        if !fname.starts_with("keetrust-") {
                            continue;
                        }
                        let kept: serde_json::Value =
                            serde_json::from_slice(&fs::read(entry.path())?)?;
                        let request = &kept["request"];
                        let push = KeeTrustPush {
                            controls: serde_json::from_value(request["controls"].clone())?,
                            title: request["title"].as_str().unwrap_or_default().to_string(),
                            description: request["description"].as_str().map(str::to_string),
                            source: request["source"].as_str().unwrap_or_default().to_string(),
                            data: request["data"].clone(),
                            valid_days: request["valid_days"].as_u64().unwrap_or(90) as u32,
                        };
                        if !hashes.contains(&push.expected_sha256(token_name)) {
                            hash_problems.push(serde_json::json!({"problem": "shipped_hash_mismatch", "file": fname}));
                        } else if let Ok(d) = serde_json::from_value::<Digest>(push.data.clone()) {
                            anchors.extend(d.anchors);
                        }
                    }
                }
            }
            let report = evidence::verify_against_anchors(
                &log,
                &audit_key,
                &device.verifying_key(),
                &anchors,
            )?;
            let ok = report.ok && hash_problems.is_empty();
            print_value(
                cli,
                &serde_json::json!({"ok": ok, "chain": report, "shipped_hash_problems": hash_problems}),
            )?;
            if !ok {
                std::process::exit(1);
            }
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Proof pack signature (D17)
// ---------------------------------------------------------------------------------------------

fn sig_path(pack: &std::path::Path) -> PathBuf {
    let mut name = pack.as_os_str().to_owned();
    name.push(".sig.json");
    PathBuf::from(name)
}

/// Write `<pack>.sig.json`: sha256 of the pack bytes, the device public key and an Ed25519
/// signature over `lockrail-proof-v1\n<sha256>`.
pub fn sign_proof_pack(cli: &Cli, pack: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use base64ct::{Base64, Encoding};
    use ed25519_dalek::Signer;
    use sha2::{Digest, Sha256};
    let (store, _) = key_store(cli)?;
    let device = store.device_signing_key()?;
    let sha = hex::encode(Sha256::digest(bytes));
    let sig = device.sign(format!("lockrail-proof-v1\n{sha}").as_bytes());
    let doc = serde_json::json!({
        "v": 1,
        "sha256": sha,
        "device_pub_b64": Base64::encode_string(device.verifying_key().as_bytes()),
        "sig_b64": Base64::encode_string(&sig.to_bytes()),
    });
    fs::write(sig_path(pack), serde_json::to_vec_pretty(&doc)?)?;
    Ok(())
}

/// Check the pack against its signature file and against a key we trust. The key inside the
/// `.sig.json` only proves the pack matches *some* signer, so `ok` also requires that signer to be
/// `trusted_pub` (base64), or this laptop's device key when none is given.
pub fn verify_proof_pack(
    cli: &Cli,
    pack: &std::path::Path,
    trusted_pub: Option<&str>,
) -> Result<serde_json::Value> {
    use base64ct::{Base64, Encoding};
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use sha2::{Digest, Sha256};
    let bytes = fs::read(pack).with_context(|| format!("read {}", pack.display()))?;
    let doc: serde_json::Value = serde_json::from_slice(
        &fs::read(sig_path(pack)).context("the pack has no .sig.json; it is unsigned")?,
    )?;
    let sha = hex::encode(Sha256::digest(&bytes));
    let fail = |reason: &str| Ok(serde_json::json!({"ok": false, "reason": reason}));
    if doc["sha256"].as_str() != Some(sha.as_str()) {
        return fail("pack_changed");
    }
    let Ok(pub_bytes) = Base64::decode_vec(doc["device_pub_b64"].as_str().unwrap_or_default())
    else {
        return fail("bad_public_key");
    };
    let Ok(array) = <[u8; 32]>::try_from(pub_bytes.as_slice()) else {
        return fail("bad_public_key");
    };
    let Ok(key) = VerifyingKey::from_bytes(&array) else {
        return fail("bad_public_key");
    };
    let Ok(sig) = Base64::decode_vec(doc["sig_b64"].as_str().unwrap_or_default()) else {
        return fail("bad_signature");
    };
    let Ok(sig) = Signature::from_slice(&sig) else {
        return fail("bad_signature");
    };
    if key
        .verify(format!("lockrail-proof-v1\n{sha}").as_bytes(), &sig)
        .is_err()
    {
        return fail("signature_mismatch");
    }
    let trusted = match trusted_pub {
        Some(p) => p.trim().to_string(),
        None => match key_store(cli).and_then(|(s, _)| s.device_signing_key()) {
            Ok(k) => Base64::encode_string(k.verifying_key().as_bytes()),
            Err(_) => return fail("unverified_signer"),
        },
    };
    if doc["device_pub_b64"].as_str() != Some(trusted.as_str()) {
        return fail("untrusted_signer");
    }
    Ok(serde_json::json!({"ok": true, "sha256": sha, "device_pub_b64": doc["device_pub_b64"]}))
}

#[cfg(test)]
mod sealer_config_tests {
    use super::*;

    #[test]
    fn every_opened_host_has_a_sealing_config() {
        let mut policy = lockrail_policy::Policy::personal();
        policy.tools.claude_code.baa = true;
        let configs = sealer_configs(&policy, [1u8; 32]);
        for host in lockrail_proxy::sealer::SEALER_MITM_HOSTS {
            let c = configs.iter().find(|(h, _)| h == host);
            assert!(c.is_some(), "{host} is opened but has no config");
        }
        let baa = |h: &str| configs.iter().find(|(x, _)| x == h).unwrap().1.baa;
        assert!(baa("api.anthropic.com"));
        assert!(!baa("api.x.ai"), "no BAA is assumed for other providers");
    }
}
