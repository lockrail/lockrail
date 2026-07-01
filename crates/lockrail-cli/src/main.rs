mod inject;
mod sync;

use anyhow::{Context, Result, anyhow};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use clap::{Parser, Subcommand, ValueEnum};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::{Arc, Mutex};
use std::thread;
use time::OffsetDateTime;

use lockrail_audit::AuditLog;
use lockrail_protocol::presets::{InjectionMethod, PRESETS, default_path_rules, preset};
use lockrail_protocol::seal::{
    ScanOptions, SealOptions, SecretFinding, redact_for_display, redact_for_logs, scan_text,
    seal_text,
};
use lockrail_protocol::{
    AgentKeypairDoc, CapabilityClaims, CapabilityToken, ProtocolError, now_unix,
};
use lockrail_proxy::{CaStore, ProxyConfig, SecretSink, install_ca_system, run_proxy};
use lockrail_relay::{FileReplayStore, FileUsageStore, RelayState, serve};
use lockrail_vault::{KdfParamsDoc, Vault, VaultError, default_home, default_vault_path};

#[derive(Clone, Debug, ValueEnum)]
enum AgentType {
    Codex,
    ClaudeCode,
    Cursor,
    Mcp,
    Antigravity,
    LocalCli,
    Custom,
}

#[derive(Clone, Debug, ValueEnum)]
enum HarnessTool {
    Claude,
    Codex,
    Cursor,
    Mcp,
    Antigravity,
    All,
}

impl HarnessTool {
    fn tools(&self) -> Vec<&'static str> {
        match self {
            Self::Claude => vec!["claude"],
            Self::Codex => vec!["codex"],
            Self::Cursor => vec!["cursor"],
            Self::Mcp => vec!["mcp"],
            Self::Antigravity => vec!["agy"],
            Self::All => vec!["claude", "codex", "cursor", "mcp", "agy"],
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
enum ExplainTopic {
    Relay,
    Shims,
    ThreatModel,
}

impl AgentType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude-code",
            Self::Cursor => "cursor",
            Self::Mcp => "mcp",
            Self::Antigravity => "antigravity",
            Self::LocalCli => "local-cli",
            Self::Custom => "custom",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AppConfig {
    relay_listen: String,
    vault_path: String,
    block_private_networks: bool,
    require_agent_proof: bool,
    signed_receipts: bool,
    redirects_disabled: bool,
    provider_presets: Vec<String>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            relay_listen: "127.0.0.1:8787".to_string(),
            vault_path: default_vault_path().to_string_lossy().to_string(),
            block_private_networks: true,
            require_agent_proof: true,
            signed_receipts: true,
            redirects_disabled: true,
            provider_presets: PRESETS.iter().map(|preset| preset.id.to_string()).collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct LocalProfile {
    name: String,
    created_at: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
enum HarnessState {
    Pass,
    Warn,
    Fail,
    Unknown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HarnessCheckItem {
    name: String,
    status: HarnessState,
    detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DemoCase {
    name: String,
    raw_input: String,
    safe_output: String,
    findings: Vec<serde_json::Value>,
    proof: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HarnessCheckReport {
    overall: HarnessState,
    items: Vec<HarnessCheckItem>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StatusSnapshot {
    vault_encrypted: bool,
    vault_permissions_ok: bool,
    vault_unlocked: bool,
    protected_tools: BTreeMap<String, String>,
    audit_ok: bool,
    replay_writable: bool,
    receipts_enabled: bool,
    private_network_blocking_enabled: bool,
    recent_activity: Vec<String>,
}

#[derive(Clone)]
struct UiState {
    home: PathBuf,
    password: SecretString,
    /// Random token generated at startup; must be present in the `X-Lockrail-Token`
    /// request header (or as the `token` query parameter) to access any UI route.
    /// Prevents other local processes from reading secret data from the UI.
    session_token: String,
}

#[derive(Parser)]
#[command(
    name = "lockrail",
    version,
    about = "Local-first secret firewall for AI coding tools",
    long_about = "Lockrail stops raw API keys and tokens from entering AI model context.\n\
                  Secrets are caught before Claude, Codex, or Cursor ever sees them,\n\
                  sealed in an AES-256-GCM encrypted local vault, and replaced with\n\
                  safe handles. No cloud. No accounts. No telemetry.\n\n\
                  Quick start:\n  \
                    lockrail setup\n  \
                    lockrail demo"
)]
struct Cli {
    #[arg(
        long,
        env = "LOCKRAIL_HOME",
        help = "Override ~/.lockrail data directory"
    )]
    home: Option<PathBuf>,
    #[arg(
        long,
        env = "LOCKRAIL_PASSWORD",
        help = "Advanced: override the generated local vault key"
    )]
    password: Option<String>,
    #[arg(
        long,
        global = true,
        help = "Output raw JSON instead of human-readable text"
    )]
    json: bool,
    #[arg(
        long,
        global = true,
        help = "Suppress non-essential output and warnings"
    )]
    quiet: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Advanced setup: create vault and optionally install tool shims")]
    Init {
        #[arg(long, help = "Skip all confirmation prompts")]
        yes: bool,
        #[arg(long, help = "Create vault only, skip shim installation")]
        skip_shims: bool,
        #[arg(long, hide = true)]
        fast_kdf_test_only: bool,
    },
    #[command(
        about = "One-command setup: auto-configure Lockrail for this machine",
        long_about = "Auto-configures Lockrail for this machine: generates a local vault key,\n\
                      creates the encrypted vault, generates local agent keys, installs\n\
                      shims for Claude, Codex, Cursor, and Antigravity, and prints the\n\
                      PATH command if your shell needs it. No account and no password\n\
                      prompt are required by default.\n\n\
                      Start here after installing Lockrail:\n  lockrail setup"
    )]
    Setup {
        #[arg(long, hide = true)]
        apply: bool,
        #[arg(
            long,
            help = "Archive the current local Lockrail state and create a fresh auto-managed setup"
        )]
        reset: bool,
        #[arg(
            long,
            value_delimiter = ',',
            default_value = "all",
            help = "Comma-separated tools to protect: all, claude, codex, cursor, agy"
        )]
        tools: Vec<String>,
    },
    #[command(about = "Install shims for AI tools (claude, codex, cursor, mcp, agy, all)")]
    Protect {
        #[arg(
            long,
            value_enum,
            default_value = "all",
            help = "Which tool(s) to protect"
        )]
        tool: HarnessTool,
        #[arg(long, help = "Skip confirmation prompt")]
        yes: bool,
    },
    #[command(about = "Run an offline demo — shows secrets being intercepted and replaced")]
    Demo,
    #[command(about = "Show vault status, protected tools, and recent activity")]
    Status,
    #[command(about = "Open the local dashboard in your browser (token-protected, localhost only)")]
    Ui {
        #[arg(long, help = "Address to listen on (default: 127.0.0.1:8790)")]
        listen: Option<SocketAddr>,
    },
    #[command(about = "Explain how a part of Lockrail works (relay, shims, threat-model)")]
    Explain {
        #[arg(value_enum, help = "Topic to explain: relay | shims | threat-model")]
        topic: Option<ExplainTopic>,
    },
    #[command(about = "Harness verification and testing")]
    Harness {
        #[command(subcommand)]
        command: HarnessCommands,
    },
    #[command(about = "Scan, seal, and run commands with a .env file")]
    Env {
        #[command(subcommand)]
        command: EnvCommands,
    },
    #[command(
        about = "Filter piped output — remove secrets before pasting into an AI tool",
        long_about = "Reads stdin, detects secrets, and writes safe output to stdout.\n\
                      Example: some-command | lockrail pipe | pbcopy"
    )]
    Pipe {
        #[arg(long, default_value = "pipe", hide = true)]
        prefix: String,
        #[arg(long, help = "Also detect low-confidence secrets")]
        aggressive: bool,
    },
    #[command(about = "Scan or seal command output before it reaches an AI tool")]
    Output {
        #[command(subcommand)]
        command: OutputCommands,
    },
    #[command(about = "Bundle audit events and receipts into a proof package")]
    Proof {
        #[command(subcommand)]
        command: ProofCommands,
    },
    #[command(about = "Run diagnostics and check for common configuration problems")]
    Doctor,
    #[command(
        about = "Detect secrets in text without storing them",
        long_about = "Reads from stdin (or --text) and reports what secrets were found.\n\
                      Nothing is stored. Use 'lockrail seal' to store and replace secrets.\n\
                      Example: echo 'sk-proj-...' | lockrail scan"
    )]
    Scan {
        #[arg(long, help = "Text to scan (default: read from stdin)")]
        text: Option<String>,
        #[arg(long, help = "Also flag lower-confidence patterns")]
        aggressive: bool,
    },
    #[command(
        about = "Detect and store secrets, replace them with safe handles",
        long_about = "Reads from stdin (or --text), stores any detected secrets in the\n\
                      encrypted vault, and outputs the text with secrets replaced by\n\
                      lockrail://secret/... handles safe to share with AI tools.\n\
                      Example: echo 'OPENAI_API_KEY=sk-proj-...' | lockrail seal"
    )]
    Seal {
        #[arg(long, help = "Text to seal (default: read from stdin)")]
        text: Option<String>,
        #[arg(long, default_value = "sealed", hide = true)]
        prefix: String,
        #[arg(long, help = "Also seal lower-confidence patterns")]
        aggressive: bool,
    },
    #[command(hide = true)]
    Hook {
        #[command(subcommand)]
        command: HookCommands,
    },
    #[command(
        about = "Run an AI tool with secret interception active",
        long_about = "Wraps an AI tool (claude, codex, cursor…) in Lockrail's firewall.\n\
                      Secrets you type are sealed before reaching the model;\n\
                      the model's output is scanned before it hits your terminal.\n\
                      Example: lockrail run -- claude\n\
                      Example: lockrail run -- codex\n\
                      Example: lockrail run -- agy"
    )]
    Run {
        #[arg(last = true, required = true, help = "Command to run (e.g. -- claude)")]
        command: Vec<String>,
    },
    #[command(about = "Manage secrets stored in the encrypted vault")]
    Secret {
        #[command(subcommand)]
        command: SecretCommands,
    },
    #[command(about = "Manage AI agent identities (Ed25519 keypairs for capability signing)")]
    Agent {
        #[command(subcommand)]
        command: AgentCommands,
    },
    #[command(about = "Issue and manage time-bound capability tokens for relay access")]
    Capability {
        #[command(subcommand)]
        command: CapabilityCommands,
    },
    #[command(about = "Start or check the local HTTP relay (policy-enforced secret injection)")]
    Relay {
        #[command(subcommand)]
        command: RelayCommands,
    },
    #[command(about = "Verify, list, and export the tamper-evident audit log")]
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },
    #[command(about = "Print, validate, or reset configuration")]
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    #[command(
        about = "Spawn a shell with vault secrets injected as environment variables",
        long_about = "WARNING: secrets become visible as env vars inside this shell.\n\
                      Do NOT run AI tools (claude, codex, cursor, agy) inside this shell —\n\
                      they can read every secret via printenv or process.env.\n\
                      Use this only for deployment scripts and non-AI build tools.\n\
                      For AI tools, use: lockrail run -- <tool>"
    )]
    Shell {
        #[arg(
            long,
            help = "Environment to inject (e.g. production, staging, default)"
        )]
        env: Option<String>,
    },
    #[command(about = "Push secrets to external platforms (GitHub Actions, Vercel, .env file)")]
    Sync {
        #[command(subcommand)]
        command: SyncCommands,
    },
    #[command(
        about = "Local HTTPS proxy — intercepts AI API traffic before secrets reach the model"
    )]
    Proxy {
        #[command(subcommand)]
        command: ProxyCommands,
    },
    #[command(about = "Install Lockrail skill document and hooks into AI agent tools")]
    Ai {
        #[command(subcommand)]
        command: AiCommands,
    },
}

#[derive(Subcommand)]
enum AiCommands {
    #[command(about = "Install the Lockrail SKILL.md into AI agent skill directories")]
    Enable {
        #[arg(
            long,
            help = "Target tool: claude | codex | cursor | agy | all (default: all)"
        )]
        tool: Option<String>,
    },
    #[command(about = "Remove the Lockrail skill document from AI agent directories")]
    Disable {
        #[arg(long, help = "Target tool (default: all)")]
        tool: Option<String>,
    },
    #[command(about = "Install Claude Code hooks (UserPromptSubmit → lockrail hook prompt)")]
    Hooks {
        #[arg(long, help = "Target tool (currently: claude)")]
        tool: Option<String>,
    },
}

#[derive(Subcommand)]
enum HookCommands {
    #[command(about = "Seal secrets in a prompt before Claude sees it (UserPromptSubmit hook)")]
    Prompt {
        #[arg(long, default_value = "hook")]
        prefix: String,
        #[arg(long)]
        aggressive: bool,
    },
    #[command(
        about = "Block secrets in tool output before Claude incorporates them (PostToolUse hook)"
    )]
    PostToolUse {
        #[arg(long, default_value = "hook")]
        prefix: String,
        #[arg(long)]
        aggressive: bool,
    },
}

#[derive(Subcommand)]
enum SecretCommands {
    #[command(about = "List secrets in the vault (optionally filter by environment)")]
    List {
        #[arg(
            long,
            help = "Filter to this environment (e.g. production, staging, default)"
        )]
        env: Option<String>,
    },
    #[command(about = "Show metadata for a secret (use --metadata-only; raw values are disabled)")]
    Show {
        #[arg(help = "Secret name")]
        name: String,
        #[arg(
            long,
            help = "Show metadata only (raw secret value display is disabled by design)"
        )]
        metadata_only: bool,
    },
    #[command(
        about = "Store or update a secret in the vault",
        long_about = "Stores a named secret in the encrypted vault, tagged to an environment.\n\
                      If VALUE is omitted, you will be prompted (safer — avoids shell history).\n\
                      Secret names must not contain spaces or '..'.\n\
                      Examples:\n  \
                        lockrail secret set OPENAI_API_KEY\n  \
                        lockrail secret set OPENAI_API_KEY sk-proj-... --env production"
    )]
    Set {
        #[arg(help = "Name for this secret (e.g. OPENAI_API_KEY)")]
        name: String,
        #[arg(help = "Secret value — omit to be prompted interactively (safer)")]
        value: Option<String>,
        #[arg(long, help = "Tag to this environment (default: 'default')")]
        env: Option<String>,
    },
    #[command(about = "Delete a secret from the vault permanently")]
    Delete {
        #[arg(help = "Name of the secret to delete")]
        name: String,
    },
    #[command(
        about = "Import secrets from a .env file into the vault",
        long_about = "Reads KEY=VALUE pairs from a .env file and stores each one in the vault.\n\
                      Comments (#) and blank lines are ignored. Values in quotes are unquoted.\n\
                      Example: lockrail secret import .env --env production"
    )]
    Import {
        #[arg(help = "Path to .env file to import")]
        path: PathBuf,
        #[arg(
            long,
            help = "Tag imported secrets to this environment (default: 'default')"
        )]
        env: Option<String>,
    },
    #[command(
        about = "Export secrets as plaintext (dotenv, json, or yaml)",
        long_about = "WARNING: exports raw plaintext secret values. Handle the output with care.\n\
                      Supported formats: dotenv (default), json, yaml\n\
                      Example: lockrail secret export --format dotenv --env production > .env"
    )]
    Export {
        #[arg(
            long,
            default_value = "dotenv",
            help = "Output format: dotenv | json | yaml"
        )]
        format: String,
        #[arg(
            long,
            help = "Export secrets from this environment (default: 'default')"
        )]
        env: Option<String>,
    },
}

#[derive(Subcommand)]
enum SyncCommands {
    #[command(
        about = "Push vault secrets to GitHub Actions repository secrets",
        long_about = "Encrypts and uploads secrets to a GitHub repository's Actions secrets\n\
                      using the X25519 sealed-box encryption required by the GitHub API.\n\
                      Requires a GitHub token with repo or secrets:write permission.\n\
                      Example: lockrail sync github --repo owner/repo --env production"
    )]
    Github {
        #[arg(long, help = "Repository in owner/repo format (e.g. acme/backend)")]
        repo: String,
        #[arg(
            long,
            help = "GitHub personal access token (or set GITHUB_TOKEN env var)"
        )]
        token: Option<String>,
        #[arg(long, help = "Environment to sync (default: 'default')")]
        env: Option<String>,
    },
    #[command(
        about = "Push vault secrets to a Vercel project's environment variables",
        long_about = "Syncs secrets to a Vercel project, targeting all environments\n\
                      (production, preview, development). Replaces existing vars with the same name.\n\
                      Example: lockrail sync vercel --project my-project-id --env production"
    )]
    Vercel {
        #[arg(long, help = "Vercel project ID or name")]
        project: String,
        #[arg(long, help = "Vercel API token (or set VERCEL_TOKEN env var)")]
        token: Option<String>,
        #[arg(long, help = "Environment to sync (default: 'default')")]
        env: Option<String>,
    },
    #[command(
        about = "Export vault secrets to a .env file",
        long_about = "WARNING: writes plaintext secrets to disk.\n\
                      Example: lockrail sync dotenv --out .env --env production"
    )]
    Dotenv {
        #[arg(long, default_value = ".env", help = "Output file path")]
        out: PathBuf,
        #[arg(long, help = "Environment to export (default: 'default')")]
        env: Option<String>,
    },
}

#[derive(Subcommand)]
enum ProxyCommands {
    #[command(about = "Generate a local CA and install it in the system trust store")]
    InstallCa,
    #[command(
        about = "Start the HTTPS intercepting proxy (configure system HTTPS_PROXY=localhost:8789)"
    )]
    Start {
        #[arg(long, default_value = "127.0.0.1:8789", help = "Address to listen on")]
        listen: std::net::SocketAddr,
        #[arg(
            long,
            help = "Allow binding the proxy to non-loopback interfaces; unsafe on shared networks"
        )]
        unsafe_public_listen: bool,
    },
    #[command(about = "Show proxy CA and configuration status")]
    Status,
}

#[derive(Subcommand)]
enum AgentCommands {
    #[command(about = "Create a new AI agent identity (generates an Ed25519 keypair)")]
    Create {
        #[arg(help = "Name for this agent (e.g. my-claude-agent)")]
        name: String,
        #[arg(
            long,
            value_enum,
            default_value = "custom",
            help = "Agent type: codex | claude-code | cursor | mcp | local-cli | custom"
        )]
        r#type: AgentType,
    },
    #[command(about = "List all registered agent identities")]
    List,
    #[command(about = "Print an agent's public document (share with relay operators)")]
    Public {
        #[arg(help = "Agent name")]
        name: String,
    },
    #[command(about = "Rotate an agent's keypair (old key is revoked)")]
    Rotate {
        #[arg(help = "Agent name")]
        name: String,
        #[arg(long, value_enum, default_value = "custom")]
        r#type: AgentType,
    },
    #[command(about = "Revoke an agent identity (capabilities signed by it will be rejected)")]
    Revoke {
        #[arg(help = "Agent name")]
        name: String,
    },
}

#[derive(Subcommand)]
enum CapabilityCommands {
    #[command(
        about = "Issue a time-bound capability token for a secret",
        long_about = "Creates a signed capability token (LRAP) that allows the relay to inject\n\
                      a specific secret into one or more HTTP requests, within a time window.\n\
                      Example: lockrail capability issue MY_API_KEY --preset openai --minutes 5"
    )]
    Issue {
        #[arg(help = "Name of the secret this capability authorises")]
        key_name: String,
        #[arg(long, default_value = "60", help = "Token validity in minutes")]
        minutes: i64,
        #[arg(
            long = "host",
            help = "Allowed upstream hostname (repeat for multiple)"
        )]
        hosts: Vec<String>,
        #[arg(long = "method", help = "Allowed HTTP methods (e.g. POST)")]
        methods: Vec<String>,
        #[arg(long = "path", help = "Allowed URL paths (e.g. /v1/*)")]
        paths: Vec<String>,
        #[arg(long, help = "Use a built-in provider preset (openai, github, aws, …)")]
        preset: Option<String>,
        #[arg(long, help = "Bind to a specific agent identity (name)")]
        agent: Option<String>,
        #[arg(long, help = "Bind to a specific task ID")]
        task_id: Option<String>,
        #[arg(long, help = "Human-readable purpose for the audit log")]
        purpose: Option<String>,
    },
    #[command(about = "Decode and display a capability token without making any requests")]
    Inspect {
        #[arg(help = "The lrap3.… token string to inspect")]
        token: String,
    },
    #[command(about = "Revoke a capability token so the relay rejects it immediately")]
    Revoke {
        #[arg(help = "Capability UUID (shown by 'capability inspect')")]
        cap_id: uuid::Uuid,
    },
}

#[derive(Subcommand)]
enum RelayCommands {
    #[command(about = "Start the local HTTP relay on localhost (default: 127.0.0.1:8787)")]
    Start {
        #[arg(long, help = "Address and port to listen on")]
        addr: Option<SocketAddr>,
    },
    #[command(about = "Check whether the relay is running and reachable")]
    Check,
}

#[derive(Subcommand)]
enum AuditCommands {
    #[command(about = "Verify the SHA-256 hash chain — detects any tampering or deletion")]
    Verify,
    #[command(about = "Print recent audit events")]
    List,
    #[command(about = "Export all audit events (format: json)")]
    Export {
        #[arg(long, default_value = "json", help = "Output format (json)")]
        format: String,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    #[command(about = "Write a default config.json (safe to run multiple times)")]
    Init,
    #[command(about = "Check that the current config is valid")]
    Validate,
    #[command(about = "Print the current configuration")]
    Print,
}

#[derive(Subcommand)]
enum HarnessCommands {
    Check,
    Test {
        #[arg(long, value_enum)]
        tool: HarnessTool,
    },
}

#[derive(Subcommand)]
enum EnvCommands {
    Scan {
        path: PathBuf,
        #[arg(long)]
        aggressive: bool,
    },
    Seal {
        path: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value = "env")]
        prefix: String,
        #[arg(long)]
        aggressive: bool,
    },
    Run {
        #[arg(long, default_value = ".env.lockrail")]
        file: PathBuf,
        #[arg(long)]
        dry_run: bool,
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
}

#[derive(Subcommand)]
enum OutputCommands {
    Scan {
        #[arg(long)]
        text: Option<String>,
        #[arg(long)]
        aggressive: bool,
    },
    Seal {
        #[arg(long)]
        text: Option<String>,
        #[arg(long, default_value = "output")]
        prefix: String,
        #[arg(long)]
        aggressive: bool,
    },
}

#[derive(Subcommand)]
enum ProofCommands {
    Pack {
        #[arg(long, default_value = "lockrail-proof-pack.json")]
        out: PathBuf,
        #[arg(long)]
        markdown: bool,
    },
}

fn home(cli: &Cli) -> PathBuf {
    cli.home.clone().unwrap_or_else(default_home)
}

fn exit_code_for_error(error: &anyhow::Error) -> i32 {
    if let Some(vault) = error.downcast_ref::<VaultError>() {
        return match vault {
            VaultError::WrongPassword | VaultError::Missing | VaultError::Exists => 4,
            VaultError::MissingCredential | VaultError::CredentialExists => 4,
            VaultError::PolicyDenied
            | VaultError::ReplayDetected
            | VaultError::UsageLimitExceeded
            | VaultError::Revoked => 3,
            VaultError::InvalidName => 2,
            VaultError::Io(_)
            | VaultError::Json(_)
            | VaultError::Crypto
            | VaultError::Version(_) => 1,
            VaultError::Protocol(_) => 3,
        };
    }
    if let Some(protocol) = error.downcast_ref::<ProtocolError>() {
        return match protocol {
            ProtocolError::AudienceMismatch
            | ProtocolError::CapabilityExpired
            | ProtocolError::CapabilityNotYetValid
            | ProtocolError::CapabilityIssuedInFuture
            | ProtocolError::CapabilityRevoked
            | ProtocolError::MissingProof
            | ProtocolError::ProofVersion
            | ProtocolError::ProofRequestMismatch
            | ProtocolError::ProofSkew
            | ProtocolError::ProofTaskMismatch
            | ProtocolError::ProofPurposeMismatch
            | ProtocolError::SchemeNotAllowed(_)
            | ProtocolError::HostNotAllowed(_)
            | ProtocolError::IpNotAllowed(_)
            | ProtocolError::PortNotAllowed(_)
            | ProtocolError::MethodNotAllowed(_)
            | ProtocolError::PathNotAllowed(_)
            | ProtocolError::QueryNotAllowed
            | ProtocolError::ContentTypeNotAllowed(_)
            | ProtocolError::BodyTooLarge => 3,
            ProtocolError::MalformedToken
            | ProtocolError::UnsupportedTokenPrefix
            | ProtocolError::Json(_)
            | ProtocolError::Base64
            | ProtocolError::Signature
            | ProtocolError::Url(_)
            | ProtocolError::Key => 1,
        };
    }
    let message = error.to_string();
    if message.contains("invalid relay_listen")
        || message.contains("raw secret display is disabled")
        || message.contains("only --format json is currently supported")
    {
        2
    } else {
        1
    }
}

fn vault_path(cli: &Cli) -> PathBuf {
    home(cli).join("vault.lockrail")
}

fn audit_path(cli: &Cli) -> PathBuf {
    home(cli).join("audit.jsonl")
}

fn agents_dir(cli: &Cli) -> PathBuf {
    home(cli).join("agents")
}

fn replay_path(cli: &Cli) -> PathBuf {
    home(cli).join("replay-cache.json")
}

fn usage_path(cli: &Cli) -> PathBuf {
    home(cli).join("usage-store.json")
}

fn config_path(cli: &Cli) -> PathBuf {
    home(cli).join("config.json")
}

fn profile_path(cli: &Cli) -> PathBuf {
    home(cli).join("profile.json")
}

fn vault_key_path(cli: &Cli) -> PathBuf {
    home(cli).join("vault.key")
}

fn prompt_line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn prompt_yes_no(prompt: &str, default_yes: bool) -> Result<bool> {
    let suffix = if default_yes { "[Y/n]" } else { "[y/N]" };
    let answer = prompt_line(&format!("{prompt} {suffix} "))?;
    if answer.is_empty() {
        return Ok(default_yes);
    }
    Ok(matches!(answer.to_ascii_lowercase().as_str(), "y" | "yes"))
}

fn password_for_init(cli: &Cli) -> Result<SecretString> {
    if let Some(password) = &cli.password {
        return Ok(SecretString::from(password.clone()));
    }
    ensure_local_vault_key(cli)
}

fn password(cli: &Cli) -> Result<SecretString> {
    if let Some(password) = &cli.password {
        return Ok(SecretString::from(password.clone()));
    }
    read_local_vault_key(cli)?.ok_or_else(|| {
        anyhow!(
            "Lockrail is not configured yet. Run `lockrail setup` once; it will create the local vault key automatically."
        )
    })
}

fn generated_vault_key() -> String {
    use rand_core::RngCore;

    let mut bytes = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn read_local_vault_key(cli: &Cli) -> Result<Option<SecretString>> {
    let path = vault_key_path(cli);
    if !path.exists() {
        return Ok(None);
    }
    let key = fs::read_to_string(&path)
        .with_context(|| format!("read local vault key at {}", path.display()))?
        .trim()
        .to_string();
    if key.is_empty() {
        return Err(anyhow!(
            "local vault key is empty at {}; remove it and run `lockrail setup` again",
            path.display()
        ));
    }
    Ok(Some(SecretString::from(key)))
}

fn ensure_local_vault_key(cli: &Cli) -> Result<SecretString> {
    if let Some(existing) = read_local_vault_key(cli)? {
        return Ok(existing);
    }
    let path = vault_key_path(cli);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }
    let key = generated_vault_key();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("create local vault key at {}", path.display()))?;
        file.write_all(key.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("create local vault key at {}", path.display()))?;
        file.write_all(key.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    Ok(SecretString::from(key))
}

fn archive_lockrail_home(cli: &Cli) -> Result<Option<PathBuf>> {
    let active_home = home(cli);
    if !active_home.exists() {
        return Ok(None);
    }
    let parent = active_home
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let base = active_home
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("lockrail");
    let mut backup = parent.join(format!("{base}.backup.{}", now_unix()));
    let mut suffix = 0;
    while backup.exists() {
        suffix += 1;
        backup = parent.join(format!("{base}.backup.{}.{}", now_unix(), suffix));
    }
    fs::rename(&active_home, &backup)
        .with_context(|| format!("archive {} to {}", active_home.display(), backup.display()))?;
    Ok(Some(backup))
}

fn print_value(cli: &Cli, value: &serde_json::Value) -> Result<()> {
    if cli.quiet && !cli.json {
        return Ok(());
    }
    if cli.json {
        println!("{}", serde_json::to_string_pretty(value)?);
    } else if value.is_string() {
        println!("{}", value.as_str().unwrap_or_default());
    } else {
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

fn read_input(text: &Option<String>) -> Result<String> {
    match text {
        Some(value) => Ok(value.clone()),
        None => Ok(std::io::read_to_string(std::io::stdin())?),
    }
}

fn write_json_pretty(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(value)?)?;
    Ok(())
}

fn write_json_pretty_atomic(path: &Path, value: &impl Serialize) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(&serde_json::to_vec_pretty(value)?)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn ensure_local_profile(cli: &Cli) -> Result<LocalProfile> {
    let path = profile_path(cli);
    if path.exists() {
        return Ok(serde_json::from_slice(&fs::read(path)?)?);
    }
    let profile = LocalProfile {
        name: "local-user".to_string(),
        created_at: now_unix(),
    };
    write_json_pretty(&path, &profile)?;
    Ok(profile)
}

fn ensure_named_agent(cli: &Cli, name: &str, kind: &str) -> Result<serde_json::Value> {
    let mut vault = Vault::open(vault_path(cli), password(cli)?)?;
    if let Some(existing) = vault
        .list_agents()
        .into_iter()
        .find(|agent| agent.name == name || agent.agent_id == name)
    {
        return Ok(serde_json::to_value(existing)?);
    }
    let agent = AgentKeypairDoc::generate(name.to_string(), kind.to_string());
    vault.save_agent(&agent, agents_dir(cli))?;
    Ok(serde_json::to_value(agent.public_view())?)
}

fn bootstrap_agents(cli: &Cli) -> Result<Vec<serde_json::Value>> {
    let definitions = [
        ("claude", "claude-code"),
        ("codex", "codex"),
        ("cursor", "cursor"),
        ("mcp", "mcp"),
        ("antigravity", "antigravity"),
        ("local", "local-cli"),
    ];
    definitions
        .into_iter()
        .map(|(name, kind)| ensure_named_agent(cli, name, kind))
        .collect()
}

fn tool_binary_status(cli: &Cli, tool: &str) -> (HarnessState, String) {
    let shim_path = home(cli).join("bin").join(tool);
    let real = find_real_command(cli, tool);
    match (shim_path.exists(), real) {
        (true, Some(path)) => (
            HarnessState::Pass,
            format!("shim active; real binary at {}", path.display()),
        ),
        (true, None) => (
            HarnessState::Warn,
            "shim installed but real binary not found on PATH".to_string(),
        ),
        (false, Some(path)) => (
            HarnessState::Warn,
            format!("real binary found at {}, shim missing", path.display()),
        ),
        (false, None) => (HarnessState::Unknown, "binary not found".to_string()),
    }
}

fn run_fake_secret_test(cli: &Cli, prefix: &str) -> Result<serde_json::Value> {
    let sample = "OPENAI_API_KEY=sk-proj-demo-abcdefghijklmnopqrstuvwxyz123456";
    let sealed = scan_and_seal(cli, sample, prefix, false)?;
    let safe_text = sealed["safe_text"].as_str().unwrap_or_default().to_string();
    Ok(serde_json::json!({
        "sample": "OPENAI_API_KEY=sk-proj-demo-...",
        "safe_text": safe_text,
        "handle_only": safe_text.contains("lockrail://secret/openai-key/") && !safe_text.contains("sk-proj-demo"),
    }))
}

fn recent_activity_summary(cli: &Cli) -> Vec<String> {
    let rows = AuditLog::new(audit_path(cli))
        .read_all()
        .unwrap_or_default();
    let today = OffsetDateTime::now_utc().date();
    let mut sealed_today = 0u64;
    let mut relay_allowed = 0u64;
    let mut relay_denied = 0u64;
    for row in rows {
        let same_day = OffsetDateTime::from_unix_timestamp(row.timestamp)
            .map(|ts| ts.date() == today)
            .unwrap_or(false);
        if same_day && row.action == "seal.text" {
            sealed_today += 1;
        }
        if row.action == "relay.request" {
            relay_allowed += 1;
        }
        if row.action == "relay.denied" {
            relay_denied += 1;
        }
    }
    vec![
        format!("{sealed_today} secrets sealed today"),
        format!("{relay_allowed} relay requests allowed"),
        format!("{relay_denied} relay requests denied"),
    ]
}

fn status_snapshot(cli: &Cli) -> Result<StatusSnapshot> {
    let report = doctor(cli);
    let config = load_config(cli)?;
    let vault_unlocked = Vault::open(vault_path(cli), password(cli)?).is_ok();
    let mut protected_tools = BTreeMap::new();
    for tool in ["claude", "codex", "cursor", "mcp", "agy"] {
        let (state, detail) = tool_binary_status(cli, tool);
        protected_tools.insert(tool.to_string(), format!("{state:?}: {detail}"));
    }
    Ok(StatusSnapshot {
        vault_encrypted: report["checks"]["vault_exists"].as_bool().unwrap_or(false),
        vault_permissions_ok: report["checks"]["vault_permissions_ok"]
            .as_bool()
            .unwrap_or(false),
        vault_unlocked,
        protected_tools,
        audit_ok: report["checks"]["audit_verify"]["ok"]
            .as_bool()
            .unwrap_or(false),
        replay_writable: report["checks"]["replay_store_writable"]
            .as_bool()
            .unwrap_or(false),
        receipts_enabled: config.signed_receipts,
        private_network_blocking_enabled: config.block_private_networks,
        recent_activity: recent_activity_summary(cli),
    })
}

fn explain_text(topic: Option<&ExplainTopic>) -> &'static str {
    match topic {
        Some(ExplainTopic::Relay) => {
            "Lockrail relay is the only supported place where a real secret is reintroduced. It verifies capability signature, time bounds, policy, proof, replay, and usage before injecting the secret into the upstream request."
        }
        Some(ExplainTopic::Shims) => {
            "Shims replace direct claude, codex, and cursor launches with `lockrail run -- <tool>`. Lockrail seals stdin before the child receives it and avoids shim recursion with LOCKRAIL_SHIM=1."
        }
        Some(ExplainTopic::ThreatModel) => {
            "Lockrail protects prompts, .env files, command output, relay requests, and relay responses after Lockrail sees them. It does not protect GUI-only flows, clipboard capture, malware, or a fully compromised host."
        }
        None => {
            "Lockrail is a local-first secret firewall for AI coding tools. It catches secrets before agents see them, replaces them with lockrail://secret handles, stores the raw value encrypted locally, and only allows real use through policy-checked relay calls."
        }
    }
}

fn resolve_handle(vault: &mut Vault, handle: &str) -> Result<Option<String>> {
    let Some(rest) = handle.strip_prefix("lockrail://secret/") else {
        return Ok(None);
    };
    let Some((kind, fingerprint)) = rest.split_once('/') else {
        return Ok(None);
    };
    for item in vault.list_secret_metadata() {
        if item.kind == kind
            && item.fingerprint == fingerprint
            && item.name.ends_with(&format!("/{kind}/{fingerprint}"))
        {
            return Ok(Some(vault.use_key(&item.name)?));
        }
    }
    Ok(None)
}

fn parse_env_entries(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            let (key, value) = trimmed.split_once('=')?;
            Some((key.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

fn print_harness_report(cli: &Cli, report: &HarnessCheckReport) -> Result<()> {
    if cli.json {
        return print_value(cli, &serde_json::to_value(report)?);
    }
    if cli.quiet {
        return Ok(());
    }
    for item in &report.items {
        println!("{:?}  {}  {}", item.status, item.name, item.detail);
    }
    println!("Overall: {:?}", report.overall);
    Ok(())
}

fn html_escape(text: &str) -> String {
    text.chars()
        .flat_map(|ch| match ch {
            '&' => "&amp;".chars().collect::<Vec<_>>(),
            '<' => "&lt;".chars().collect(),
            '>' => "&gt;".chars().collect(),
            '"' => "&quot;".chars().collect(),
            '\'' => "&#39;".chars().collect(),
            _ => vec![ch],
        })
        .collect()
}

fn collect_json_strings(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::String(text) => out.push(text.clone()),
        serde_json::Value::Array(items) => {
            for item in items {
                collect_json_strings(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values() {
                collect_json_strings(item, out);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

fn text_for_post_tool_use_scan(input: &str) -> String {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(input) else {
        return input.to_string();
    };
    let target = json.get("tool_response").unwrap_or(&json);
    let mut strings = Vec::new();
    collect_json_strings(target, &mut strings);
    if strings.is_empty() {
        target.to_string()
    } else {
        strings.join("\n")
    }
}

fn save_sealed_findings(vault: &mut Vault, prefix: &str, findings: &[SecretFinding]) -> Result<()> {
    for finding in findings.iter().filter(|finding| finding.should_seal) {
        let name = format!("{prefix}/{}/{}", finding.kind, finding.fingerprint);
        match vault.add_key(name.clone(), finding.value.clone()) {
            Ok(_) => {}
            Err(VaultError::CredentialExists) => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

struct VaultSecretSink {
    vault_path: PathBuf,
    password: SecretString,
}

impl SecretSink for VaultSecretSink {
    fn save_findings(&self, prefix: &str, findings: &[SecretFinding]) -> Result<()> {
        let mut vault = Vault::open(&self.vault_path, self.password.clone())?;
        save_sealed_findings(&mut vault, prefix, findings)
    }
}

fn scan_and_seal(
    cli: &Cli,
    input: &str,
    prefix: &str,
    aggressive: bool,
) -> Result<serde_json::Value> {
    let sealed = seal_text(
        input,
        SealOptions {
            aggressive,
            protection_mode: true,
        },
    );
    let mut vault = Vault::open(vault_path(cli), password(cli)?)?;
    save_sealed_findings(&mut vault, prefix, &sealed.findings)?;
    AuditLog::new(audit_path(cli)).append(
        "seal.text",
        prefix,
        serde_json::json!({
            "count": sealed.findings.iter().filter(|finding| finding.should_seal).count(),
            "fingerprints": sealed.findings.iter().map(|finding| finding.fingerprint.clone()).collect::<Vec<_>>()
        }),
    )?;
    Ok(serde_json::json!({
        "safe_text": sealed.safe_text,
        "findings": sealed.findings.iter().map(|finding| serde_json::json!({
            "kind": finding.kind,
            "fingerprint": finding.fingerprint,
            "confidence": finding.confidence,
            "should_seal": finding.should_seal,
            "preview": finding.preview,
        })).collect::<Vec<_>>(),
    }))
}

fn terminal_size() -> PtySize {
    PtySize {
        rows: 30,
        cols: 120,
        pixel_width: 0,
        pixel_height: 0,
    }
}

fn path_command(name: &str) -> Option<PathBuf> {
    let executable = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(&executable))
            .find(|candidate| candidate.exists() && candidate.is_file())
    })
}

fn same_path(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

fn find_real_command(cli: &Cli, name: &str) -> Option<PathBuf> {
    let shim = home(cli).join("bin").join(name);
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(name))
            .find(|candidate| candidate.exists() && candidate.is_file() && *candidate != shim)
    })
}

fn sanitized_command(
    cli: &Cli,
    command: &[String],
    prefix: &str,
) -> Result<(PathBuf, Vec<String>)> {
    let executable = if std::env::var("LOCKRAIL_SHIM").is_ok() {
        find_real_command(cli, &command[0]).unwrap_or_else(|| PathBuf::from(&command[0]))
    } else {
        PathBuf::from(&command[0])
    };
    let mut sanitized_args = Vec::with_capacity(command.len().saturating_sub(1));
    for arg in &command[1..] {
        let sealed = scan_and_seal(cli, arg, prefix, false)?;
        let safe_arg = sealed
            .get("safe_text")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(arg)
            .to_string();
        sanitized_args.push(safe_arg);
    }
    Ok((executable, sanitized_args))
}

fn run_interactive(cli: &Cli, command: &[String]) -> Result<()> {
    let (executable, sanitized_args) = sanitized_command(cli, command, "pty-arg")?;
    let pty_system = native_pty_system();
    let pair = pty_system.openpty(terminal_size())?;
    let mut cmd = CommandBuilder::new(executable);
    for arg in &sanitized_args {
        cmd.arg(arg);
    }
    let mut child = pair.slave.spawn_command(cmd)?;
    drop(pair.slave);

    let mut reader = pair.master.try_clone_reader()?;
    let mut writer = pair.master.take_writer()?;

    // Scan AI tool output for secrets before forwarding to the user's terminal.
    // This catches cases where the model echoes or generates a secret in its response.
    let options = lockrail_protocol::seal::SealOptions::default();
    let output_thread = thread::spawn(move || {
        use std::io::{BufRead, BufReader, Write};
        let mut stdout = std::io::stdout();
        let buf = BufReader::new(&mut reader);
        for line in buf.lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            let result = lockrail_protocol::seal::seal_text(&line, options);
            let _ = stdout.write_all(result.safe_text.as_bytes());
            let _ = stdout.write_all(b"\n");
            let _ = stdout.flush();
        }
    });

    let stdin = std::io::stdin();
    let mut buffered = String::new();
    loop {
        let mut line = String::new();
        if stdin.read_line(&mut line)? == 0 {
            break;
        }
        buffered.push_str(&line);
        if line.ends_with('\n') || line.ends_with('\r') {
            let sealed = scan_and_seal(cli, &buffered, "pty", false)?;
            let safe = sealed
                .get("safe_text")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string();
            writer.write_all(safe.as_bytes())?;
            writer.flush()?;
            buffered.clear();
        }
    }
    let status = child.wait()?;
    let _ = output_thread.join();
    if !status.success() {
        std::process::exit(status.exit_code() as i32);
    }
    Ok(())
}

fn run_piped(cli: &Cli, command: &[String]) -> Result<()> {
    let input = std::io::read_to_string(std::io::stdin())?;
    let sealed = scan_and_seal(cli, &input, "run", false)?;
    let safe_input = sealed
        .get("safe_text")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_string();
    let (executable, sanitized_args) = sanitized_command(cli, command, "run-arg")?;
    let output = Command::new(executable)
        .args(&sanitized_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(safe_input.as_bytes())?;
            }
            child.wait_with_output()
        })?;
    let safe_stdout = redact_for_display(&String::from_utf8_lossy(&output.stdout));
    let safe_stderr = redact_for_display(&String::from_utf8_lossy(&output.stderr));
    print!("{safe_stdout}");
    eprint!("{safe_stderr}");
    if !output.status.success() {
        std::process::exit(output.status.code().unwrap_or(1));
    }
    Ok(())
}

fn install_shims(cli: &Cli, tools: &[String]) -> Result<serde_json::Value> {
    let bin_dir = home(cli).join("bin");
    fs::create_dir_all(&bin_dir)?;
    let current_exe = std::env::current_exe()?;
    let mut installed = Vec::new();
    for tool in tools {
        #[cfg(windows)]
        let path = bin_dir.join(format!("{tool}.bat"));
        #[cfg(not(windows))]
        let path = bin_dir.join(tool);

        #[cfg(windows)]
        let script = format!(
            "@echo off\r\nset LOCKRAIL_SHIM=1\r\n\"{}\" run -- \"{}\" %*\r\n",
            current_exe.display(),
            tool
        );
        #[cfg(not(windows))]
        let script = format!(
            "#!/bin/sh\nLOCKRAIL_SHIM=1 exec \"{}\" run -- \"{}\" \"$@\"\n",
            current_exe.display(),
            tool
        );

        fs::write(&path, script)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
        }
        installed.push(path.to_string_lossy().to_string());
    }

    #[cfg(windows)]
    let path_prepend = format!(
        "$env:PATH = \"{};$env:PATH\"  # PowerShell\n# or: set PATH={};%PATH%  # CMD",
        bin_dir.display(),
        bin_dir.display()
    );
    #[cfg(not(windows))]
    let path_prepend = format!("export PATH=\"{}:$PATH\"", bin_dir.display());

    Ok(serde_json::json!({
        "installed": installed,
        "path_prepend": path_prepend,
    }))
}

fn ensure_default_agent_with_password(
    cli: &Cli,
    vault_password: SecretString,
) -> Result<serde_json::Value> {
    let mut vault = Vault::open(vault_path(cli), vault_password)?;
    if let Some(agent) = vault.list_agents().first() {
        return Ok(serde_json::to_value(agent)?);
    }
    let agent = AgentKeypairDoc::generate("default-local-agent", "local-cli");
    vault.save_agent(&agent, agents_dir(cli))?;
    Ok(serde_json::to_value(agent.public_view())?)
}

fn setup_tools(tools: &[String]) -> Vec<String> {
    let mut selected = Vec::new();
    for tool in tools {
        if tool.eq_ignore_ascii_case("all") {
            selected.extend(
                ["claude", "codex", "cursor", "agy"]
                    .iter()
                    .map(|t| t.to_string()),
            );
        } else {
            selected.push(tool.to_ascii_lowercase());
        }
    }
    selected.sort();
    selected.dedup();
    selected
}

fn setup_apply(cli: &Cli, tools: &[String], reset: bool) -> Result<serde_json::Value> {
    let selected_tools = setup_tools(tools);
    let mut recovered_from = if reset {
        archive_lockrail_home(cli)?
    } else {
        None
    };
    if recovered_from.is_none()
        && vault_path(cli).exists()
        && read_local_vault_key(cli)?.is_none()
        && cli.password.is_none()
        && std::env::var("LOCKRAIL_PASSWORD").is_err()
    {
        recovered_from = archive_lockrail_home(cli)?;
    }
    let vault_password = if !vault_path(cli).exists() {
        password_for_init(cli)?
    } else {
        password(cli)?
    };
    if !vault_path(cli).exists() {
        let _ = Vault::init(
            vault_path(cli),
            vault_password.clone(),
            KdfParamsDoc::default(),
        )?;
        AuditLog::new(audit_path(cli)).append("vault.init", "", serde_json::json!({}))?;
    } else {
        let _ = Vault::open(vault_path(cli), vault_password.clone())?;
    }
    if !config_path(cli).exists() {
        save_config(cli, &AppConfig::default())?;
    }
    let profile = ensure_local_profile(cli)?;
    let agent = ensure_default_agent_with_password(cli, vault_password)?;
    let shims = install_shims(cli, &selected_tools)?;
    let doctor_report = doctor(cli);
    let credential_mode = if cli.password.is_some() {
        "user_supplied_password"
    } else {
        "generated_local_key"
    };
    Ok(serde_json::json!({
        "status": "ready",
        "credential_mode": credential_mode,
        "vault_key": {
            "path": vault_key_path(cli),
            "stored_locally": cli.password.is_none()
        },
        "recovered_from": recovered_from,
        "profile": profile,
        "agent": agent,
        "tools": selected_tools,
        "shims": shims,
        "doctor": doctor_report,
        "next": [
            "open a new terminal if PATH changed",
            "lockrail demo",
            "lockrail doctor",
            "claude",
            "codex",
            "cursor",
            "agy"
        ]
    }))
}

fn init_lockrail(
    cli: &Cli,
    yes: bool,
    skip_shims: bool,
    fast_kdf_test_only: bool,
) -> Result<serde_json::Value> {
    let init_password = password_for_init(cli)?;
    let kdf = if fast_kdf_test_only {
        KdfParamsDoc::test_fast()
    } else {
        KdfParamsDoc::default()
    };
    if !vault_path(cli).exists() {
        let _ = Vault::init(vault_path(cli), init_password, kdf)?;
        AuditLog::new(audit_path(cli)).append("vault.init", "", serde_json::json!({}))?;
    }
    if !config_path(cli).exists() {
        save_config(cli, &AppConfig::default())?;
    }
    let profile = ensure_local_profile(cli)?;
    let agents = bootstrap_agents(cli)?;
    let install = if skip_shims {
        false
    } else if yes {
        true
    } else {
        prompt_yes_no(
            "Install shims for Claude, Codex, Cursor, and Antigravity now?",
            true,
        )?
    };
    let shims = if install {
        install_shims(
            cli,
            &["claude", "codex", "cursor", "agy"]
                .iter()
                .map(|t| t.to_string())
                .collect::<Vec<_>>(),
        )?
    } else {
        serde_json::json!({"installed": [], "path_prepend": format!("export PATH=\"{}:$PATH\"", home(cli).join("bin").display())})
    };
    let doctor_report = doctor(cli);
    Ok(serde_json::json!({
        "message": "Lockrail is ready.",
        "profile": profile,
        "agents": agents,
        "protected_tools": {
            "claude": install,
            "codex": install,
            "cursor": install,
            "agy": install,
        },
        "vault": {
            "encrypted_local_vault": true,
            "no_cloud": true,
            "audit_enabled": true,
        },
        "shims": shims,
        "doctor": doctor_report,
        "next": [
            "lockrail protect --tool all",
            "lockrail demo",
            "lockrail status",
            "echo 'OPENAI_API_KEY=sk-proj-demo...' | lockrail seal --json"
        ]
    }))
}

fn protect_tool(cli: &Cli, tool: HarnessTool, _yes: bool) -> Result<serde_json::Value> {
    let selected = tool.tools();
    let installed = install_shims(
        cli,
        &selected
            .iter()
            .map(|tool| (*tool).to_string())
            .collect::<Vec<_>>(),
    )?;
    let checks = selected
        .iter()
        .map(|tool| {
            let (status, detail) = tool_binary_status(cli, tool);
            serde_json::json!({
                "tool": tool,
                "status": status,
                "detail": detail,
            })
        })
        .collect::<Vec<_>>();
    let test = run_fake_secret_test(cli, "protect")?;
    AuditLog::new(audit_path(cli)).append(
        "protect.run",
        "",
        serde_json::json!({"tools": selected}),
    )?;
    Ok(serde_json::json!({
        "installed": installed,
        "checks": checks,
        "safe_handle_test": test,
    }))
}

fn demo_cases(cli: &Cli) -> Result<Vec<DemoCase>> {
    let samples = [
        (
            "prompt",
            "OPENAI_API_KEY=sk-proj-demo-abcdefghijklmnopqrstuvwxyz123456",
            "demo.prompt",
        ),
        (
            "env",
            "GITHUB_TOKEN=ghp_demoabcdefghijklmnopqrstuvwxyz123456",
            "demo.env",
        ),
        (
            "output",
            "slack token xoxb-LOCKRAILTEST-XXXXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXX",
            "demo.output",
        ),
        (
            "response",
            "{\"token\":\"sk-proj-demo-abcdefghijklmnopqrstuvwxyz123456\"}",
            "demo.response",
        ),
    ];
    let mut vault = Vault::open(vault_path(cli), password(cli)?)?;
    let mut out = Vec::new();
    for (name, raw_input, prefix) in samples {
        let sealed = seal_text(raw_input, SealOptions::default());
        save_sealed_findings(&mut vault, prefix, &sealed.findings)?;
        AuditLog::new(audit_path(cli)).append(
            "demo.case",
            name,
            serde_json::json!({
                "fingerprints": sealed.findings.iter().map(|f| f.fingerprint.clone()).collect::<Vec<_>>()
            }),
        )?;
        out.push(DemoCase {
            name: name.to_string(),
            raw_input: raw_input.to_string(),
            safe_output: sealed.safe_text.clone(),
            findings: sealed
                .findings
                .iter()
                .map(|finding| {
                    serde_json::json!({
                        "kind": finding.kind,
                        "fingerprint": finding.fingerprint,
                        "preview": finding.preview,
                    })
                })
                .collect(),
            proof: vec![
                "raw secret absent from safe text".to_string(),
                "raw secret absent from ~/.lockrail".to_string(),
                "audit event written".to_string(),
            ],
        });
    }
    Ok(out)
}

fn harness_check_report(cli: &Cli) -> HarnessCheckReport {
    let mut items = Vec::new();
    items.push(HarnessCheckItem {
        name: "os".to_string(),
        status: HarnessState::Pass,
        detail: std::env::consts::OS.to_string(),
    });
    items.push(HarnessCheckItem {
        name: "shell".to_string(),
        status: std::env::var("SHELL")
            .map(|_| HarnessState::Pass)
            .unwrap_or(HarnessState::Unknown),
        detail: std::env::var("SHELL").unwrap_or_else(|_| "unknown".to_string()),
    });
    items.push(HarnessCheckItem {
        name: "path order".to_string(),
        status: if doctor(cli)["checks"]["path_prepend_ok"]
            .as_bool()
            .unwrap_or(false)
        {
            HarnessState::Pass
        } else {
            HarnessState::Warn
        },
        detail: "Lockrail shims should be first on PATH".to_string(),
    });
    for tool in ["claude", "codex", "cursor", "agy"] {
        let (status, detail) = tool_binary_status(cli, tool);
        items.push(HarnessCheckItem {
            name: format!("{tool} binary"),
            status,
            detail,
        });
    }
    items.push(HarnessCheckItem {
        name: "vault".to_string(),
        status: if vault_path(cli).exists() {
            HarnessState::Pass
        } else {
            HarnessState::Fail
        },
        detail: vault_path(cli).display().to_string(),
    });
    items.push(HarnessCheckItem {
        name: "audit".to_string(),
        status: if doctor(cli)["checks"]["audit_verify"]["ok"]
            .as_bool()
            .unwrap_or(false)
        {
            HarnessState::Pass
        } else {
            HarnessState::Warn
        },
        detail: audit_path(cli).display().to_string(),
    });
    items.push(HarnessCheckItem {
        name: "config".to_string(),
        status: if load_config(cli).is_ok() {
            HarnessState::Pass
        } else {
            HarnessState::Fail
        },
        detail: config_path(cli).display().to_string(),
    });
    items.push(HarnessCheckItem {
        name: "relay port".to_string(),
        status: load_config(cli)
            .ok()
            .and_then(|config| config.relay_listen.parse::<SocketAddr>().ok())
            .map(|_| HarnessState::Pass)
            .unwrap_or(HarnessState::Fail),
        detail: load_config(cli)
            .map(|config| config.relay_listen)
            .unwrap_or_else(|_| "invalid".to_string()),
    });
    let overall = if items.iter().any(|item| item.status == HarnessState::Fail) {
        HarnessState::Fail
    } else if items.iter().any(|item| item.status == HarnessState::Warn) {
        HarnessState::Warn
    } else if items
        .iter()
        .any(|item| item.status == HarnessState::Unknown)
    {
        HarnessState::Unknown
    } else {
        HarnessState::Pass
    };
    HarnessCheckReport { overall, items }
}

fn harness_test_report(cli: &Cli, tool: HarnessTool) -> HarnessCheckReport {
    let mut items = Vec::new();
    for name in tool.tools() {
        let shim_exists = home(cli).join("bin").join(name).exists();
        let real_binary = find_real_command(cli, name);
        let fake_test = run_fake_secret_test(cli, "harness").ok();
        let status = match (
            shim_exists,
            real_binary.is_some(),
            fake_test
                .as_ref()
                .and_then(|value| value["handle_only"].as_bool()),
        ) {
            (true, true, Some(true)) => HarnessState::Pass,
            (true, false, Some(true)) => HarnessState::Warn,
            (false, _, _) => HarnessState::Fail,
            (_, _, _) => HarnessState::Unknown,
        };
        items.push(HarnessCheckItem {
            name: format!("{name} shim path"),
            status,
            detail: match real_binary {
                Some(path) => format!(
                    "shim={}, real={}",
                    home(cli).join("bin").join(name).display(),
                    path.display()
                ),
                None => "shim simulation only; real binary unavailable".to_string(),
            },
        });
    }
    let overall = if items.iter().all(|item| item.status == HarnessState::Pass) {
        HarnessState::Pass
    } else if items.iter().any(|item| item.status == HarnessState::Fail) {
        HarnessState::Fail
    } else if items.iter().any(|item| item.status == HarnessState::Warn) {
        HarnessState::Warn
    } else {
        HarnessState::Unknown
    };
    HarnessCheckReport { overall, items }
}

#[cfg(unix)]
fn permissions_mode(path: &PathBuf) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .ok()
        .map(|meta| meta.permissions().mode() & 0o777)
}

#[cfg(not(unix))]
fn permissions_mode(_path: &PathBuf) -> Option<u32> {
    None
}

fn store_writable(path: &PathBuf) -> bool {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .is_ok()
}

fn doctor(cli: &Cli) -> serde_json::Value {
    let vault_exists = vault_path(cli).exists();
    let vault_key_exists = vault_key_path(cli).exists();
    let legacy_password_vault_without_key = vault_exists
        && !vault_key_exists
        && cli.password.is_none()
        && std::env::var("LOCKRAIL_PASSWORD").is_err();
    let audit_exists = audit_path(cli).exists();
    let config = load_config(cli);
    let current_exe = std::env::current_exe().ok();
    let active_lockrail = path_command("lockrail");
    let active_lockrail_matches_current = match (&active_lockrail, &current_exe) {
        (Some(active), Some(current)) => same_path(active, current),
        _ => false,
    };
    let audit_verify = if audit_exists {
        match AuditLog::new(audit_path(cli)).verify() {
            Ok((ok, message)) => serde_json::json!({"ok": ok, "message": message}),
            Err(error) => {
                serde_json::json!({"ok": false, "message": redact_for_logs(&error.to_string())})
            }
        }
    } else {
        serde_json::json!({"ok": true, "message": "audit log not created yet"})
    };
    let shim_dir = home(cli).join("bin");
    let shims = ["claude", "codex", "cursor", "agy"]
        .iter()
        .map(|tool| ((*tool).to_string(), shim_dir.join(tool).exists()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let path_order_ok = std::env::var_os("PATH")
        .map(|paths| {
            std::env::split_paths(&paths)
                .next()
                .map(|first| first == shim_dir)
                .unwrap_or(false)
        })
        .unwrap_or(false);
    let config_valid = config.is_ok();
    let security_defaults_enabled = config
        .as_ref()
        .map(|config| {
            config.block_private_networks
                && config.require_agent_proof
                && config.signed_receipts
                && config.redirects_disabled
        })
        .unwrap_or(false);
    let mut fixes = Vec::new();
    if std::env::var("LOCKRAIL_PASSWORD").is_ok() {
        fixes.push("unset LOCKRAIL_PASSWORD".to_string());
    }
    if legacy_password_vault_without_key {
        fixes.push("lockrail setup --reset".to_string());
    }
    if !path_order_ok {
        fixes.push(format!("export PATH=\"{}:$PATH\"", shim_dir.display()));
    }
    if active_lockrail.is_none() {
        fixes.push("add the Lockrail install directory to PATH".to_string());
    } else if !active_lockrail_matches_current {
        fixes.push("your shell resolves lockrail to a different binary; run `command -v lockrail` and put the intended install directory first on PATH".to_string());
    }
    let checks = serde_json::json!({
        "home": home(cli),
        "current_exe": current_exe,
        "active_lockrail": active_lockrail,
        "active_lockrail_matches_current": active_lockrail_matches_current,
        "vault_exists": vault_exists,
        "vault_permissions": permissions_mode(&vault_path(cli)).map(|m| format!("{:04o}", m)),
        "vault_permissions_ok": permissions_mode(&vault_path(cli)).map(|mode| mode == 0o600).unwrap_or(vault_exists),
        "vault_key_exists": vault_key_exists,
        "vault_key_permissions": permissions_mode(&vault_key_path(cli)).map(|m| format!("{:04o}", m)),
        "vault_key_permissions_ok": permissions_mode(&vault_key_path(cli)).map(|mode| mode == 0o600).unwrap_or(!vault_key_path(cli).exists()),
        "vault_key_auto_managed": cli.password.is_none() && std::env::var("LOCKRAIL_PASSWORD").is_err(),
        "legacy_password_vault_without_key": legacy_password_vault_without_key,
        "audit_exists": audit_exists,
        "audit_verify": audit_verify,
        "config_valid": config_valid,
        "replay_store_writable": store_writable(&replay_path(cli)),
        "usage_store_writable": store_writable(&usage_path(cli)),
        "shims_installed": shims,
        "path_prepend_ok": path_order_ok,
        "real_claude_found": find_real_command(cli, "claude").is_some(),
        "real_codex_found": find_real_command(cli, "codex").is_some(),
        "real_cursor_found": find_real_command(cli, "cursor").is_some(),
        "security_defaults_enabled": security_defaults_enabled,
        "vault_credential_available": cli.password.is_some() || std::env::var("LOCKRAIL_PASSWORD").is_ok() || vault_key_exists,
    });
    let overall_ok = vault_exists
        && !legacy_password_vault_without_key
        && config_valid
        && security_defaults_enabled
        && checks["replay_store_writable"].as_bool().unwrap_or(false)
        && checks["usage_store_writable"].as_bool().unwrap_or(false)
        && checks["path_prepend_ok"].as_bool().unwrap_or(false)
        && checks["audit_verify"]["ok"].as_bool().unwrap_or(false);
    serde_json::json!({"ok": overall_ok, "checks": checks, "fixes": fixes})
}

fn env_scan(_cli: &Cli, path: &Path, aggressive: bool) -> Result<serde_json::Value> {
    let input = fs::read_to_string(path)?;
    let findings = scan_text(
        &input,
        ScanOptions {
            aggressive,
            protection_mode: true,
        },
    );
    Ok(serde_json::json!({
        "path": path,
        "count": findings.len(),
        "findings": findings.iter().map(|finding| serde_json::json!({
            "kind": finding.kind,
            "fingerprint": finding.fingerprint,
            "preview": finding.preview,
        })).collect::<Vec<_>>(),
        "safe_text": redact_for_display(&input),
    }))
}

fn env_seal(
    cli: &Cli,
    path: &Path,
    out: &Path,
    prefix: &str,
    aggressive: bool,
    dry_run: bool,
) -> Result<serde_json::Value> {
    let input = fs::read_to_string(path)?;
    let sealed = seal_text(
        &input,
        SealOptions {
            aggressive,
            protection_mode: true,
        },
    );
    if !dry_run {
        let mut vault = Vault::open(vault_path(cli), password(cli)?)?;
        save_sealed_findings(&mut vault, prefix, &sealed.findings)?;
        fs::write(out, sealed.safe_text.as_bytes())?;
        AuditLog::new(audit_path(cli)).append(
            "env.seal",
            out.display().to_string(),
            serde_json::json!({
                "source": path,
                "fingerprints": sealed.findings.iter().map(|finding| finding.fingerprint.clone()).collect::<Vec<_>>()
            }),
        )?;
    }
    Ok(serde_json::json!({
        "path": path,
        "out": out,
        "dry_run": dry_run,
        "safe_text": sealed.safe_text,
        "findings": sealed.findings.iter().map(|finding| serde_json::json!({
            "kind": finding.kind,
            "fingerprint": finding.fingerprint,
            "preview": finding.preview,
        })).collect::<Vec<_>>(),
    }))
}

fn env_run(cli: &Cli, file: &Path, command: &[String], dry_run: bool) -> Result<serde_json::Value> {
    let input = fs::read_to_string(file)?;
    let entries = parse_env_entries(&input);
    let mut resolved = BTreeMap::new();
    let mut vault = Vault::open(vault_path(cli), password(cli)?)?;
    for (key, value) in entries {
        if let Some(secret) = resolve_handle(&mut vault, &value)? {
            resolved.insert(key, secret);
        } else {
            resolved.insert(key, value);
        }
    }
    if dry_run {
        return Ok(serde_json::json!({
            "file": file,
            "dry_run": true,
            "env_keys": resolved.keys().cloned().collect::<Vec<_>>(),
        }));
    }
    let output = Command::new(&command[0])
        .args(&command[1..])
        .envs(&resolved)
        .output()?;
    AuditLog::new(audit_path(cli)).append(
        "env.run",
        file.display().to_string(),
        serde_json::json!({"command": command, "env_keys": resolved.keys().cloned().collect::<Vec<_>>()}),
    )?;
    Ok(serde_json::json!({
        "status": output.status.code().unwrap_or_default(),
        "stdout": redact_for_display(&String::from_utf8_lossy(&output.stdout)),
        "stderr": redact_for_display(&String::from_utf8_lossy(&output.stderr)),
    }))
}

fn proof_pack(cli: &Cli, out: &Path, markdown: bool) -> Result<serde_json::Value> {
    let status = status_snapshot(cli)?;
    let audit = AuditLog::new(audit_path(cli)).verify()?;
    let secrets = Vault::open(vault_path(cli), password(cli)?)?.list_secret_metadata();
    let report = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "tool_protection_status": status.protected_tools,
        "audit_verification": {"ok": audit.0, "message": audit.1},
        "receipt_verification": "receipts are verified during relay and local tests",
        "sealed_secret_count": secrets.len(),
        "denied_relay_examples": AuditLog::new(audit_path(cli)).read_all()?.into_iter().filter(|row| row.action == "relay.denied").map(|row| row.metadata).collect::<Vec<_>>(),
        "limitations": [
            "PTY interception is best-effort",
            "GUI and clipboard flows are outside the enforced boundary",
            "Header-based relay injection is strongest today"
        ],
        "build": {
            "crate": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION")
        }
    });
    fs::write(out, serde_json::to_vec_pretty(&report)?)?;
    if markdown {
        let md_path = out.with_extension("md");
        let markdown_body = format!(
            "# Lockrail Proof Pack\n\n- Version: `{}`\n- Audit: `{}`\n- Sealed secrets: `{}`\n- Limitations: PTY interception is best-effort; GUI-only flows are outside the boundary.\n",
            env!("CARGO_PKG_VERSION"),
            audit.1,
            secrets.len()
        );
        fs::write(md_path, markdown_body)?;
    }
    Ok(serde_json::json!({"out": out, "markdown": markdown}))
}

fn ai_skill_source() -> std::path::PathBuf {
    // Look for SKILL.md next to the binary, then in the repo root
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_default();
    let candidates = [
        exe_dir.join("SKILL.md"),
        std::path::PathBuf::from("SKILL.md"),
        // Development: relative to Cargo workspace root
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../SKILL.md"),
    ];
    candidates
        .into_iter()
        .find(|p| p.exists())
        .unwrap_or_else(|| std::path::PathBuf::from("SKILL.md"))
}

fn ai_skill_dirs(tool: Option<&str>) -> Vec<(String, std::path::PathBuf)> {
    // dirs::home_dir() returns None in some CI/container environments; fall back
    // to standard env vars so the result is always an absolute path.
    let home = dirs::home_dir().unwrap_or_else(|| {
        std::env::var("USERPROFILE") // Windows
            .or_else(|_| std::env::var("HOME")) // Unix fallback
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
    });
    let all: Vec<(&str, std::path::PathBuf)> = vec![
        ("claude", home.join(".claude")),
        ("codex", home.join(".codex")),
        ("agy", home.join(".agy").join("skills")),
    ];
    all.into_iter()
        .filter(|(name, _)| tool.is_none() || tool == Some(name))
        .map(|(name, path)| (name.to_string(), path))
        .collect()
}

fn ai_enable(tool: Option<&str>, quiet: bool) -> Result<serde_json::Value> {
    let skill_src = ai_skill_source();
    let skill_content = if skill_src.exists() {
        fs::read_to_string(&skill_src)
            .with_context(|| format!("reading SKILL.md from {}", skill_src.display()))?
    } else {
        return Err(anyhow!(
            "SKILL.md not found — expected at {}",
            skill_src.display()
        ));
    };
    let dirs = ai_skill_dirs(tool);
    let mut installed = Vec::new();
    let skipped: Vec<String> = Vec::new();
    for (name, dir) in &dirs {
        fs::create_dir_all(dir)?;
        let dest = dir.join("lockrail.md");
        fs::write(&dest, skill_content.as_bytes())?;
        installed.push(dest.to_string_lossy().to_string());
        if !quiet {
            eprintln!(
                "lockrail: installed skill for {} → {}",
                name,
                dest.display()
            );
        }
    }
    // Cursor: also write to .cursorrules in current dir if it exists or create it
    if tool.is_none() || tool == Some("cursor") {
        let cursorrules = std::path::PathBuf::from(".cursorrules");
        let header = "# Lockrail — see ~/.lockrail/SKILL.md for full context\n\
                      # You are operating inside a Lockrail secret firewall.\n\
                      # Secrets are replaced with lockrail://secret/... handles.\n\
                      # Never ask users to reveal handle contents.\n";
        if cursorrules.exists() {
            let existing = fs::read_to_string(&cursorrules).unwrap_or_default();
            if !existing.contains("lockrail") {
                fs::write(&cursorrules, format!("{header}\n{existing}"))?;
                installed.push(cursorrules.to_string_lossy().to_string());
            }
        }
    }
    Ok(serde_json::json!({ "installed": installed, "skipped": skipped }))
}

fn ai_disable(tool: Option<&str>, quiet: bool) -> Result<serde_json::Value> {
    let dirs = ai_skill_dirs(tool);
    let mut removed = Vec::new();
    for (_, dir) in &dirs {
        let dest = dir.join("lockrail.md");
        if dest.exists() {
            fs::remove_file(&dest)?;
            removed.push(dest.to_string_lossy().to_string());
        }
    }
    if !quiet {
        eprintln!("lockrail: removed {} skill file(s)", removed.len());
    }
    Ok(serde_json::json!({ "removed": removed }))
}

fn ai_install_hooks(tool: Option<&str>, quiet: bool) -> Result<serde_json::Value> {
    let target = tool.unwrap_or("claude");
    if target != "claude" {
        return Err(anyhow!(
            "hooks are currently only supported for --tool claude"
        ));
    }
    let settings_path = dirs::home_dir()
        .unwrap_or_default()
        .join(".claude")
        .join("settings.json");
    if let Some(parent) = settings_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut settings: serde_json::Value = if settings_path.exists() {
        serde_json::from_slice(&fs::read(&settings_path)?).unwrap_or_else(|_| serde_json::json!({}))
    } else {
        serde_json::json!({})
    };

    let exe = std::env::current_exe()?.to_string_lossy().to_string();

    // Ensure settings.hooks exists as an object before we try to mutate sub-keys.
    {
        let root = settings
            .as_object_mut()
            .ok_or_else(|| anyhow!("settings.json root is not a JSON object"))?;
        root.entry("hooks").or_insert_with(|| serde_json::json!({}));
    }

    fn hook_command(value: &serde_json::Value) -> Option<&str> {
        value
            .get("hooks")
            .and_then(serde_json::Value::as_array)
            .and_then(|hooks| hooks.first())
            .and_then(|hook| hook.get("command"))
            .and_then(serde_json::Value::as_str)
    }

    // Upsert one hook event entry. Returns true if the exact command is already present.
    fn insert_hook(settings: &mut serde_json::Value, event: &str, command: &str) -> Result<bool> {
        let entry = serde_json::json!({
            "hooks": [{ "type": "command", "command": command }]
        });
        let hooks_obj = settings
            .get_mut("hooks")
            .and_then(|h| h.as_object_mut())
            .ok_or_else(|| anyhow!("hooks is not a JSON object"))?;
        let arr = hooks_obj
            .entry(event)
            .or_insert_with(|| serde_json::json!([]));
        let already = arr
            .as_array()
            .map(|a| a.iter().any(|value| hook_command(value) == Some(command)))
            .unwrap_or(false);
        if !already {
            arr.as_array_mut()
                .ok_or_else(|| anyhow!("{event} is not a JSON array"))?
                .push(entry);
        }
        Ok(already)
    }

    let ups_already = insert_hook(
        &mut settings,
        "UserPromptSubmit",
        &format!("{exe} hook prompt"),
    )?;
    let ptu_already = insert_hook(
        &mut settings,
        "PostToolUse",
        &format!("{exe} hook post-tool-use"),
    )?;

    if settings_path.exists() {
        let backup_path = settings_path.with_extension("json.lockrail.bak");
        fs::copy(&settings_path, backup_path)?;
    }
    write_json_pretty_atomic(&settings_path, &settings)?;
    if !quiet {
        eprintln!(
            "lockrail: installed UserPromptSubmit + PostToolUse hooks in {}",
            settings_path.display()
        );
    }
    Ok(serde_json::json!({
        "hooks": ["UserPromptSubmit", "PostToolUse"],
        "settings": settings_path,
        "already_present": { "UserPromptSubmit": ups_already, "PostToolUse": ptu_already },
    }))
}

fn ui_css() -> &'static str {
    r#":root{--bg:#0d1117;--surface:#161b22;--card:#1c2128;--border:#30363d;--t1:#e6edf3;--t2:#8b949e;--t3:#6e7681;--accent:#58a6ff;--ok:#3fb950;--warn:#d29922;--err:#f85149;--sidebar:220px}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--t1);display:flex;font-size:14px;line-height:1.5}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.sidebar{width:var(--sidebar);background:var(--surface);border-right:1px solid var(--border);display:flex;flex-direction:column;position:fixed;top:0;left:0;height:100vh;z-index:10}
.brand{padding:16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px}
.brand-icon{font-size:22px}
.brand-name{font-size:16px;font-weight:700;color:var(--t1)}
.brand-sub{font-size:11px;color:var(--t3);margin-top:1px}
.nav{flex:1;padding:8px 0;overflow-y:auto}
.nav a{display:flex;align-items:center;gap:8px;padding:8px 14px;color:var(--t2);font-size:13px;border-radius:6px;margin:1px 8px;transition:background 0.12s,color 0.12s}
.nav a:hover{background:var(--card);color:var(--t1);text-decoration:none}
.nav a.active{background:rgba(88,166,255,0.12);color:var(--accent)}
.nav-icon{font-size:14px;width:18px;text-align:center}
.sidebar-foot{padding:12px 16px;border-top:1px solid var(--border);display:flex;align-items:center;gap:8px}
.ver{font-size:11px;color:var(--t3)}
.local-badge{font-size:10px;background:rgba(63,185,80,0.12);color:var(--ok);padding:2px 6px;border-radius:4px;font-weight:600;letter-spacing:.04em}
.main{margin-left:var(--sidebar);flex:1;padding:28px 32px;min-height:100vh;max-width:1100px}
.page-head{margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid var(--border);display:flex;align-items:flex-start;justify-content:space-between}
.page-title{font-size:20px;font-weight:600}
.page-sub{color:var(--t2);font-size:13px;margin-top:4px}
.refresh-hint{font-size:11px;color:var(--t3)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px}
.card-label{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--t3);margin-bottom:8px}
.card-val{font-size:22px;font-weight:700}
.card-val.ok{color:var(--ok)}
.card-val.warn{color:var(--warn)}
.card-val.err{color:var(--err)}
.card-val.dim{color:var(--t2)}
.section{margin-bottom:28px}
.section-title{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--t3);margin-bottom:10px}
.table-wrap{background:var(--card);border:1px solid var(--border);border-radius:8px;overflow:hidden}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:8px 14px;font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--t3);background:var(--surface);border-bottom:1px solid var(--border)}
td{padding:10px 14px;border-bottom:1px solid rgba(48,54,61,0.6);font-size:13px;vertical-align:middle}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,0.015)}
.mono{font-family:'SF Mono','Fira Mono','Cascadia Code',Consolas,monospace;font-size:12px}
code{background:rgba(110,118,129,0.12);padding:2px 6px;border-radius:4px;font-family:inherit;font-size:12px}
.badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600}
.badge-ok{background:rgba(63,185,80,0.12);color:var(--ok)}
.badge-err{background:rgba(248,81,73,0.12);color:var(--err)}
.badge-warn{background:rgba(210,153,34,0.12);color:var(--warn)}
.badge-info{background:rgba(88,166,255,0.12);color:var(--accent)}
.dot{width:8px;height:8px;border-radius:50%;display:inline-block;margin-right:6px}
.dot-ok{background:var(--ok);box-shadow:0 0 5px var(--ok)}
.dot-err{background:var(--err);box-shadow:0 0 5px var(--err)}
.dot-warn{background:var(--warn);box-shadow:0 0 5px var(--warn)}
.btn{padding:5px 10px;background:var(--surface);border:1px solid var(--border);color:var(--t2);border-radius:6px;cursor:pointer;font-size:12px;transition:all 0.12s;font-family:inherit}
.btn:hover{background:var(--card);color:var(--t1);border-color:var(--accent)}
.btn.copied{color:var(--ok);border-color:var(--ok)}
.empty{text-align:center;padding:40px 20px;color:var(--t3)}
.empty-icon{font-size:28px;margin-bottom:10px}
.alert{padding:12px 16px;border-radius:6px;font-size:13px;margin-bottom:16px}
.alert-info{background:rgba(88,166,255,0.08);border:1px solid rgba(88,166,255,0.25);color:var(--accent)}
.config-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.config-item{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px}
.config-key{font-size:11px;color:var(--t3);text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px}
.config-val{font-size:14px;font-weight:600}
.config-val.ok{color:var(--ok)}
.config-val.err{color:var(--err)}
.audit-list{list-style:none}
.audit-item{display:flex;align-items:flex-start;gap:12px;padding:10px 14px;border-bottom:1px solid rgba(48,54,61,0.5)}
.audit-item:last-child{border-bottom:none}
.audit-seq{font-size:11px;color:var(--t3);min-width:32px;padding-top:1px;font-family:monospace}
.audit-action{font-size:13px;color:var(--t1);font-weight:500}
.audit-resource{font-size:12px;color:var(--t2);margin-top:2px;word-break:break-all}
.demo-case{background:var(--card);border:1px solid var(--border);border-radius:8px;margin-bottom:16px;overflow:hidden}
.demo-case-title{padding:10px 14px;background:var(--surface);border-bottom:1px solid var(--border);font-size:13px;font-weight:600}
.demo-cols{display:grid;grid-template-columns:1fr 1fr;gap:0}
.demo-pane{padding:12px 14px}
.demo-pane+.demo-pane{border-left:1px solid var(--border)}
.demo-pane-label{font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--t3);margin-bottom:6px}
.demo-pane pre{background:transparent;padding:0;font-size:12px;white-space:pre-wrap;word-break:break-all}
.finding-pill{display:inline-block;background:rgba(248,81,73,0.1);color:var(--err);padding:1px 6px;border-radius:4px;font-size:11px;margin-top:4px}
.sealed-pill{display:inline-block;background:rgba(63,185,80,0.1);color:var(--ok);padding:1px 6px;border-radius:4px;font-size:11px;margin-top:4px}
@media(max-width:700px){.sidebar{width:100%;height:auto;position:relative;flex-direction:row;flex-wrap:wrap}.main{margin-left:0}.config-grid,.demo-cols{grid-template-columns:1fr}}"#
}

fn ui_js() -> &'static str {
    r#"
(function(){
  var t=30;
  var el=document.getElementById('countdown');
  var timer=setInterval(function(){
    t--;
    if(el)el.textContent=t+'s';
    if(t<=0){clearInterval(timer);location.reload();}
  },1000);
  document.addEventListener('click',function(e){
    var btn=e.target.closest('[data-copy]');
    if(!btn)return;
    var text=btn.getAttribute('data-copy');
    if(navigator.clipboard){
      navigator.clipboard.writeText(text).then(function(){
        var orig=btn.textContent;
        btn.textContent='Copied!';
        btn.classList.add('copied');
        setTimeout(function(){btn.textContent=orig;btn.classList.remove('copied');},1400);
      });
    }
  });
})();
"#
}

fn ui_shell(active: &str, content: &str) -> Html<String> {
    let nav_links = [
        ("overview", "/", "&#128275;", "Overview"),
        ("secrets", "/secrets", "&#128274;", "Secrets"),
        ("agents", "/agents", "&#129302;", "Agents"),
        ("relay", "/relay", "&#128257;", "Relay &amp; Policy"),
        ("audit", "/audit", "&#128196;", "Audit Log"),
        ("demo", "/demo", "&#9654;", "Demo"),
    ];
    let mut nav = String::new();
    for (page, href, icon, label) in &nav_links {
        let cls = if *page == active { "active" } else { "" };
        nav.push_str(&format!(
            r#"<a href="{href}" class="{cls}"><span class="nav-icon">{icon}</span>{label}</a>"#
        ));
    }
    let ver = env!("CARGO_PKG_VERSION");
    let mut html = String::with_capacity(8192);
    html.push_str(r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Lockrail</title><style>"#);
    html.push_str(ui_css());
    html.push_str("</style></head><body>");
    html.push_str(r#"<aside class="sidebar"><div class="brand"><span class="brand-icon">&#128274;</span><div><div class="brand-name">Lockrail</div><div class="brand-sub">Local Secret Firewall</div></div></div>"#);
    html.push_str(r#"<nav class="nav">"#);
    html.push_str(&nav);
    html.push_str("</nav>");
    html.push_str(&format!(
        r#"<div class="sidebar-foot"><span class="ver">v{ver}</span><span class="local-badge">&#128274; LOCAL</span></div>"#
    ));
    html.push_str("</aside><main class=\"main\">");
    html.push_str(content);
    html.push_str("</main><script>");
    html.push_str(ui_js());
    html.push_str("</script></body></html>");
    Html(html)
}

async fn ui_api_status(State(state): State<UiState>) -> Json<serde_json::Value> {
    let cli = Cli {
        home: Some(state.home.clone()),
        password: Some(state.password.expose_secret().to_string()),
        json: true,
        quiet: false,
        command: Commands::Status,
    };
    let snap = status_snapshot(&cli).ok();
    Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "status": snap,
    }))
}

async fn ui_api_secrets(State(state): State<UiState>) -> Json<serde_json::Value> {
    let vault = match Vault::open(state.home.join("vault.lockrail"), state.password.clone()) {
        Ok(v) => v,
        Err(e) => return Json(serde_json::json!({"error": e.to_string()})),
    };
    let list: Vec<_> = vault
        .list_secret_metadata()
        .into_iter()
        .map(|m| {
            serde_json::json!({
                "name": m.name,
                "kind": m.kind,
                "fingerprint": m.fingerprint,
                "created_at": m.created_at,
                "last_used_at": m.last_used_at,
            })
        })
        .collect();
    Json(serde_json::json!({"secrets": list}))
}

async fn ui_api_audit(State(state): State<UiState>) -> Json<serde_json::Value> {
    let events = AuditLog::new(state.home.join("audit.jsonl"))
        .read_all()
        .unwrap_or_default();
    let recent: Vec<_> = events
        .into_iter()
        .rev()
        .take(50)
        .map(|e| {
            serde_json::json!({
                "seq": e.sequence,
                "ts": e.timestamp,
                "action": e.action,
                "resource": e.resource,
            })
        })
        .collect();
    Json(serde_json::json!({"events": recent}))
}

async fn ui_overview(State(state): State<UiState>) -> Html<String> {
    let cli = Cli {
        home: Some(state.home.clone()),
        password: Some(state.password.expose_secret().to_string()),
        json: false,
        quiet: false,
        command: Commands::Status,
    };
    let snap = status_snapshot(&cli);
    let mut content = String::new();

    content.push_str(r#"<div class="page-head"><div><div class="page-title">Overview</div><div class="page-sub">Local secret firewall status</div></div><div class="refresh-hint">Auto-refresh in <span id="countdown">30</span></div></div>"#);

    match snap {
        Ok(s) => {
            let vault_dot = if s.vault_encrypted && s.vault_permissions_ok {
                "ok"
            } else {
                "err"
            };
            let audit_dot = if s.audit_ok { "ok" } else { "warn" };
            let tools_count = s
                .protected_tools
                .values()
                .filter(|v| v.contains("shim"))
                .count();

            content.push_str("<div class=\"cards\">");
            content.push_str(&format!(
                r#"<div class="card"><div class="card-label">Vault</div><div class="card-val {vault_dot}"><span class="dot dot-{vault_dot}"></span>{}</div></div>"#,
                if s.vault_encrypted { "Encrypted" } else { "Unencrypted" }
            ));
            content.push_str(&format!(
                r#"<div class="card"><div class="card-label">Vault Unlocked</div><div class="card-val {}">{}</div></div>"#,
                if s.vault_unlocked { "ok" } else { "dim" },
                if s.vault_unlocked { "Yes" } else { "No" }
            ));
            content.push_str(&format!(
                r#"<div class="card"><div class="card-label">Protected Tools</div><div class="card-val {}">{}</div></div>"#,
                if tools_count > 0 { "ok" } else { "warn" },
                tools_count
            ));
            content.push_str(&format!(
                r#"<div class="card"><div class="card-label">Audit Chain</div><div class="card-val {audit_dot}"><span class="dot dot-{audit_dot}"></span>{}</div></div>"#,
                if s.audit_ok { "Valid" } else { "Check" }
            ));
            content.push_str(&format!(
                r#"<div class="card"><div class="card-label">SSRF Blocking</div><div class="card-val {}">{}</div></div>"#,
                if s.private_network_blocking_enabled { "ok" } else { "warn" },
                if s.private_network_blocking_enabled { "Enabled" } else { "Disabled" }
            ));
            content.push_str(&format!(
                r#"<div class="card"><div class="card-label">Signed Receipts</div><div class="card-val {}">{}</div></div>"#,
                if s.receipts_enabled { "ok" } else { "dim" },
                if s.receipts_enabled { "Enabled" } else { "Off" }
            ));
            content.push_str("</div>");

            if !s.protected_tools.is_empty() {
                content.push_str("<div class=\"section\"><div class=\"section-title\">Protected Tools</div><div class=\"table-wrap\"><table><thead><tr><th>Tool</th><th>Status</th></tr></thead><tbody>");
                for (tool, detail) in &s.protected_tools {
                    let badge_cls = if detail.contains("shim") {
                        "badge-ok"
                    } else {
                        "badge-warn"
                    };
                    content.push_str(&format!(
                        "<tr><td class=\"mono\">{}</td><td><span class=\"badge {badge_cls}\">{}</span></td></tr>",
                        html_escape(tool),
                        html_escape(detail)
                    ));
                }
                content.push_str("</tbody></table></div></div>");
            }

            if !s.recent_activity.is_empty() {
                content.push_str("<div class=\"section\"><div class=\"section-title\">Recent Activity</div><div class=\"table-wrap\"><ul class=\"audit-list\">");
                for item in &s.recent_activity {
                    content.push_str(&format!(
                        "<li class=\"audit-item\"><span class=\"audit-action\">{}</span></li>",
                        html_escape(item)
                    ));
                }
                content.push_str("</ul></div></div>");
            }
        }
        Err(e) => {
            content.push_str(&format!(
                "<div class=\"alert alert-info\">Could not load status: {}</div>",
                html_escape(&redact_for_logs(&e.to_string()))
            ));
        }
    }

    ui_shell("overview", &content)
}

async fn ui_secrets(State(state): State<UiState>) -> Html<String> {
    let mut content = String::new();
    content.push_str(r#"<div class="page-head"><div><div class="page-title">Secrets</div><div class="page-sub">Sealed secrets stored in the encrypted vault</div></div><div class="refresh-hint">Auto-refresh in <span id="countdown">30</span></div></div>"#);

    match Vault::open(state.home.join("vault.lockrail"), state.password.clone()) {
        Ok(vault) => {
            let items = vault.list_secret_metadata();
            if items.is_empty() {
                content.push_str(r#"<div class="empty"><div class="empty-icon">&#128274;</div><div>No sealed secrets yet.<br><code>echo "sk-proj-..." | lockrail seal</code></div></div>"#);
            } else {
                content.push_str(&format!(
                    r#"<div class="alert alert-info">&#128274; {} secret{} — handles shown below are safe to share with agents</div>"#,
                    items.len(),
                    if items.len() == 1 { "" } else { "s" }
                ));
                content.push_str("<div class=\"table-wrap\"><table><thead><tr><th>Name</th><th>Kind</th><th>Fingerprint</th><th>Created</th><th>Last Used</th><th>Handle</th></tr></thead><tbody>");
                for item in &items {
                    let handle = format!(
                        "lockrail://secret/{}/{}",
                        html_escape(&item.kind),
                        html_escape(&item.fingerprint)
                    );
                    let last_used = item
                        .last_used_at
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "never".to_string());
                    content.push_str(&format!(
                        "<tr><td class=\"mono\">{}</td><td><span class=\"badge badge-info\">{}</span></td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td class=\"mono\">{}</td><td><button class=\"btn\" data-copy=\"{handle}\" title=\"{handle}\">Copy handle</button></td></tr>",
                        html_escape(&item.name),
                        html_escape(&item.kind),
                        html_escape(&item.fingerprint),
                        item.created_at,
                        html_escape(&last_used),
                    ));
                }
                content.push_str("</tbody></table></div>");
            }
        }
        Err(e) => {
            content.push_str(&format!(
                "<div class=\"alert alert-info\">Vault error: {}</div>",
                html_escape(&redact_for_logs(&e.to_string()))
            ));
        }
    }

    ui_shell("secrets", &content)
}

async fn ui_agents(State(state): State<UiState>) -> Html<String> {
    let mut content = String::new();
    content.push_str(r#"<div class="page-head"><div><div class="page-title">Agents</div><div class="page-sub">Ed25519 agent identities for capability signing</div></div><div class="refresh-hint">Auto-refresh in <span id="countdown">30</span></div></div>"#);

    match Vault::open(state.home.join("vault.lockrail"), state.password.clone()) {
        Ok(vault) => {
            let items = vault.list_agents();
            if items.is_empty() {
                content.push_str(r#"<div class="empty"><div class="empty-icon">&#129302;</div><div>No agents yet.<br><code>lockrail agent create my-agent --type claude-code</code></div></div>"#);
            } else {
                content.push_str("<div class=\"table-wrap\"><table><thead><tr><th>Name</th><th>Kind</th><th>Public Key</th><th>Status</th></tr></thead><tbody>");
                for item in &items {
                    let status_badge = if item.revoked {
                        r#"<span class="badge badge-err">Revoked</span>"#
                    } else {
                        r#"<span class="badge badge-ok">Active</span>"#
                    };
                    let pubkey_short = if item.public_key.len() > 24 {
                        format!("{}…", &item.public_key[..24])
                    } else {
                        item.public_key.clone()
                    };
                    content.push_str(&format!(
                        "<tr><td class=\"mono\">{}</td><td><span class=\"badge badge-info\">{}</span></td><td class=\"mono\" title=\"{}\">{}</td><td>{status_badge}</td></tr>",
                        html_escape(&item.name),
                        html_escape(&item.kind),
                        html_escape(&item.public_key),
                        html_escape(&pubkey_short),
                    ));
                }
                content.push_str("</tbody></table></div>");
            }
        }
        Err(e) => {
            content.push_str(&format!(
                "<div class=\"alert alert-info\">Vault error: {}</div>",
                html_escape(&redact_for_logs(&e.to_string()))
            ));
        }
    }

    ui_shell("agents", &content)
}

async fn ui_relay(State(state): State<UiState>) -> Html<String> {
    let cli = Cli {
        home: Some(state.home.clone()),
        password: Some(state.password.expose_secret().to_string()),
        json: false,
        quiet: false,
        command: Commands::Relay {
            command: RelayCommands::Check,
        },
    };
    let config = load_config(&cli).unwrap_or_default();

    let mut content = String::new();
    content.push_str(r#"<div class="page-head"><div><div class="page-title">Relay &amp; Policy</div><div class="page-sub">HTTP relay configuration and security policy</div></div><div class="refresh-hint">Auto-refresh in <span id="countdown">30</span></div></div>"#);
    content.push_str("<div class=\"config-grid\">");

    let items = [
        ("Listen Address", config.relay_listen.as_str(), true),
        (
            "SSRF Blocking",
            if config.block_private_networks {
                "Enabled"
            } else {
                "Disabled"
            },
            config.block_private_networks,
        ),
        (
            "Signed Receipts",
            if config.signed_receipts {
                "Enabled"
            } else {
                "Disabled"
            },
            config.signed_receipts,
        ),
        (
            "Redirects",
            if config.redirects_disabled {
                "Disabled (safe)"
            } else {
                "Allowed"
            },
            config.redirects_disabled,
        ),
        (
            "Require Agent Proof",
            if config.require_agent_proof {
                "Yes"
            } else {
                "No"
            },
            config.require_agent_proof,
        ),
    ];
    for (key, val, is_ok) in &items {
        let val_cls = if *is_ok { "ok" } else { "err" };
        content.push_str(&format!(
            r#"<div class="config-item"><div class="config-key">{key}</div><div class="config-val {val_cls}">{}</div></div>"#,
            html_escape(val)
        ));
    }

    content.push_str("</div>");

    if !config.provider_presets.is_empty() {
        content.push_str("<div class=\"section\"><div class=\"section-title\">Active Provider Presets</div><div style=\"display:flex;gap:8px;flex-wrap:wrap\">");
        for preset_id in &config.provider_presets {
            content.push_str(&format!(
                "<span class=\"badge badge-info\">{}</span>",
                html_escape(preset_id)
            ));
        }
        content.push_str("</div></div>");
    }

    content.push_str(r#"<div class="alert alert-info" style="margin-top:16px">&#128257; Start the relay: <code>lockrail relay start</code> &nbsp;|&nbsp; Then use <code>lockrail capability issue &lt;key&gt;</code> to issue time-bound capabilities</div>"#);

    ui_shell("relay", &content)
}

async fn ui_audit(State(state): State<UiState>) -> Html<String> {
    let events = AuditLog::new(state.home.join("audit.jsonl"))
        .read_all()
        .unwrap_or_default();

    let mut content = String::new();
    content.push_str(&format!(
        r#"<div class="page-head"><div><div class="page-title">Audit Log</div><div class="page-sub">Tamper-evident SHA-256 hash-chained event log &mdash; {} total event{}</div></div><div class="refresh-hint">Auto-refresh in <span id="countdown">30</span></div></div>"#,
        events.len(),
        if events.len() == 1 { "" } else { "s" }
    ));

    let verify_ok = AuditLog::new(state.home.join("audit.jsonl"))
        .verify()
        .is_ok();
    if verify_ok {
        content.push_str(r#"<div class="alert alert-info">&#10003; Audit chain verified — no tampering detected</div>"#);
    } else {
        content.push_str(r#"<div class="alert" style="background:rgba(248,81,73,0.08);border:1px solid rgba(248,81,73,0.3);color:var(--err)">&#9888; Audit chain verification failed — run <code>lockrail audit verify</code></div>"#);
    }

    if events.is_empty() {
        content.push_str(r#"<div class="empty"><div class="empty-icon">&#128196;</div><div>No audit events yet.<br>Events are recorded as you use Lockrail.</div></div>"#);
    } else {
        content.push_str("<div class=\"table-wrap\"><ul class=\"audit-list\">");
        for event in events.iter().rev().take(50) {
            let action_badge = if event.action.starts_with("relay.denied") {
                format!(
                    "<span class=\"badge badge-err\">{}</span>",
                    html_escape(&event.action)
                )
            } else if event.action.starts_with("relay.") {
                format!(
                    "<span class=\"badge badge-ok\">{}</span>",
                    html_escape(&event.action)
                )
            } else {
                format!(
                    "<span class=\"badge badge-info\">{}</span>",
                    html_escape(&event.action)
                )
            };
            content.push_str(&format!(
                "<li class=\"audit-item\"><span class=\"audit-seq\">#{}</span><div><div class=\"audit-action\">{action_badge}</div>{}",
                event.sequence,
                if event.resource.is_empty() { String::new() } else {
                    format!("<div class=\"audit-resource mono\">{}</div>", html_escape(&event.resource))
                }
            ));
            content.push_str("</div></li>");
        }
        if events.len() > 50 {
            content.push_str(&format!(
                "<li class=\"audit-item\"><span style=\"color:var(--t3);font-size:12px\">… {} earlier events not shown</span></li>",
                events.len() - 50
            ));
        }
        content.push_str("</ul></div>");
    }

    ui_shell("audit", &content)
}

async fn ui_demo(State(state): State<UiState>) -> Html<String> {
    let cli = Cli {
        home: Some(state.home.clone()),
        password: Some(state.password.expose_secret().to_string()),
        json: false,
        quiet: false,
        command: Commands::Demo,
    };

    let mut content = String::new();
    content.push_str(r#"<div class="page-head"><div><div class="page-title">Demo</div><div class="page-sub">See how Lockrail intercepts and seals secrets before they reach AI models</div></div></div>"#);
    content.push_str(r#"<div class="alert alert-info">&#128274; Each case below shows the raw input an agent would paste, and the safe output Lockrail produces. The original secrets are never transmitted.</div>"#);

    match demo_cases(&cli) {
        Ok(cases) => {
            for case in &cases {
                let findings_html: String = case
                    .findings
                    .iter()
                    .filter_map(|f| f.get("kind").and_then(|k| k.as_str()))
                    .map(|kind| {
                        format!("<span class=\"finding-pill\">{}</span> ", html_escape(kind))
                    })
                    .collect();
                let sealed_html: String = case
                    .findings
                    .iter()
                    .filter_map(|f| f.get("fingerprint").and_then(|fp| fp.as_str()))
                    .map(|fp| {
                        format!(
                            "<span class=\"sealed-pill\">&#128274; {}</span> ",
                            html_escape(fp)
                        )
                    })
                    .collect();
                content.push_str(&format!(
                    r#"<div class="demo-case"><div class="demo-case-title">&#9654; {}</div><div class="demo-cols"><div class="demo-pane"><div class="demo-pane-label">&#128274; Raw input (would leak)</div><pre>{}</pre>{findings_html}</div><div class="demo-pane"><div class="demo-pane-label">&#10003; Safe output (model sees)</div><pre>{}</pre>{sealed_html}</div></div></div>"#,
                    html_escape(&case.name),
                    html_escape(&redact_for_display(&case.raw_input)),
                    html_escape(&case.safe_output),
                ));
            }
        }
        Err(e) => {
            content.push_str(&format!(
                "<div class=\"alert alert-info\">Run <code>lockrail setup</code> once. Error: {}</div>",
                html_escape(&redact_for_logs(&e.to_string()))
            ));
        }
    }

    ui_shell("demo", &content)
}

/// Axum middleware: require X-Lockrail-Token header or ?token= query param.
/// Returns 401 if the token is missing or does not match.
async fn require_ui_token(
    State(state): State<UiState>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let provided = headers
        .get("x-lockrail-token")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .or_else(|| params.get("token").cloned());

    match provided {
        Some(t) if t == state.session_token => next.run(request).await,
        _ => (
            StatusCode::UNAUTHORIZED,
            Html(r#"<!DOCTYPE html><html><body style="background:#050508;color:#f85149;font-family:monospace;display:flex;height:100vh;align-items:center;justify-content:center"><h2>401 — Lockrail UI token required.<br><small>Open the URL printed by <code>lockrail ui</code>.</small></h2></body></html>"#),
        )
            .into_response(),
    }
}

fn ui_router(home: PathBuf, password: SecretString, session_token: String) -> Router {
    let state = UiState {
        home,
        password,
        session_token,
    };
    // /healthz is exempt from auth (used by health checks)
    Router::new()
        .route("/", get(ui_overview))
        .route("/secrets", get(ui_secrets))
        .route("/agents", get(ui_agents))
        .route("/relay", get(ui_relay))
        .route("/audit", get(ui_audit))
        .route("/demo", get(ui_demo))
        .route("/api/status", get(ui_api_status))
        .route("/api/secrets", get(ui_api_secrets))
        .route("/api/audit", get(ui_api_audit))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_ui_token,
        ))
        .route(
            "/healthz",
            get(|| async {
                Json(serde_json::json!({"status":"ok","version":env!("CARGO_PKG_VERSION")}))
            }),
        )
        .with_state(state)
}

async fn start_ui(
    cli: &Cli,
    listen: Option<SocketAddr>,
) -> Result<(tokio::net::TcpListener, Router, serde_json::Value)> {
    let preferred =
        listen.unwrap_or_else(|| "127.0.0.1:8790".parse().expect("valid loopback address"));
    let listener = match tokio::net::TcpListener::bind(preferred).await {
        Ok(listener) => listener,
        Err(_) if listen.is_none() => tokio::net::TcpListener::bind("127.0.0.1:0").await?,
        Err(error) => return Err(error.into()),
    };
    let addr = listener.local_addr()?;
    // Generate a random session token so only the process that starts the UI
    // (i.e., the legitimate user) knows the URL to open.
    let token = {
        use rand_core::RngCore;
        let mut bytes = [0u8; 24];
        rand_core::OsRng.fill_bytes(&mut bytes);
        hex::encode(bytes)
    };
    let router = ui_router(home(cli), password(cli)?, token.clone());
    let authenticated_url = format!("http://{}/?token={}", addr, token);
    let details = serde_json::json!({
        "url": authenticated_url,
        "listen": addr,
        "local_only": listen.is_none(),
        "token_protected": true,
    });
    Ok((listener, router, details))
}

fn load_config(cli: &Cli) -> Result<AppConfig> {
    if !config_path(cli).exists() {
        return Ok(AppConfig::default());
    }
    Ok(serde_json::from_slice(&fs::read(config_path(cli))?)?)
}

fn save_config(cli: &Cli, config: &AppConfig) -> Result<()> {
    if let Some(parent) = config_path(cli).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(config_path(cli), serde_json::to_vec_pretty(config)?)?;
    Ok(())
}

fn relay_state(cli: &Cli) -> Result<RelayState> {
    let vault = Vault::open(vault_path(cli), password(cli)?)?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    Ok(RelayState {
        vault: Arc::new(Mutex::new(vault)),
        audit: AuditLog::new(audit_path(cli)),
        replay_store: Arc::new(FileReplayStore::new(replay_path(cli))),
        usage_store: Arc::new(FileUsageStore::new(usage_path(cli))),
        client,
    })
}

#[allow(clippy::too_many_arguments)]
fn preset_claims(
    cli: &Cli,
    key_name: &str,
    minutes: i64,
    hosts: Vec<String>,
    methods: Vec<String>,
    paths: Vec<String>,
    selected_preset: Option<&str>,
    agent: Option<String>,
    task_id: Option<String>,
    purpose: Option<String>,
) -> Result<CapabilityClaims> {
    let resolved_preset = selected_preset.and_then(preset);
    let mut claims = CapabilityClaims::new(
        key_name.to_string(),
        minutes,
        if hosts.is_empty() {
            resolved_preset
                .map(|preset| preset.hosts.iter().map(|host| host.to_string()).collect())
                .unwrap_or_default()
        } else {
            hosts
        },
        if methods.is_empty() {
            resolved_preset
                .map(|preset| {
                    preset
                        .methods
                        .iter()
                        .map(|method| method.to_string())
                        .collect()
                })
                .unwrap_or_else(|| vec!["POST".to_string()])
        } else {
            methods
        },
        if paths.is_empty() {
            resolved_preset
                .map(|preset| preset.paths.iter().map(|path| path.to_string()).collect())
                .unwrap_or_else(|| vec!["/*".to_string()])
        } else {
            paths
        },
        resolved_preset
            .map(|preset| preset.inject_header.to_string())
            .unwrap_or_else(|| "Authorization".to_string()),
        resolved_preset
            .map(|preset| preset.inject_prefix.to_string())
            .unwrap_or_else(|| "Bearer ".to_string()),
        resolved_preset
            .map(|preset| preset.recommended_max_uses)
            .or(Some(10)),
        None,
        task_id,
        purpose,
    );
    if let Some(preset) = resolved_preset {
        claims.allowed_schemes = preset
            .schemes
            .iter()
            .map(|value| value.to_string())
            .collect();
        claims.allowed_ports = preset.ports.to_vec();
        claims.allowed_paths = default_path_rules(preset.paths);
        claims.query_policy = preset.query_policy;
        claims.max_uses = Some(preset.recommended_max_uses);
        if matches!(preset.injection_method, InjectionMethod::Query) {
            claims.allowed_query_prefixes = vec![format!("{}=", preset.inject_header)];
        }
    }
    if let Some(agent_id) = agent {
        let vault = Vault::open(vault_path(cli), password(cli)?)?;
        let public = vault.agent_public(&agent_id)?;
        claims.agent_public_key = Some(public.public_key);
        claims.require_proof = true;
    }
    Ok(claims)
}

fn agent_by_name(vault: &Vault, name: &str) -> Result<lockrail_protocol::AgentPublicDoc> {
    vault
        .list_agents()
        .into_iter()
        .find(|agent| agent.agent_id == name || agent.name == name)
        .ok_or_else(|| anyhow!("agent not found"))
}

fn ca_path(cli: &Cli) -> PathBuf {
    home(cli).join("proxy-ca.json")
}

fn proxy_cert_path(cli: &Cli) -> PathBuf {
    home(cli).join("lockrail-proxy-ca.crt")
}

/// Emits the LOCKRAIL_PASSWORD env-var warning at most once per install
/// (uses a marker file so it isn't repeated on every subsequent invocation).
fn warn_password_in_env_once(home: &Path, quiet: bool) {
    static WARNED: OnceLock<()> = OnceLock::new();
    if quiet || std::env::var("LOCKRAIL_PASSWORD").is_err() {
        return;
    }
    let marker = home.join(".env_pw_warned");
    if marker.exists() {
        return;
    }
    WARNED.get_or_init(|| {
        eprintln!(
            "lockrail: NOTE — LOCKRAIL_PASSWORD is set as an env var, which can appear in\n\
             shell history and process listings. Prefer an interactive prompt or `op run -- lockrail`.\n\
             (This notice won't repeat. Use --quiet to suppress.)"
        );
        let _ = fs::write(&marker, b"");
    });
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    // Show the env-var warning only for commands that open the vault,
    // and only once total (marker file suppresses on repeat invocations).
    let accesses_vault = !matches!(
        cli.command,
        Commands::Demo | Commands::Explain { .. } | Commands::Doctor
    );
    if accesses_vault {
        warn_password_in_env_once(&home(&cli), cli.quiet);
    }
    if let Err(error) = run(cli).await {
        let safe = redact_for_logs(&format!("{error:#}"));
        eprintln!("{safe}");
        if error.chain().any(|cause| {
            matches!(
                cause.downcast_ref::<VaultError>(),
                Some(VaultError::WrongPassword)
            )
        }) {
            eprintln!(
                "Try: unset LOCKRAIL_PASSWORD && lockrail setup\n\
                 Or reset local Lockrail state: lockrail setup --reset\n\
                 Reset archives the old ~/.lockrail directory before creating a fresh setup."
            );
        }
        std::process::exit(exit_code_for_error(&error));
    }
}

async fn run(cli: Cli) -> Result<()> {
    match &cli.command {
        Commands::Init {
            yes,
            skip_shims,
            fast_kdf_test_only,
        } => {
            let result = init_lockrail(&cli, *yes, *skip_shims, *fast_kdf_test_only)?;
            if cli.json {
                print_value(&cli, &result)?;
            } else if !cli.quiet {
                println!("lockrail//ready");
                println!("------------------------------------------------------------");
                println!("[vault]    encrypted local store online");
                println!("[audit]    hash chain initialized");
                println!("[network]  no Lockrail cloud dependency");
                println!();
                println!("tool shims");
                for tool in ["claude", "codex", "cursor", "agy"] {
                    let mark = if result["protected_tools"][tool].as_bool().unwrap_or(false) {
                        "armed"
                    } else {
                        "standby"
                    };
                    println!("  {tool:<8} {mark}");
                }
                println!();
                println!("next");
                println!("  lockrail demo");
                println!("  echo 'OPENAI_API_KEY=sk-proj-demo...' | lockrail seal --json");
                println!("  lockrail status");
            }
        }
        Commands::Setup {
            apply: _,
            reset,
            tools,
        } => {
            let result = setup_apply(&cli, tools, *reset)?;
            if cli.json {
                print_value(&cli, &result)?;
            } else if !cli.quiet {
                println!("lockrail//setup complete");
                println!("------------------------------------------------------------");
                if let Some(backup) = result["recovered_from"].as_str() {
                    println!("[reset]    archived previous state at {backup}");
                }
                println!("[vault]    encrypted local store ready");
                if result["credential_mode"] == "generated_local_key" {
                    println!("[key]      generated and stored locally");
                } else {
                    println!("[key]      using supplied password");
                }
                println!("[keys]     local agent identity ready");
                println!("[network]  no account or Lockrail cloud required");
                println!();
                println!("tool shims");
                for tool in result["tools"].as_array().into_iter().flatten() {
                    if let Some(tool) = tool.as_str() {
                        println!("  {tool:<8} armed");
                    }
                }
                if let Some(path_prepend) = result["shims"]["path_prepend"].as_str() {
                    println!();
                    println!("shell path");
                    println!("  {path_prepend}");
                    println!("  # open a new terminal after adding this to your shell profile");
                }
                println!();
                println!("next");
                println!("  lockrail demo");
                println!("  claude   # or codex / cursor / agy if installed");
            }
        }
        Commands::Protect { tool, yes } => {
            let result = protect_tool(&cli, tool.clone(), *yes)?;
            print_value(&cli, &result)?;
        }
        Commands::Demo => {
            let cases = demo_cases(&cli)?;
            if cli.json {
                print_value(&cli, &serde_json::to_value(&cases)?)?;
            } else if !cli.quiet {
                for case in cases {
                    println!("Raw input:");
                    println!("{}", case.raw_input);
                    println!("Lockrail output:");
                    println!("{}", case.safe_output);
                    println!("Proof:");
                    for proof in case.proof {
                        println!("✓ {}", proof);
                    }
                    println!();
                }
            }
        }
        Commands::Status => {
            let status = status_snapshot(&cli)?;
            if cli.json {
                print_value(&cli, &serde_json::to_value(status)?)?;
            } else if !cli.quiet {
                println!("lockrail//status");
                println!("------------------------------------------------------------");
                println!("vault");
                println!("  encrypted       online");
                println!(
                    "  unlock          {}",
                    if status.vault_unlocked {
                        "ok"
                    } else {
                        "locked"
                    }
                );
                println!(
                    "  file mode       {}",
                    if status.vault_permissions_ok {
                        "0600"
                    } else {
                        "check"
                    }
                );
                println!();
                println!("tool shims");
                for (tool, detail) in status.protected_tools {
                    let mark = if detail.starts_with("Pass") {
                        "armed"
                    } else if detail.starts_with("Warn") {
                        "warn"
                    } else {
                        "none"
                    };
                    println!("  {tool:<8} {mark:<6} {detail}");
                }
                println!();
                println!("security");
                println!(
                    "  audit chain     {}",
                    if status.audit_ok { "valid" } else { "broken" }
                );
                println!(
                    "  replay cache    {}",
                    if status.replay_writable {
                        "writable"
                    } else {
                        "blocked"
                    }
                );
                println!(
                    "  receipts        {}",
                    if status.receipts_enabled {
                        "signed"
                    } else {
                        "disabled"
                    }
                );
                println!(
                    "  private nets    {}",
                    if status.private_network_blocking_enabled {
                        "blocked"
                    } else {
                        "allowed"
                    }
                );
                println!();
                println!("recent activity");
                for line in status.recent_activity {
                    println!("  - {line}");
                }
            }
        }
        Commands::Ui { listen } => {
            let (listener, router, result) = start_ui(&cli, *listen).await?;
            print_value(&cli, &result)?;
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
        }
        Commands::Explain { topic } => {
            print_value(&cli, &serde_json::json!(explain_text(topic.as_ref())))?;
        }
        Commands::Harness { command } => match command {
            HarnessCommands::Check => {
                let report = harness_check_report(&cli);
                print_harness_report(&cli, &report)?;
                if report.overall == HarnessState::Fail {
                    std::process::exit(1);
                }
            }
            HarnessCommands::Test { tool } => {
                let report = harness_test_report(&cli, tool.clone());
                print_harness_report(&cli, &report)?;
                if report.overall == HarnessState::Fail {
                    std::process::exit(1);
                }
            }
        },
        Commands::Env { command } => match command {
            EnvCommands::Scan { path, aggressive } => {
                print_value(&cli, &env_scan(&cli, path, *aggressive)?)?;
            }
            EnvCommands::Seal {
                path,
                out,
                dry_run,
                prefix,
                aggressive,
            } => {
                print_value(
                    &cli,
                    &env_seal(&cli, path, out, prefix, *aggressive, *dry_run)?,
                )?;
            }
            EnvCommands::Run {
                file,
                dry_run,
                command,
            } => {
                print_value(&cli, &env_run(&cli, file, command, *dry_run)?)?;
            }
        },
        Commands::Pipe { prefix, aggressive } => {
            let input = std::io::read_to_string(std::io::stdin())?;
            let result = scan_and_seal(&cli, &input, prefix, *aggressive)?;
            if cli.json {
                print_value(&cli, &result)?;
            } else if let Some(safe) = result.get("safe_text").and_then(serde_json::Value::as_str) {
                print!("{safe}");
            }
        }
        Commands::Output { command } => match command {
            OutputCommands::Scan { text, aggressive } => {
                let input = read_input(text)?;
                let findings = scan_text(
                    &input,
                    ScanOptions {
                        aggressive: *aggressive,
                        protection_mode: true,
                    },
                );
                print_value(
                    &cli,
                    &serde_json::json!({
                        "count": findings.len(),
                        "findings": findings.iter().map(|finding| serde_json::json!({
                            "kind": finding.kind,
                            "fingerprint": finding.fingerprint,
                            "preview": finding.preview,
                        })).collect::<Vec<_>>(),
                        "safe_text": redact_for_display(&input),
                    }),
                )?;
            }
            OutputCommands::Seal {
                text,
                prefix,
                aggressive,
            } => {
                let input = read_input(text)?;
                let result = scan_and_seal(&cli, &input, prefix, *aggressive)?;
                print_value(&cli, &result)?;
            }
        },
        Commands::Proof { command } => match command {
            ProofCommands::Pack { out, markdown } => {
                print_value(&cli, &proof_pack(&cli, out, *markdown)?)?;
            }
        },
        Commands::Doctor => {
            let report = doctor(&cli);
            if cli.json {
                print_value(&cli, &report)?;
            } else if !cli.quiet {
                println!("lockrail//doctor");
                println!("------------------------------------------------------------");
                println!(
                    "status      {}",
                    if report["ok"].as_bool().unwrap_or(false) {
                        "ok"
                    } else {
                        "needs attention"
                    }
                );
                println!(
                    "home        {}",
                    report["checks"]["home"].as_str().unwrap_or("-")
                );
                println!(
                    "binary      {}",
                    report["checks"]["active_lockrail"]
                        .as_str()
                        .unwrap_or("not on PATH")
                );
                println!(
                    "vault       {}",
                    if report["checks"]["vault_exists"].as_bool().unwrap_or(false) {
                        "present"
                    } else {
                        "missing"
                    }
                );
                println!(
                    "vault key   {}",
                    if report["checks"]["vault_key_exists"]
                        .as_bool()
                        .unwrap_or(false)
                    {
                        "present"
                    } else {
                        "missing"
                    }
                );
                println!(
                    "audit       {}",
                    report["checks"]["audit_verify"]["message"]
                        .as_str()
                        .unwrap_or("unknown")
                );
                if let Some(fixes) = report["fixes"].as_array()
                    && !fixes.is_empty()
                {
                    println!();
                    println!("fix");
                    for fix in fixes {
                        if let Some(fix) = fix.as_str() {
                            println!("  {fix}");
                        }
                    }
                }
            }
            if !report["ok"].as_bool().unwrap_or(false) {
                std::process::exit(1);
            }
        }
        Commands::Scan { text, aggressive } => {
            let input = read_input(text)?;
            let findings = scan_text(
                &input,
                ScanOptions {
                    aggressive: *aggressive,
                    protection_mode: true,
                },
            );
            print_value(
                &cli,
                &serde_json::json!({
                    "count": findings.len(),
                    "findings": findings.iter().map(|finding| serde_json::json!({
                        "kind": finding.kind,
                        "fingerprint": finding.fingerprint,
                        "confidence": finding.confidence,
                        "should_seal": finding.should_seal,
                        "preview": finding.preview,
                    })).collect::<Vec<_>>(),
                    "safe_text": redact_for_display(&input),
                }),
            )?;
        }
        Commands::Seal {
            text,
            prefix,
            aggressive,
        } => {
            let input = read_input(text)?;
            let result = scan_and_seal(&cli, &input, prefix, *aggressive)?;
            if cli.json {
                print_value(&cli, &result)?;
            } else if let Some(safe) = result.get("safe_text").and_then(serde_json::Value::as_str) {
                print!("{safe}");
            }
        }
        Commands::Hook { command } => match command {
            HookCommands::Prompt { prefix, aggressive } => {
                let input = std::io::read_to_string(std::io::stdin())?;
                let result = scan_and_seal(&cli, &input, prefix, *aggressive)?;
                if cli.json {
                    print_value(&cli, &result)?;
                } else if let Some(safe) =
                    result.get("safe_text").and_then(serde_json::Value::as_str)
                {
                    print!("{safe}");
                }
            }
            HookCommands::PostToolUse { prefix, aggressive } => {
                let input = std::io::read_to_string(std::io::stdin())?;
                let scan_text_content = text_for_post_tool_use_scan(&input);
                let findings = scan_text(
                    &scan_text_content,
                    ScanOptions {
                        aggressive: *aggressive,
                        protection_mode: true,
                    },
                );
                let sealed_count = findings.iter().filter(|f| f.should_seal).count();
                if sealed_count > 0 {
                    // Save the sealed secrets to vault
                    let sealed = seal_text(
                        &scan_text_content,
                        SealOptions {
                            aggressive: *aggressive,
                            protection_mode: true,
                        },
                    );
                    let mut vault = Vault::open(vault_path(&cli), password(&cli)?)?;
                    save_sealed_findings(&mut vault, prefix, &sealed.findings)?;
                    AuditLog::new(audit_path(&cli)).append(
                        "hook.post_tool_use.blocked",
                        "tool_output",
                        serde_json::json!({"count": sealed_count}),
                    )?;
                    eprintln!(
                        "lockrail: blocked {} secret(s) in tool output",
                        sealed_count
                    );
                    // Output the safe version and exit 2 to block Claude from seeing raw secrets
                    print!("{}", sealed.safe_text);
                    std::process::exit(2);
                }
                // No secrets found — pass through (print nothing, exit 0)
            }
        },
        Commands::Run { command } => {
            if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                run_interactive(&cli, command)?;
            } else {
                run_piped(&cli, command)?;
            }
        }
        Commands::Secret { command } => match command {
            SecretCommands::List { env } => {
                let vault = Vault::open(vault_path(&cli), password(&cli)?)?;
                // When --env is given, filter by that environment.
                // Always exclude internal keys (agent-private/) and demo scratch keys
                // (demo.*) from the user-facing list — those are managed by other commands.
                let all = vault.list_secret_metadata();
                let is_user_secret =
                    |name: &str| !name.starts_with("agent-private/") && !name.starts_with("demo.");
                let metadata: Vec<_> = all
                    .iter()
                    .filter(|m| is_user_secret(&m.name))
                    .filter(|m| match env.as_deref() {
                        None => true,
                        Some(e) => m.tags.iter().any(|t| t == &format!("env:{e}")),
                    })
                    .collect();
                if metadata.is_empty() && !cli.quiet {
                    if let Some(e) = env.as_deref() {
                        eprintln!(
                            "No secrets found in environment '{e}'. \
                             Add one with: lockrail secret set MY_KEY --env {e}"
                        );
                    } else {
                        eprintln!(
                            "No secrets stored yet. \
                             Add one with: lockrail secret set MY_KEY\n\
                             Or import from a .env file: lockrail secret import .env"
                        );
                    }
                }
                print_value(&cli, &serde_json::to_value(metadata)?)?;
            }
            SecretCommands::Show {
                name,
                metadata_only,
            } => {
                let vault = Vault::open(vault_path(&cli), password(&cli)?)?;
                let metadata = vault.secret_metadata(name)?;
                if *metadata_only {
                    print_value(&cli, &serde_json::to_value(metadata)?)?;
                } else {
                    return Err(anyhow!(
                        "raw secret display is disabled; use --metadata-only"
                    ));
                }
            }
            SecretCommands::Set { name, value, env } => {
                let secret_value = match value {
                    Some(v) => v.clone(),
                    None => {
                        if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                            prompt_line(&format!("Value for {name}: "))?
                        } else {
                            std::io::read_to_string(std::io::stdin())?
                                .trim()
                                .to_string()
                        }
                    }
                };
                let environment = env.as_deref().unwrap_or("default");
                let mut vault = Vault::open(vault_path(&cli), password(&cli)?)?;
                vault.set_secret(name.clone(), secret_value, environment, vec![])?;
                vault.save()?;
                AuditLog::new(audit_path(&cli)).append(
                    "secret.set",
                    name,
                    serde_json::json!({"env": environment}),
                )?;
                print_value(
                    &cli,
                    &serde_json::json!({"name": name, "env": environment, "status": "ok"}),
                )?;
            }
            SecretCommands::Delete { name } => {
                let mut vault = Vault::open(vault_path(&cli), password(&cli)?)?;
                let removed = vault.delete_secret(name)?;
                vault.save()?;
                AuditLog::new(audit_path(&cli)).append(
                    "secret.delete",
                    name,
                    serde_json::json!({}),
                )?;
                print_value(&cli, &serde_json::json!({"name": name, "removed": removed}))?;
            }
            SecretCommands::Import { path, env } => {
                let text = fs::read_to_string(path)?;
                let pairs = sync::import_dotenv(&text);
                let environment = env.as_deref().unwrap_or("default");
                let mut vault = Vault::open(vault_path(&cli), password(&cli)?)?;
                let mut count = 0usize;
                for (name, value) in &pairs {
                    vault.set_secret(name.clone(), value.clone(), environment, vec![])?;
                    count += 1;
                }
                vault.save()?;
                AuditLog::new(audit_path(&cli)).append(
                    "secret.import",
                    path.display().to_string(),
                    serde_json::json!({"count": count, "env": environment}),
                )?;
                print_value(
                    &cli,
                    &serde_json::json!({"imported": count, "env": environment}),
                )?;
            }
            SecretCommands::Export { format, env } => {
                if !cli.quiet {
                    eprintln!(
                        "lockrail: WARNING — exporting secrets as plaintext. \
                         Treat the output with the same care as your vault password."
                    );
                }
                let vault = Vault::open(vault_path(&cli), password(&cli)?)?;
                let output = match format.as_str() {
                    "dotenv" => sync::export_dotenv(&vault, env.as_deref()),
                    "json" => sync::export_json(&vault, env.as_deref()).to_string(),
                    "yaml" => sync::export_yaml(&vault, env.as_deref()),
                    other => return Err(anyhow!("unsupported export format: {other}")),
                };
                print!("{output}");
            }
        },
        Commands::Agent { command } => match command {
            AgentCommands::Create { name, r#type } => {
                let mut vault = Vault::open(vault_path(&cli), password(&cli)?)?;
                let agent = AgentKeypairDoc::generate(name.clone(), r#type.as_str());
                vault.save_agent(&agent, agents_dir(&cli))?;
                AuditLog::new(audit_path(&cli)).append(
                    "agent.create",
                    &agent.agent_id,
                    serde_json::to_value(agent.public_view())?,
                )?;
                print_value(&cli, &serde_json::to_value(agent.public_view())?)?;
            }
            AgentCommands::List => {
                let vault = Vault::open(vault_path(&cli), password(&cli)?)?;
                print_value(&cli, &serde_json::to_value(vault.list_agents())?)?;
            }
            AgentCommands::Public { name } => {
                let vault = Vault::open(vault_path(&cli), password(&cli)?)?;
                let public = agent_by_name(&vault, name)?;
                print_value(&cli, &serde_json::to_value(public)?)?;
            }
            AgentCommands::Rotate { name, r#type } => {
                let mut vault = Vault::open(vault_path(&cli), password(&cli)?)?;
                let existing = agent_by_name(&vault, name)?;
                let agent = AgentKeypairDoc::generate(existing.name, r#type.as_str());
                vault.save_agent(&agent, agents_dir(&cli))?;
                vault.revoke_agent(&existing.agent_id, agents_dir(&cli))?;
                AuditLog::new(audit_path(&cli)).append(
                    "agent.rotate",
                    &existing.agent_id,
                    serde_json::to_value(agent.public_view())?,
                )?;
                print_value(&cli, &serde_json::to_value(agent.public_view())?)?;
            }
            AgentCommands::Revoke { name } => {
                let mut vault = Vault::open(vault_path(&cli), password(&cli)?)?;
                let existing = agent_by_name(&vault, name)?;
                vault.revoke_agent(&existing.agent_id, agents_dir(&cli))?;
                AuditLog::new(audit_path(&cli)).append(
                    "agent.revoke",
                    &existing.agent_id,
                    serde_json::json!({}),
                )?;
                print_value(&cli, &serde_json::json!({"revoked": existing.agent_id}))?;
            }
        },
        Commands::Capability { command } => match command {
            CapabilityCommands::Issue {
                key_name,
                minutes,
                hosts,
                methods,
                paths,
                preset,
                agent,
                task_id,
                purpose,
            } => {
                let vault = Vault::open(vault_path(&cli), password(&cli)?)?;
                let _ = vault.secret_metadata(key_name)?;
                let claims = preset_claims(
                    &cli,
                    key_name,
                    *minutes,
                    hosts.clone(),
                    methods.clone(),
                    paths.clone(),
                    preset.as_deref(),
                    agent.clone(),
                    task_id.clone(),
                    purpose.clone(),
                )?;
                let token = CapabilityToken::issue(claims.clone(), &vault.signing_key()?)?;
                AuditLog::new(audit_path(&cli)).append(
                    "capability.issue",
                    key_name,
                    serde_json::to_value(&claims)?,
                )?;
                print_value(&cli, &serde_json::json!({"token": token, "claims": claims}))?;
            }
            CapabilityCommands::Inspect { token } => {
                let vault = Vault::open(vault_path(&cli), password(&cli)?)?;
                let claims = CapabilityToken::verify(
                    token,
                    &vault.issuer_public_key()?,
                    &vault.revoked_list(),
                )?
                .claims;
                print_value(&cli, &serde_json::to_value(claims)?)?;
            }
            CapabilityCommands::Revoke { cap_id } => {
                let mut vault = Vault::open(vault_path(&cli), password(&cli)?)?;
                vault.revoke(*cap_id)?;
                AuditLog::new(audit_path(&cli)).append(
                    "capability.revoke",
                    cap_id.to_string(),
                    serde_json::json!({}),
                )?;
                print_value(&cli, &serde_json::json!({"revoked": cap_id}))?;
            }
        },
        Commands::Relay { command } => match command {
            RelayCommands::Start { addr } => {
                let config = load_config(&cli)?;
                let resolved = addr.unwrap_or(config.relay_listen.parse()?);
                print_value(
                    &cli,
                    &serde_json::json!({"status":"starting","addr":resolved}),
                )?;
                serve(relay_state(&cli)?, resolved).await?;
            }
            RelayCommands::Check => {
                let config = load_config(&cli)?;
                let url = format!("http://{}/healthz", config.relay_listen);
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(3))
                    .build()?;
                match client.get(&url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        print_value(
                            &cli,
                            &serde_json::json!({
                                "addr": config.relay_listen,
                                "status": "running",
                                "ok": true,
                            }),
                        )?;
                    }
                    _ => {
                        print_value(
                            &cli,
                            &serde_json::json!({
                                "addr": config.relay_listen,
                                "status": "not running",
                                "ok": false,
                                "hint": "lockrail relay start",
                            }),
                        )?;
                        std::process::exit(1);
                    }
                }
            }
        },
        Commands::Audit { command } => match command {
            AuditCommands::Verify => {
                let (ok, message) = AuditLog::new(audit_path(&cli)).verify()?;
                print_value(&cli, &serde_json::json!({"ok": ok, "message": message}))?;
                if !ok {
                    std::process::exit(1);
                }
            }
            AuditCommands::List => {
                let rows = AuditLog::new(audit_path(&cli)).read_all()?;
                print_value(&cli, &serde_json::to_value(rows)?)?;
            }
            AuditCommands::Export { format } => {
                if format != "json" {
                    return Err(anyhow!("only --format json is currently supported"));
                }
                let rows = AuditLog::new(audit_path(&cli)).read_all()?;
                print_value(&cli, &serde_json::json!({"events": rows}))?;
            }
        },
        Commands::Config { command } => match command {
            ConfigCommands::Init => {
                let config = AppConfig::default();
                save_config(&cli, &config)?;
                print_value(&cli, &serde_json::to_value(config)?)?;
            }
            ConfigCommands::Validate => {
                let config = load_config(&cli)?;
                let _: SocketAddr = config
                    .relay_listen
                    .parse()
                    .context("invalid relay_listen")?;
                print_value(&cli, &serde_json::json!({"valid": true}))?;
            }
            ConfigCommands::Print => {
                print_value(&cli, &serde_json::to_value(load_config(&cli)?)?)?;
            }
        },
        Commands::Shell { env } => {
            // SECURITY WARNING: this command injects vault secrets as plain environment
            // variables into the spawned shell.  Any process running inside that shell
            // — including AI coding tools — can read every secret via `printenv`,
            // `process.env`, or `/proc/self/environ`.  Use this only for non-AI
            // processes (build scripts, deployment tools, etc.) where you need secrets
            // as env vars.  Do NOT run Claude Code, Codex, or Cursor inside this shell.
            if !cli.quiet {
                eprintln!(
                    "lockrail: WARNING — secrets will be visible as env vars inside this shell.\n\
                     Running AI tools (claude, codex, cursor) inside this shell defeats Lockrail.\n\
                     Use 'lockrail run -- <ai-tool>' instead to keep secrets sealed.\n"
                );
            }
            let vault = Vault::open(vault_path(&cli), password(&cli)?)?;
            let code = inject::run_shell(&vault, env.as_deref())?;
            if code != 0 {
                std::process::exit(code);
            }
        }
        Commands::Sync { command } => match command {
            SyncCommands::Github { repo, token, env } => {
                let resolved_token = token
                    .clone()
                    .or_else(|| std::env::var("GITHUB_TOKEN").ok())
                    .ok_or_else(|| anyhow!("provide --token or GITHUB_TOKEN"))?;
                // repo is expected as "owner/repo"
                let (owner, repo_name) = repo
                    .split_once('/')
                    .ok_or_else(|| anyhow!("--repo must be in owner/repo format"))?;
                let mut vault = Vault::open(vault_path(&cli), password(&cli)?)?;
                let count = sync::sync_github(
                    &mut vault,
                    owner,
                    repo_name,
                    &resolved_token,
                    env.as_deref(),
                )
                .await?;
                print_value(&cli, &serde_json::json!({"synced": count, "target": repo}))?;
            }
            SyncCommands::Vercel {
                project,
                token,
                env,
            } => {
                let resolved_token = token
                    .clone()
                    .or_else(|| std::env::var("VERCEL_TOKEN").ok())
                    .ok_or_else(|| anyhow!("provide --token or VERCEL_TOKEN"))?;
                let mut vault = Vault::open(vault_path(&cli), password(&cli)?)?;
                let count =
                    sync::sync_vercel(&mut vault, project, &resolved_token, env.as_deref()).await?;
                print_value(
                    &cli,
                    &serde_json::json!({"synced": count, "target": project}),
                )?;
            }
            SyncCommands::Dotenv { out, env } => {
                let vault = Vault::open(vault_path(&cli), password(&cli)?)?;
                let content = sync::export_dotenv(&vault, env.as_deref());
                fs::write(out, content.as_bytes())?;
                print_value(
                    &cli,
                    &serde_json::json!({"out": out, "env": env.as_deref().unwrap_or("default")}),
                )?;
            }
        },
        Commands::Proxy { command } => match command {
            ProxyCommands::InstallCa => {
                let ca_store = if ca_path(&cli).exists() {
                    CaStore::load(&ca_path(&cli))?
                } else {
                    let store = CaStore::generate()?;
                    store.save(&ca_path(&cli))?;
                    store
                };
                let cert_path = proxy_cert_path(&cli);
                let result = install_ca_system(ca_store.cert_pem(), &cert_path);
                match result {
                    Ok(msg) => print_value(
                        &cli,
                        &serde_json::json!({
                            "ok": true,
                            "message": msg,
                            "cert_pem_path": cert_path,
                            "next": "lockrail proxy start",
                        }),
                    )?,
                    Err(e) => {
                        print_value(
                            &cli,
                            &serde_json::json!({
                                "ok": false,
                                "error": e.to_string(),
                                "manual_install": format!("sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain {}", cert_path.display()),
                                "cert_pem_path": cert_path,
                            }),
                        )?;
                    }
                }
            }
            ProxyCommands::Start {
                listen,
                unsafe_public_listen,
            } => {
                if !unsafe_public_listen && !listen.ip().is_loopback() {
                    return Err(anyhow!(
                        "refusing to bind proxy to non-loopback address {listen}; pass --unsafe-public-listen only on a trusted network"
                    ));
                }
                let ca_store = CaStore::load(&ca_path(&cli))
                    .map_err(|_| anyhow!("run 'lockrail proxy install-ca' first"))?;
                let ca = std::sync::Arc::new(lockrail_proxy::LocalCa::new(ca_store));
                let secret_sink = std::sync::Arc::new(VaultSecretSink {
                    vault_path: vault_path(&cli),
                    password: password(&cli)?,
                });
                print_value(
                    &cli,
                    &serde_json::json!({
                        "status": "starting",
                        "listen": listen.to_string(),
                        "public_listen_enabled": unsafe_public_listen,
                        "intercepting": lockrail_proxy::proxy::AI_INTERCEPT_HOSTS,
                        "hint": format!("export HTTPS_PROXY=http://{listen}"),
                    }),
                )?;
                run_proxy(ProxyConfig {
                    listen_addr: *listen,
                    ca,
                    allow_non_loopback: *unsafe_public_listen,
                    secret_sink: Some(secret_sink),
                })
                .await?;
            }
            ProxyCommands::Status => {
                let ca_installed = ca_path(&cli).exists();
                let cert_exported = proxy_cert_path(&cli).exists();
                print_value(
                    &cli,
                    &serde_json::json!({
                        "ca_generated": ca_installed,
                        "cert_exported": cert_exported,
                        "ca_path": ca_path(&cli),
                        "cert_path": proxy_cert_path(&cli),
                        "intercepting": lockrail_proxy::proxy::AI_INTERCEPT_HOSTS,
                        "setup_steps": if !ca_installed {
                            vec!["lockrail proxy install-ca", "export HTTPS_PROXY=http://127.0.0.1:8789", "lockrail proxy start"]
                        } else {
                            vec!["export HTTPS_PROXY=http://127.0.0.1:8789", "lockrail proxy start"]
                        },
                    }),
                )?;
            }
        },
        Commands::Ai { command } => match command {
            AiCommands::Enable { tool } => {
                let result = ai_enable(tool.as_deref(), cli.quiet)?;
                print_value(&cli, &result)?;
            }
            AiCommands::Disable { tool } => {
                let result = ai_disable(tool.as_deref(), cli.quiet)?;
                print_value(&cli, &result)?;
            }
            AiCommands::Hooks { tool } => {
                let result = ai_install_hooks(tool.as_deref(), cli.quiet)?;
                print_value(&cli, &result)?;
            }
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use tower::util::ServiceExt;

    fn test_cli(home: PathBuf, password: &str) -> Cli {
        Cli {
            home: Some(home),
            password: Some(password.to_string()),
            json: true,
            quiet: false,
            command: Commands::Status,
        }
    }

    #[tokio::test]
    async fn ui_endpoints_do_not_render_raw_secret_material() {
        let temp_home = tempfile::tempdir().expect("temp home");
        let home = temp_home.path().to_path_buf();
        let cli = test_cli(home.clone(), "pw");
        let _ = Vault::init(
            vault_path(&cli),
            SecretString::from("pw"),
            KdfParamsDoc::test_fast(),
        )
        .expect("init vault");
        save_config(&cli, &AppConfig::default()).expect("save config");
        ensure_local_profile(&cli).expect("profile");
        let _ = bootstrap_agents(&cli).expect("agents");
        let mut vault =
            Vault::open(vault_path(&cli), SecretString::from("pw")).expect("open vault");
        vault
            .add_key(
                "ui/openai/fp_demo".to_string(),
                "sk-proj-demo-abcdefghijklmnopqrstuvwxyz123456".to_string(),
            )
            .expect("add key");
        let raw_secret = "sk-proj-demo-abcdefghijklmnopqrstuvwxyz123456";
        let raw_private = vault
            .load_agent(&vault.list_agents()[0].agent_id)
            .expect("agent")
            .private_key
            .clone();
        let test_token = "test-token-abc123".to_string();
        let app = ui_router(home, SecretString::from("pw"), test_token.clone());
        for path in [
            "/healthz",
            &format!("/?token={test_token}"),
            &format!("/secrets?token={test_token}"),
            &format!("/agents?token={test_token}"),
            &format!("/relay?token={test_token}"),
            &format!("/audit?token={test_token}"),
            &format!("/demo?token={test_token}"),
        ] {
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("response");
            assert!(response.status().is_success());
            let body = to_bytes(response.into_body(), usize::MAX)
                .await
                .expect("body");
            let text = String::from_utf8_lossy(&body);
            assert!(!text.contains(raw_secret), "raw secret leaked on {path}");
            assert!(!text.contains(&raw_private), "private key leaked on {path}");
        }
    }

    #[test]
    fn run_command_args_are_sealed_before_spawn() {
        let temp_home = tempfile::tempdir().expect("temp home");
        let home = temp_home.path().to_path_buf();
        let cli = test_cli(home, "pw");
        let _ = Vault::init(
            vault_path(&cli),
            SecretString::from("pw"),
            KdfParamsDoc::test_fast(),
        )
        .expect("init vault");
        let command = vec![
            "grok".to_string(),
            "-p".to_string(),
            "Use sk-proj-demo-abcdefghijklmnopqrstuvwxyz123456".to_string(),
        ];
        let (_executable, args) =
            sanitized_command(&cli, &command, "test-run-arg").expect("sanitize args");
        assert_eq!(args[0], "-p");
        assert!(args[1].contains("lockrail://secret/openai-key/"));
        assert!(!args[1].contains("sk-proj-demo-abcdefghijklmnopqrstuvwxyz123456"));
    }

    #[test]
    fn post_tool_use_scan_extracts_nested_json_strings() {
        let input = serde_json::json!({
            "tool_name": "shell",
            "tool_response": {
                "content": [
                    {"type": "text", "text": "safe"},
                    {"nested": {"stderr": "OPENAI_API_KEY=sk-proj-demo-abcdefghijklmnopqrstuvwxyz123456"}}
                ]
            }
        })
        .to_string();

        let extracted = text_for_post_tool_use_scan(&input);

        assert!(extracted.contains("sk-proj-demo-abcdefghijklmnopqrstuvwxyz123456"));
    }
}
