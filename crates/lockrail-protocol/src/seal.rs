use core::fmt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum SecretConfidence {
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScanOptions {
    pub aggressive: bool,
    pub protection_mode: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            aggressive: false,
            protection_mode: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealOptions {
    pub aggressive: bool,
    pub protection_mode: bool,
}

impl Default for SealOptions {
    fn default() -> Self {
        Self {
            aggressive: false,
            protection_mode: true,
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretFinding {
    pub kind: String,
    pub start: usize,
    pub end: usize,
    pub value: String,
    pub fingerprint: String,
    pub confidence: SecretConfidence,
    pub should_seal: bool,
    pub preview: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealResult {
    pub safe_text: String,
    pub findings: Vec<SecretFinding>,
}

impl fmt::Debug for SecretFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretFinding")
            .field("kind", &self.kind)
            .field("start", &self.start)
            .field("end", &self.end)
            .field("value", &"[REDACTED]")
            .field("fingerprint", &self.fingerprint)
            .field("confidence", &self.confidence)
            .field("should_seal", &self.should_seal)
            .field("preview", &self.preview)
            .finish()
    }
}

impl fmt::Debug for SealResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealResult")
            .field("safe_text", &self.safe_text)
            .field("findings", &self.findings)
            .finish()
    }
}

pub fn fingerprint(secret: &str) -> String {
    let mut h = Sha256::new();
    h.update(secret.as_bytes());
    let hex = hex::encode(h.finalize());
    format!("fp_{}", &hex[..16])
}

fn redacted_preview(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    match chars.len() {
        0 => String::new(),
        1..=8 => "***".to_string(),
        len => format!(
            "{}***{}",
            chars[..4].iter().collect::<String>(),
            chars[len - 4..].iter().collect::<String>()
        ),
    }
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '+' | '=' | ':' | '~')
}

fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for b in s.as_bytes() {
        counts[*b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = *c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn looks_high_entropy(s: &str) -> bool {
    s.len() >= 24 && shannon_entropy(s) >= 3.6
}

fn context_suggests_secret(input: &str, start: usize) -> bool {
    let window_start = start.saturating_sub(48);
    let lower = input[window_start..start].to_ascii_lowercase();
    [
        "api",
        "token",
        "secret",
        "password",
        "bearer",
        "auth",
        "client",
        "key",
        "credential",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn should_seal(confidence: SecretConfidence, options: ScanOptions) -> bool {
    match confidence {
        SecretConfidence::High => true,
        SecretConfidence::Medium => options.protection_mode,
        SecretConfidence::Low => options.aggressive,
    }
}

fn push_finding(
    out: &mut Vec<SecretFinding>,
    kind: &str,
    start: usize,
    end: usize,
    value: String,
    confidence: SecretConfidence,
    options: ScanOptions,
) {
    out.push(SecretFinding {
        kind: kind.to_string(),
        start,
        end,
        fingerprint: fingerprint(&value),
        preview: redacted_preview(&value),
        should_seal: should_seal(confidence, options),
        confidence,
        value,
    });
}

fn scan_prefixed(
    input: &str,
    prefix: &str,
    kind: &str,
    min_len: usize,
    confidence: SecretConfidence,
    out: &mut Vec<SecretFinding>,
    options: ScanOptions,
) {
    let mut offset = 0;
    while let Some(pos) = input[offset..].find(prefix) {
        let start = offset + pos;
        let mut end = start;
        for (idx, ch) in input[start..].char_indices() {
            if idx == 0 || is_token_char(ch) {
                end = start + idx + ch.len_utf8();
            } else {
                break;
            }
        }
        if end > start && end - start >= min_len {
            let value = input[start..end].to_string();
            push_finding(out, kind, start, end, value, confidence, options);
        }
        offset = end.max(start + prefix.len());
    }
}

fn scan_bearer(input: &str, out: &mut Vec<SecretFinding>, options: ScanOptions) {
    let lower = input.to_ascii_lowercase();
    let mut offset = 0;
    while let Some(pos) = lower[offset..].find("bearer ") {
        let start = offset + pos + 7;
        let mut end = start;
        for (idx, ch) in input[start..].char_indices() {
            if is_token_char(ch) {
                end = start + idx + ch.len_utf8();
            } else {
                break;
            }
        }
        if end - start >= 16 {
            let value = input[start..end].to_string();
            push_finding(
                out,
                "bearer-token",
                start,
                end,
                value,
                SecretConfidence::High,
                options,
            );
        }
        offset = end.max(start + 1);
    }
}

fn scan_jwt(input: &str, out: &mut Vec<SecretFinding>, options: ScanOptions) {
    let mut offset = 0;
    while let Some(pos) = input[offset..].find("eyJ") {
        let start = offset + pos;
        let mut end = start;
        for (idx, ch) in input[start..].char_indices() {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                end = start + idx + ch.len_utf8();
            } else {
                break;
            }
        }
        let value = &input[start..end];
        if value.matches('.').count() == 2 && value.len() >= 40 {
            push_finding(
                out,
                "jwt",
                start,
                end,
                value.to_string(),
                SecretConfidence::Medium,
                options,
            );
        }
        offset = end.max(start + 3);
    }
}

fn scan_private_key_blocks(input: &str, out: &mut Vec<SecretFinding>, options: ScanOptions) {
    let begin = "-----BEGIN ";
    let end_marker = "-----END ";
    let mut offset = 0;
    while let Some(pos) = input[offset..].find(begin) {
        let start = offset + pos;
        if let Some(end_pos) = input[start..].find(end_marker) {
            let maybe_end = start + end_pos;
            if let Some(close) = input[maybe_end + end_marker.len()..].find("-----") {
                let end = maybe_end + end_marker.len() + close + 5;
                let value = input[start..end].to_string();
                if value.contains("PRIVATE KEY")
                    || value.contains("OPENSSH")
                    || value.contains("PGP")
                {
                    push_finding(
                        out,
                        "private-key-block",
                        start,
                        end,
                        value,
                        SecretConfidence::High,
                        options,
                    );
                }
                offset = end;
                continue;
            }
        }
        offset = start + begin.len();
    }
}

fn scan_database_urls(input: &str, out: &mut Vec<SecretFinding>, options: ScanOptions) {
    let lower = input.to_ascii_lowercase();
    let schemes: &[&str] = &[
        "postgresql://",
        "postgres://",
        "mysql://",
        "mongodb+srv://",
        "mongodb://",
        "redis://",
        "rediss://",
        "amqp://",
        "amqps://",
    ];
    for scheme in schemes {
        let mut offset = 0;
        while let Some(pos) = lower[offset..].find(scheme) {
            let start = offset + pos;
            let mut end = start;
            for (idx, ch) in input[start..].char_indices() {
                if ch.is_ascii_whitespace() || matches!(ch, '"' | '\'' | '`' | ')' | ']' | '}') {
                    break;
                }
                end = start + idx + ch.len_utf8();
            }
            let value = &input[start..end];
            // Only flag if the URL contains credentials (user:pass@host)
            if value.contains('@') && value.len() >= 16 {
                push_finding(
                    out,
                    "database-url",
                    start,
                    end,
                    value.to_string(),
                    SecretConfidence::High,
                    options,
                );
            }
            offset = end.max(start + scheme.len());
        }
    }
}

fn scan_assignment(
    input: &str,
    keys: &[(&str, &str, SecretConfidence)],
    out: &mut Vec<SecretFinding>,
    options: ScanOptions,
) {
    let lower = input.to_ascii_lowercase();
    for (key, kind, confidence) in keys {
        let mut offset = 0;
        while let Some(pos) = lower[offset..].find(key) {
            let kstart = offset + pos;
            let after_key = kstart + key.len();
            let rest = &input[after_key..];
            let sep_pos = rest.find(|c: char| c == '=' || c == ':' || c.is_whitespace());
            if let Some(sp) = sep_pos {
                let mut start = after_key + sp;
                while start < input.len() {
                    let ch = input.as_bytes()[start] as char;
                    if ch.is_ascii_whitespace() || matches!(ch, '=' | ':' | '"' | '\'') {
                        start += 1;
                    } else {
                        break;
                    }
                }
                let mut end = start;
                for (idx, ch) in input[start..].char_indices() {
                    if is_token_char(ch) {
                        end = start + idx + ch.len_utf8();
                    } else {
                        break;
                    }
                }
                if end > start && end - start >= 8 {
                    let value = input[start..end].trim_matches(['"', '\'']).to_string();
                    push_finding(out, kind, start, end, value, *confidence, options);
                }
            }
            offset = after_key;
        }
    }
}

fn scan_generic_entropy(input: &str, out: &mut Vec<SecretFinding>, options: ScanOptions) {
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && !is_token_char(bytes[i] as char) {
            i += 1;
        }
        let start = i;
        while i < bytes.len() && is_token_char(bytes[i] as char) {
            i += 1;
        }
        let end = i;
        if end > start {
            let value = &input[start..end];
            if looks_high_entropy(value)
                && !value.starts_with("lockrail://")
                && value.chars().any(|c| c.is_ascii_digit())
                && value.chars().any(|c| c.is_ascii_alphabetic())
                && context_suggests_secret(input, start)
            {
                push_finding(
                    out,
                    "high-entropy-token",
                    start,
                    end,
                    value.to_string(),
                    SecretConfidence::Low,
                    options,
                );
            }
        }
    }
}

fn normalize_findings(mut out: Vec<SecretFinding>) -> Vec<SecretFinding> {
    out.sort_by_key(|d| (d.start, d.end));
    let mut clean: Vec<SecretFinding> = Vec::new();
    for finding in out {
        if let Some(prev) = clean.last()
            && finding.start < prev.end
        {
            if (finding.end - finding.start) > (prev.end - prev.start) {
                let _ = clean.pop();
                clean.push(finding);
            }
            continue;
        }
        clean.push(finding);
    }
    clean
}

pub fn scan_text(input: &str, options: ScanOptions) -> Vec<SecretFinding> {
    let mut out = Vec::new();
    scan_prefixed(
        input,
        "sk-proj-",
        "openai-key",
        18,
        SecretConfidence::High,
        &mut out,
        options,
    );
    scan_prefixed(
        input,
        "sk-ant-",
        "anthropic-key",
        18,
        SecretConfidence::High,
        &mut out,
        options,
    );
    scan_prefixed(
        input,
        "ghp_",
        "github-token",
        20,
        SecretConfidence::High,
        &mut out,
        options,
    );
    scan_prefixed(
        input,
        "github_pat_",
        "github-token",
        24,
        SecretConfidence::High,
        &mut out,
        options,
    );
    scan_prefixed(
        input,
        "glpat-",
        "gitlab-token",
        16,
        SecretConfidence::High,
        &mut out,
        options,
    );
    scan_prefixed(
        input,
        "xoxb-",
        "slack-bot-token",
        16,
        SecretConfidence::High,
        &mut out,
        options,
    );
    scan_prefixed(
        input,
        "xoxp-",
        "slack-user-token",
        16,
        SecretConfidence::High,
        &mut out,
        options,
    );
    scan_prefixed(
        input,
        "sk_live_",
        "stripe-key",
        16,
        SecretConfidence::High,
        &mut out,
        options,
    );
    scan_prefixed(
        input,
        "sk_test_",
        "stripe-key",
        16,
        SecretConfidence::High,
        &mut out,
        options,
    );
    scan_prefixed(
        input,
        "AKIA",
        "aws-access-key-id",
        20,
        SecretConfidence::High,
        &mut out,
        options,
    );
    scan_prefixed(
        input,
        "ASIA",
        "aws-session-key-id",
        20,
        SecretConfidence::High,
        &mut out,
        options,
    );
    scan_prefixed(
        input,
        "AIza",
        "google-api-key",
        20,
        SecretConfidence::High,
        &mut out,
        options,
    );
    scan_prefixed(
        input,
        "cfp_",
        "cloudflare-token",
        16,
        SecretConfidence::High,
        &mut out,
        options,
    );
    scan_prefixed(
        input,
        "vercel_",
        "vercel-token",
        16,
        SecretConfidence::High,
        &mut out,
        options,
    );
    scan_prefixed(
        input,
        "ntl_",
        "netlify-token",
        16,
        SecretConfidence::High,
        &mut out,
        options,
    );
    scan_prefixed(
        input,
        "sbp_",
        "supabase-token",
        16,
        SecretConfidence::High,
        &mut out,
        options,
    );
    // GitHub token variants (Enterprise + OAuth + server-to-server)
    scan_prefixed(
        input,
        "ghs_",
        "github-app-token",
        20,
        SecretConfidence::High,
        &mut out,
        options,
    );
    scan_prefixed(
        input,
        "ghu_",
        "github-user-token",
        20,
        SecretConfidence::High,
        &mut out,
        options,
    );
    scan_prefixed(
        input,
        "gho_",
        "github-oauth-token",
        20,
        SecretConfidence::High,
        &mut out,
        options,
    );
    scan_prefixed(
        input,
        "ghr_",
        "github-refresh-token",
        20,
        SecretConfidence::High,
        &mut out,
        options,
    );
    // npm tokens (npm_<base64>)
    scan_prefixed(
        input,
        "npm_",
        "npm-token",
        24,
        SecretConfidence::High,
        &mut out,
        options,
    );
    // PyPI API tokens
    scan_prefixed(
        input,
        "pypi-",
        "pypi-token",
        24,
        SecretConfidence::High,
        &mut out,
        options,
    );
    // HuggingFace API tokens
    scan_prefixed(
        input,
        "hf_",
        "huggingface-token",
        20,
        SecretConfidence::High,
        &mut out,
        options,
    );
    // Stripe webhook secrets
    scan_prefixed(
        input,
        "whsec_",
        "stripe-webhook-secret",
        16,
        SecretConfidence::High,
        &mut out,
        options,
    );
    // Doppler service tokens
    scan_prefixed(
        input,
        "dp.pt.",
        "doppler-token",
        16,
        SecretConfidence::High,
        &mut out,
        options,
    );
    // HashiCorp Vault tokens
    scan_prefixed(
        input,
        "hvs.",
        "vault-service-token",
        20,
        SecretConfidence::High,
        &mut out,
        options,
    );
    scan_prefixed(
        input,
        "hvb.",
        "vault-batch-token",
        20,
        SecretConfidence::High,
        &mut out,
        options,
    );
    // SendGrid (medium: SG. prefix is common in other contexts)
    scan_prefixed(
        input,
        "SG.",
        "sendgrid-key",
        32,
        SecretConfidence::Medium,
        &mut out,
        options,
    );
    scan_bearer(input, &mut out, options);
    scan_jwt(input, &mut out, options);
    scan_private_key_blocks(input, &mut out, options);
    scan_database_urls(input, &mut out, options);
    scan_assignment(
        input,
        &[
            ("api_key", "api-key", SecretConfidence::High),
            ("apikey", "api-key", SecretConfidence::High),
            ("api_secret", "api-secret", SecretConfidence::High),
            ("token", "token-value", SecretConfidence::Medium),
            ("password", "password", SecretConfidence::High),
            ("passwd", "password", SecretConfidence::High),
            ("client_secret", "client-secret", SecretConfidence::High),
            ("client_token", "client-token", SecretConfidence::High),
            ("access_token", "oauth-access-token", SecretConfidence::High),
            (
                "refresh_token",
                "oauth-refresh-token",
                SecretConfidence::High,
            ),
            ("id_token", "oauth-id-token", SecretConfidence::Medium),
            (
                "secret_access_key",
                "aws-secret-access-key",
                SecretConfidence::High,
            ),
            (
                "aws_secret_access_key",
                "aws-secret-access-key",
                SecretConfidence::High,
            ),
            ("database_url", "database-url", SecretConfidence::High),
            ("db_url", "database-url", SecretConfidence::High),
            ("connection_string", "database-url", SecretConfidence::High),
            ("private_key", "private-key", SecretConfidence::High),
            ("webhook_secret", "webhook-secret", SecretConfidence::High),
            ("gemini_api_key", "gemini-api-key", SecretConfidence::High),
            (
                "antigravity_api_key",
                "antigravity-api-key",
                SecretConfidence::High,
            ),
            ("google_api_key", "google-api-key", SecretConfidence::High),
            ("gcp_api_key", "gcp-api-key", SecretConfidence::High),
        ],
        &mut out,
        options,
    );
    scan_generic_entropy(input, &mut out, options);
    normalize_findings(out)
}

pub fn replace_with_handles(input: &str, findings: &[SecretFinding]) -> String {
    let mut out = String::new();
    let mut cursor = 0;
    for finding in findings {
        out.push_str(&input[cursor..finding.start]);
        out.push_str(&format!(
            "lockrail://secret/{}/{}",
            finding.kind, finding.fingerprint
        ));
        cursor = finding.end;
    }
    out.push_str(&input[cursor..]);
    out
}

pub fn seal_text(input: &str, options: SealOptions) -> SealResult {
    let findings = scan_text(
        input,
        ScanOptions {
            aggressive: options.aggressive,
            protection_mode: options.protection_mode,
        },
    );
    let sealed: Vec<_> = findings
        .iter()
        .filter(|finding| finding.should_seal)
        .cloned()
        .collect();
    SealResult {
        safe_text: replace_with_handles(input, &sealed),
        findings,
    }
}

pub fn redact_for_display(input: &str) -> String {
    let result = seal_text(
        input,
        SealOptions {
            aggressive: true,
            protection_mode: true,
        },
    );
    result.safe_text
}

pub fn redact_for_logs(input: &str) -> String {
    redact_for_display(input)
}

pub fn detect_secrets(input: &str) -> Vec<SecretFinding> {
    scan_text(input, ScanOptions::default())
}

pub fn scrub(input: &str) -> SealResult {
    seal_text(input, SealOptions::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_known_secret_types() {
        let input =
            "Use sk-proj-abcdefghijklmnopqrstuvwxyz123456 and ghp_abcdefghijklmnopqrstuvwxyz123456";
        let sealed = seal_text(input, SealOptions::default());
        assert_eq!(sealed.findings.len(), 2);
        assert!(
            !sealed
                .safe_text
                .contains("sk-proj-abcdefghijklmnopqrstuvwxyz123456")
        );
        assert!(sealed.safe_text.contains("lockrail://secret/openai-key/"));
        assert!(sealed.safe_text.contains("lockrail://secret/github-token/"));
    }

    #[test]
    fn low_confidence_needs_aggressive_mode() {
        let input = "secret = abcdEFGH1234567890abcdEFGH1234567890";
        let scan = scan_text(input, ScanOptions::default());
        assert!(scan.iter().any(|f| f.confidence == SecretConfidence::Low));
        let sealed = seal_text(input, SealOptions::default());
        assert!(
            sealed
                .safe_text
                .contains("abcdEFGH1234567890abcdEFGH1234567890")
        );
        let aggressive = seal_text(
            input,
            SealOptions {
                aggressive: true,
                protection_mode: true,
            },
        );
        assert!(
            !aggressive
                .safe_text
                .contains("abcdEFGH1234567890abcdEFGH1234567890")
        );
    }

    #[test]
    fn redacts_private_key_and_jwt() {
        let input = "jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk key -----BEGIN PRIVATE KEY-----abc-----END PRIVATE KEY-----";
        let redacted = redact_for_logs(input);
        assert!(!redacted.contains("PRIVATE KEY"));
        assert!(!redacted.contains("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
    }

    #[test]
    fn debug_output_redacts_secret_values() {
        let input = "Use sk-proj-abcdefghijklmnopqrstuvwxyz123456";
        let sealed = seal_text(input, SealOptions::default());
        let debug = format!("{sealed:?}");
        assert!(!debug.contains("sk-proj-abcdefghijklmnopqrstuvwxyz123456"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn detects_provider_and_generic_secret_samples() {
        let input = concat!(
            "openai=sk-proj-abcdefghijklmnopqrstuvwxyz123456\n",
            "github=ghp_abcdefghijklmnopqrstuvwxyz123456\n",
            "slack=xoxb-LOCKRAILTEST-XXXXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXX\n",
            "aws_id=AKIAIOSFODNN7EXAMPLE\n",
            "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
            "pem=-----BEGIN PRIVATE KEY-----abc-----END PRIVATE KEY-----\n",
            "token = abcdEFGH1234567890abcdEFGH1234567890\n"
        );

        let findings = scan_text(
            input,
            ScanOptions {
                aggressive: true,
                protection_mode: true,
            },
        );
        let kinds = findings
            .iter()
            .map(|finding| finding.kind.as_str())
            .collect::<Vec<_>>();
        assert!(kinds.contains(&"openai-key"));
        assert!(kinds.contains(&"github-token"));
        assert!(kinds.contains(&"slack-bot-token"));
        assert!(kinds.contains(&"aws-access-key-id"));
        assert!(kinds.contains(&"aws-secret-access-key"));
        assert!(kinds.contains(&"private-key-block"));

        let jwt_findings = scan_text(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            ScanOptions {
                aggressive: true,
                protection_mode: true,
            },
        );
        assert!(jwt_findings.iter().any(|finding| finding.kind == "jwt"));

        let generic_findings = scan_text(
            "secret = abcdEFGH1234567890abcdEFGH1234567890",
            ScanOptions {
                aggressive: true,
                protection_mode: true,
            },
        );
        assert!(
            generic_findings
                .iter()
                .any(|finding| finding.kind == "high-entropy-token")
        );
    }
}
