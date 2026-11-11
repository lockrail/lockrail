//! Handles (PLAN.md section 3.2, Phase 3D; fixes D6).
//!
//! `lockrail://secret/<kind>/<fp>` and `lockrail://phi/<kind>/<fp>`, where
//! `fp = "h_" + hex(HMAC-SHA256(fp_key, value)[..16])`. The key makes a handle useless for
//! confirming a guessed value, and two vaults with different keys give different handles for
//! the same value. 0.3.7 handles (`fp_` + 16 hex of an unkeyed SHA-256) still parse, so existing
//! `.env.lockrail` files keep resolving through the vault's legacy entries.
//!
//! PHI handles are never resolvable into a command, the relay or a file (B2): callers check
//! [`Handle::class`] and refuse `Class::Phi`.

use crate::seal::{ScanOptions, SealOptions, SealResult, replace_with_handles, scan_text};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub const SECRET_PREFIX: &str = "lockrail://secret/";
pub const PHI_PREFIX: &str = "lockrail://phi/";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    Secret,
    Phi,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handle {
    pub class: Class,
    pub kind: String,
    pub fingerprint: String,
}

impl Handle {
    pub fn is_legacy(&self) -> bool {
        self.fingerprint.starts_with("fp_")
    }
}

/// `h_` + 32 hex characters (the first 16 bytes of the HMAC).
pub fn keyed_fingerprint(fp_key: &[u8; 32], value: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(fp_key).expect("any key length works");
    mac.update(value.as_bytes());
    let bytes = mac.finalize().into_bytes();
    format!("h_{}", hex::encode(&bytes[..16]))
}

pub fn secret_handle(kind: &str, fingerprint: &str) -> String {
    format!("{SECRET_PREFIX}{kind}/{fingerprint}")
}

pub fn phi_handle(kind: &str, fingerprint: &str) -> String {
    format!("{PHI_PREFIX}{kind}/{fingerprint}")
}

fn valid_kind(kind: &str) -> bool {
    !kind.is_empty()
        && kind.len() <= 64
        && kind
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_fingerprint(fp: &str) -> bool {
    let hex_part = |s: &str, len: usize| s.len() == len && s.bytes().all(|b| b.is_ascii_hexdigit());
    match (fp.strip_prefix("h_"), fp.strip_prefix("fp_")) {
        (Some(rest), _) => hex_part(rest, 32),
        (_, Some(rest)) => hex_part(rest, 16),
        _ => false,
    }
}

/// Parse a whole handle string. Anything else (extra path segments, odd characters) is `None`.
pub fn parse(text: &str) -> Option<Handle> {
    let (class, rest) = if let Some(rest) = text.strip_prefix(SECRET_PREFIX) {
        (Class::Secret, rest)
    } else {
        (Class::Phi, text.strip_prefix(PHI_PREFIX)?)
    };
    let (kind, fingerprint) = rest.split_once('/')?;
    if !valid_kind(kind) || !valid_fingerprint(fingerprint) {
        return None;
    }
    Some(Handle {
        class,
        kind: kind.to_string(),
        fingerprint: fingerprint.to_string(),
    })
}

/// [`crate::seal::seal_text`] with keyed fingerprints: identical detection, but every finding's
/// `fingerprint` and every emitted handle use `HMAC(fp_key, value)`.
pub fn seal_text_keyed(input: &str, options: SealOptions, fp_key: &[u8; 32]) -> SealResult {
    let mut findings = scan_text(
        input,
        ScanOptions {
            aggressive: options.aggressive,
            protection_mode: options.protection_mode,
        },
    );
    for finding in &mut findings {
        finding.fingerprint = keyed_fingerprint(fp_key, &finding.value);
    }
    let sealed: Vec<_> = findings.iter().filter(|f| f.should_seal).cloned().collect();
    SealResult {
        safe_text: replace_with_handles(input, &sealed),
        findings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_value_different_keys_different_handles() {
        let value = ["ghp_", "Zx9Yw8Vu7Ts6Rq5Po4Nm3Lk2Jh1Gf0Ed9Cb8"].concat();
        let a = seal_text_keyed(&value, SealOptions::default(), &[1u8; 32]);
        let b = seal_text_keyed(&value, SealOptions::default(), &[2u8; 32]);
        assert_ne!(a.safe_text, b.safe_text);
        assert!(a.safe_text.starts_with("lockrail://secret/github-token/h_"));
        // Deterministic for one key: the model sees one consistent handle per value.
        let again = seal_text_keyed(&value, SealOptions::default(), &[1u8; 32]);
        assert_eq!(a.safe_text, again.safe_text);
        assert!(!a.safe_text.contains(&crate::seal::fingerprint(&value)));
    }

    #[test]
    fn parse_accepts_new_legacy_and_phi_and_rejects_junk() {
        let new = secret_handle("openai-key", &keyed_fingerprint(&[0u8; 32], "x"));
        assert_eq!(parse(&new).unwrap().class, Class::Secret);
        let legacy = parse("lockrail://secret/github-token/fp_620e24b631970fdc").unwrap();
        assert!(legacy.is_legacy());
        let phi = parse(&phi_handle(
            "ssn",
            &keyed_fingerprint(&[0u8; 32], "219-09-9999"),
        ))
        .unwrap();
        assert_eq!(phi.class, Class::Phi);
        for junk in [
            "lockrail://secret/github-token/fp_620e",
            "lockrail://secret/Git/fp_620e24b631970fdc",
            "lockrail://secret/a/b/fp_620e24b631970fdc",
            "lockrail://other/a/fp_620e24b631970fdc",
            "lockrail://secret/a/h_zz",
        ] {
            assert!(parse(junk).is_none(), "{junk}");
        }
    }
}
