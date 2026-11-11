use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, GeneralSubtree, IsCa, KeyPair,
    KeyUsagePurpose, NameConstraints, SanType,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, PrivateKeyDer},
    server::ResolvesServerCert,
    sign::CertifiedKey,
};

/// Persisted state for the local CA — cert PEM (for installation) + key PEM (for signing).
#[derive(Debug, Serialize, Deserialize)]
pub struct CaStore {
    pub cert_pem: String,
    pub key_pem: String,
}

impl CaStore {
    pub fn generate() -> Result<Self> {
        let key_pair = KeyPair::generate().context("CA keygen failed")?;
        let cert = new_ca_params()
            .self_signed(&key_pair)
            .context("CA self-sign failed")?;
        Ok(Self {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
        })
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
        }
        let tmp = path.with_extension("tmp");
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(&serde_json::to_vec_pretty(self)?)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)?;
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes =
            fs::read(path).context("CA store not found — run 'lockrail proxy install-ca'")?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }
}

/// CA validity (D5).
pub const CA_VALIDITY_DAYS: i64 = 365;

/// Params for a newly generated CA (D5): path length 0 (no sub-CAs), key usage limited to
/// certificate and CRL signing, DNS name constraints limited to the hosts Lockrail intercepts,
/// and a 365-day validity. Even if the CA key leaked, it could not mint a trusted certificate
/// for any other site. A 0.3.7 CA keeps working until `proxy uninstall-ca` + `install-ca`.
pub fn new_ca_params() -> CertificateParams {
    let mut params = ca_params_for_dn();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.name_constraints = Some(NameConstraints {
        permitted_subtrees: {
            let mut hosts: Vec<&str> = crate::proxy::AI_INTERCEPT_HOSTS.to_vec();
            for h in crate::sealer::SEALER_MITM_HOSTS {
                if !hosts.contains(h) {
                    hosts.push(h);
                }
            }
            hosts
                .into_iter()
                .map(|h| GeneralSubtree::DnsName(h.to_string()))
                .collect()
        },
        excluded_subtrees: vec![],
    });
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(CA_VALIDITY_DAYS);
    params
}

/// Returns consistent CA cert params (same Subject DN used for both generation and reconstruction).
fn ca_params_for_dn() -> CertificateParams {
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Lockrail Local CA");
    dn.push(DnType::OrganizationName, "Lockrail");
    params.distinguished_name = dn;
    params
}

#[derive(Debug)]
pub struct LocalCa {
    store: CaStore,
}

impl LocalCa {
    pub fn new(store: CaStore) -> Self {
        Self { store }
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        Ok(Self::new(CaStore::load(path)?))
    }

    pub fn cert_pem(&self) -> &str {
        self.store.cert_pem()
    }

    fn sign_for_host(&self, hostname: &str) -> Result<Arc<CertifiedKey>> {
        let ca_key = KeyPair::from_pem(&self.store.key_pem).context("parse CA private key")?;

        // Reconstruct the CA Certificate for signing. TLS chain validation only checks
        // Subject DN and the signature on the leaf cert — not the CA cert's serial number
        // or validity period — so this reconstructed cert (same DN + same key) is valid
        // for signing even though its serial number differs from the installed cert.
        let ca_cert = ca_params_for_dn()
            .self_signed(&ca_key)
            .context("reconstruct CA for signing")?;

        let leaf_key = KeyPair::generate().context("leaf keygen")?;
        let mut leaf_params = CertificateParams::default();
        leaf_params.subject_alt_names =
            vec![SanType::DnsName(hostname.try_into().map_err(|e| {
                anyhow::anyhow!("invalid hostname {hostname}: {e}")
            })?)];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, hostname);
        leaf_params.distinguished_name = dn;
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .context("sign leaf cert")?;

        let cert_der = CertificateDer::from(leaf_cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(leaf_key.serialize_der())
            .map_err(|e| anyhow::anyhow!("key der: {e}"))?;
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
            .map_err(|e| anyhow::anyhow!("signing key: {e:?}"))?;

        Ok(Arc::new(CertifiedKey::new(vec![cert_der], signing_key)))
    }
}

#[derive(Debug)]
pub struct DynamicCertResolver {
    ca: Arc<LocalCa>,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
    generated: std::sync::atomic::AtomicUsize,
}

impl DynamicCertResolver {
    pub fn new(ca: Arc<LocalCa>) -> Self {
        Self {
            ca,
            cache: Mutex::new(HashMap::new()),
            generated: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Leaf keys generated so far (D14: one per host for a shared resolver).
    pub fn generated(&self) -> usize {
        self.generated.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let name = client_hello.server_name()?.to_string();
        // C7: leaves only for the hosts Lockrail intercepts; the cache cannot grow per SNI.
        let known = crate::proxy::AI_INTERCEPT_HOSTS.contains(&name.as_str())
            || crate::sealer::SEALER_MITM_HOSTS.contains(&name.as_str());
        if !known {
            return None;
        }
        {
            let cache = self.cache.lock().ok()?;
            if let Some(key) = cache.get(&name) {
                return Some(key.clone());
            }
        }
        let ck = self.ca.sign_for_host(&name).ok()?;
        self.generated
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(name, ck.clone());
        }
        Some(ck)
    }
}

#[cfg(test)]
mod d5_tests {
    use super::*;

    /// GATE 4 (D5): name constraints present, validity within 366 days.
    #[test]
    fn new_ca_is_name_constrained_and_short_lived() {
        let store = CaStore::generate().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let pem = tmp.path().join("ca.pem");
        std::fs::write(&pem, store.cert_pem()).unwrap();
        let out = std::process::Command::new("openssl")
            .args(["x509", "-noout", "-text", "-in"])
            .arg(&pem)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("Name Constraints"), "{text}");
        assert!(text.contains("DNS:api.anthropic.com"), "{text}");
        assert!(text.contains("pathlen:0"), "{text}");
        let end = std::process::Command::new("openssl")
            .args([
                "x509",
                "-noout",
                "-checkend",
                &(366 * 24 * 3600).to_string(),
                "-in",
            ])
            .arg(&pem)
            .output()
            .unwrap();
        assert!(!end.status.success(), "CA valid for more than 366 days");
        let ok_now = std::process::Command::new("openssl")
            .args([
                "x509",
                "-noout",
                "-checkend",
                &(364 * 24 * 3600).to_string(),
                "-in",
            ])
            .arg(&pem)
            .output()
            .unwrap();
        assert!(ok_now.status.success(), "CA expires within 364 days");
    }
}
