use anyhow::{Context, Result};
use std::path::Path;

/// Install the proxy CA certificate into the system trust store.
///
/// Returns a human-readable success message or a detailed error with manual
/// installation instructions. The cert PEM is always written to `cert_path`
/// so the user can install it manually if the automatic path requires
/// elevated privileges.
pub fn install_ca_system(cert_pem: &str, cert_path: &Path) -> Result<String> {
    std::fs::write(cert_path, cert_pem.as_bytes())
        .with_context(|| format!("write cert to {}", cert_path.display()))?;

    #[cfg(target_os = "macos")]
    return install_ca_macos(cert_path);

    #[cfg(target_os = "linux")]
    return install_ca_linux(cert_path);

    #[cfg(target_os = "windows")]
    return install_ca_windows(cert_path);

    #[allow(unreachable_code)]
    Ok(format!(
        "CA cert written to {}. Install it manually in your system trust store.",
        cert_path.display()
    ))
}

#[cfg(target_os = "macos")]
fn install_ca_macos(cert_path: &Path) -> Result<String> {
    // Prefer the user keychain (no sudo needed) then fall back to system keychain.
    let user_result = std::process::Command::new("security")
        .args([
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            &format!(
                "{}/Library/Keychains/login.keychain-db",
                dirs::home_dir()
                    .map(|h| h.to_string_lossy().into_owned())
                    .unwrap_or_default()
            ),
            &cert_path.to_string_lossy(),
        ])
        .status();

    if matches!(user_result, Ok(s) if s.success()) {
        return Ok(format!(
            "CA installed in macOS user keychain. Cert: {}",
            cert_path.display()
        ));
    }

    // Try system keychain (requires sudo).
    let system_result = std::process::Command::new("sudo")
        .args([
            "security",
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-k",
            "/Library/Keychains/System.keychain",
            &cert_path.to_string_lossy(),
        ])
        .status();

    if matches!(system_result, Ok(s) if s.success()) {
        return Ok(format!(
            "CA installed in macOS system keychain. Cert: {}",
            cert_path.display()
        ));
    }

    Err(anyhow::anyhow!(
        "Could not install CA automatically. Run manually:\n  \
        sudo security add-trusted-cert -d -r trustRoot \\\n    \
        -k /Library/Keychains/System.keychain {}",
        cert_path.display()
    ))
}

#[cfg(target_os = "linux")]
fn install_ca_linux(cert_path: &Path) -> Result<String> {
    // Detect the distro family by checking which trust-store directory exists.
    struct Distro {
        dir: &'static str,
        dest_name: &'static str,
        update_cmd: &'static [&'static str],
        label: &'static str,
    }

    let candidates = [
        Distro {
            dir: "/usr/local/share/ca-certificates",
            dest_name: "lockrail-local-ca.crt",
            update_cmd: &["update-ca-certificates"],
            label: "Debian/Ubuntu",
        },
        Distro {
            dir: "/etc/pki/ca-trust/source/anchors",
            dest_name: "lockrail-local-ca.crt",
            update_cmd: &["update-ca-trust", "extract"],
            label: "RHEL/Fedora/CentOS",
        },
        Distro {
            dir: "/etc/ca-certificates/trust-source/anchors",
            dest_name: "lockrail-local-ca.crt",
            update_cmd: &["trust", "extract-compat"],
            label: "Arch Linux",
        },
    ];

    for d in &candidates {
        let dir = std::path::Path::new(d.dir);
        if !dir.exists() {
            continue;
        }
        let dest = dir.join(d.dest_name);
        if let Err(e) = std::fs::copy(cert_path, &dest) {
            // Likely a permission error — try with sudo.
            let sudo_ok = std::process::Command::new("sudo")
                .arg("cp")
                .arg(cert_path)
                .arg(&dest)
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !sudo_ok {
                return Err(anyhow::anyhow!(
                    "Could not copy cert to {} ({}). Try:\n  sudo cp {} {}",
                    dest.display(),
                    e,
                    cert_path.display(),
                    dest.display()
                ));
            }
        }
        // Run the trust-store update command.
        let update_ok = std::process::Command::new(d.update_cmd[0])
            .args(&d.update_cmd[1..])
            .status()
            .or_else(|_| {
                std::process::Command::new("sudo")
                    .args(d.update_cmd)
                    .status()
            })
            .map(|s| s.success())
            .unwrap_or(false);

        if update_ok {
            return Ok(format!(
                "CA installed ({}) via {}. Cert: {}",
                d.label,
                d.update_cmd.join(" "),
                cert_path.display()
            ));
        }
    }

    Err(anyhow::anyhow!(
        "Could not detect Linux distro trust store. Install manually:\n\
        # Debian/Ubuntu:\n  \
            sudo cp {0} /usr/local/share/ca-certificates/lockrail-ca.crt && sudo update-ca-certificates\n\
        # RHEL/Fedora:\n  \
            sudo cp {0} /etc/pki/ca-trust/source/anchors/lockrail-ca.crt && sudo update-ca-trust extract\n\
        # Arch:\n  \
            sudo cp {0} /etc/ca-certificates/trust-source/anchors/lockrail-ca.crt && sudo trust extract-compat",
        cert_path.display()
    ))
}

#[cfg(target_os = "windows")]
fn install_ca_windows(cert_path: &Path) -> Result<String> {
    // certutil is built into Windows; no sudo equivalent needed — it prompts UAC.
    let result = std::process::Command::new("certutil")
        .args([
            "-addstore",
            "-user", // Current-user store, no elevation required
            "Root",
            &cert_path.to_string_lossy(),
        ])
        .status();

    if matches!(result, Ok(s) if s.success()) {
        return Ok(format!(
            "CA installed in Windows current-user Root store. Cert: {}",
            cert_path.display()
        ));
    }

    // Try system-wide (requires elevation).
    let result_sys = std::process::Command::new("certutil")
        .args(["-addstore", "Root", &cert_path.to_string_lossy()])
        .status();

    if matches!(result_sys, Ok(s) if s.success()) {
        return Ok(format!(
            "CA installed in Windows system Root store. Cert: {}",
            cert_path.display()
        ));
    }

    Err(anyhow::anyhow!(
        "Could not install CA automatically. Run in an elevated PowerShell:\n  \
        certutil -addstore Root \"{}\"",
        cert_path.display()
    ))
}
