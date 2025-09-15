use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;
use tracing::{debug, info};

const CA_NAME: &str = "httpjail CA";

#[cfg(target_os = "macos")]
pub struct KeychainManager;

#[cfg(target_os = "macos")]
impl Default for KeychainManager {
    fn default() -> Self {
        Self
    }
}

#[cfg(target_os = "macos")]
impl KeychainManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_ca_trusted(&self) -> Result<bool> {
        // First check if the certificate exists in keychain
        let find_output = Command::new("security")
            .args(["find-certificate", "-c", CA_NAME, "-p"])
            .arg(self.get_user_keychain()?)
            .output()
            .context("Failed to check for CA certificate")?;

        if !find_output.status.success() {
            debug!("Certificate not found in keychain");
            return Ok(false);
        }

        // Certificate exists in keychain, now verify if it's actually trusted for SSL
        // We need to get the certificate path to verify it
        let config_dir = dirs::config_dir()
            .context("Could not find user config directory")?
            .join("httpjail");
        let ca_cert_path = config_dir.join("ca-cert.pem");

        if !ca_cert_path.exists() {
            debug!("Certificate file not found at {:?}", ca_cert_path);
            return Ok(false);
        }

        // Use verify-cert to check if it's trusted for SSL
        // -p ssl specifies we're checking SSL trust policy
        let verify_output = Command::new("security")
            .args([
                "verify-cert",
                "-c",
                ca_cert_path.to_str().unwrap(),
                "-p",
                "ssl",
            ])
            .output()
            .context("Failed to verify certificate trust")?;

        if !verify_output.status.success() {
            debug!("Certificate exists but is not trusted for SSL");
            debug!(
                "verify-cert stderr: {}",
                String::from_utf8_lossy(&verify_output.stderr)
            );
        }

        // verify-cert returns 0 if the certificate is trusted
        Ok(verify_output.status.success())
    }

    pub fn install_ca(&self, cert_path: &Path) -> Result<()> {
        self.cleanup_old_certificates()?;

        info!("Installing {} to user keychain...", CA_NAME);
        println!("\n⚠️  Security Notice:");
        println!(
            "You are about to install the {} certificate to your user keychain.",
            CA_NAME
        );
        println!("This allows httpjail to inspect HTTPS traffic for allowed domains.");
        println!("The certificate will only be trusted for SSL connections.");
        println!("\nYou may be prompted for your password to authorize this change.");
        println!("To uninstall later, run: httpjail trust --remove\n");

        let output = Command::new("security")
            .args(["add-trusted-cert", "-d", "-r", "trustRoot", "-p", "ssl"])
            .arg("-k")
            .arg(self.get_user_keychain()?)
            .arg(cert_path)
            .output()
            .context("Failed to add certificate to keychain")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("User canceled") {
                anyhow::bail!("Installation canceled by user");
            } else if stderr.contains("authorization") || stderr.contains("MDM") {
                anyhow::bail!("Installation blocked by system policy or MDM restrictions");
            } else {
                anyhow::bail!("Failed to install certificate: {}", stderr);
            }
        }

        info!("Successfully installed {} to keychain", CA_NAME);

        // Try to show certificate info
        if let Ok(cert_content) = std::fs::read_to_string(cert_path) {
            if let Ok(info) = self.get_cert_info(&cert_content) {
                println!("✓ Installed certificate: {}", info);
            }
        }

        Ok(())
    }

    pub fn uninstall_ca(&self) -> Result<()> {
        info!("Looking for {} in keychain...", CA_NAME);

        let find_output = Command::new("security")
            .args(["find-certificate", "-a", "-c", CA_NAME, "-p", "-Z"])
            .arg(self.get_user_keychain()?)
            .output()
            .context("Failed to find certificates")?;

        if !find_output.status.success() || find_output.stdout.is_empty() {
            println!("No {} certificates found in keychain", CA_NAME);
            return Ok(());
        }

        let output_str = String::from_utf8_lossy(&find_output.stdout);
        let mut removed_count = 0;
        let mut cert_info = Vec::new();

        // Extract certificate info and hashes
        let mut current_cert_pem = String::new();
        let mut in_cert = false;

        for line in output_str.lines() {
            if line == "-----BEGIN CERTIFICATE-----" {
                in_cert = true;
                current_cert_pem.clear();
                current_cert_pem.push_str(line);
                current_cert_pem.push('\n');
            } else if line == "-----END CERTIFICATE-----" {
                current_cert_pem.push_str(line);
                in_cert = false;
                // Try to get basic cert info
                if let Ok(info) = self.get_cert_info(&current_cert_pem) {
                    cert_info.push(info);
                }
            } else if in_cert {
                current_cert_pem.push_str(line);
                current_cert_pem.push('\n');
            } else if (line.contains("SHA-256 hash:") || line.contains("SHA-1 hash:"))
                && let Some(hash) = line.split(':').last().map(|s| s.trim())
            {
                let delete_output = Command::new("security")
                    .args(["delete-certificate", "-Z", hash])
                    .arg(self.get_user_keychain()?)
                    .output()
                    .context("Failed to delete certificate")?;

                if delete_output.status.success() {
                    removed_count += 1;
                    if !cert_info.is_empty() && cert_info.len() > removed_count - 1 {
                        let info = &cert_info[removed_count - 1];
                        println!("✓ Removed certificate: {}", info);
                    } else {
                        println!("✓ Removed certificate with hash: {}", hash);
                    }
                }
            }
        }

        if removed_count > 0 {
            println!(
                "Successfully removed {} {} certificate(s) from keychain",
                removed_count, CA_NAME
            );
        } else {
            println!(
                "No {} certificates were removed (may have already been removed)",
                CA_NAME
            );
        }

        Ok(())
    }

    fn cleanup_old_certificates(&self) -> Result<()> {
        let sha1_output = Command::new("security")
            .args(["find-certificate", "-a", "-c", CA_NAME, "-Z"])
            .arg(self.get_user_keychain()?)
            .output()
            .context("Failed to find existing certificates")?;

        if !sha1_output.status.success() {
            return Ok(());
        }

        let output_str = String::from_utf8_lossy(&sha1_output.stdout);
        let mut old_certs = Vec::new();

        for line in output_str.lines() {
            // Accept both SHA-256 and SHA-1 hashes (SHA-256 preferred)
            if (line.contains("SHA-256 hash:") || line.contains("SHA-1 hash:"))
                && let Some(hash) = line.split(':').last().map(|s| s.trim())
            {
                old_certs.push(hash.to_string());
            }
        }

        if !old_certs.is_empty() {
            info!(
                "Found {} existing {} certificate(s), removing old ones...",
                old_certs.len(),
                CA_NAME
            );
            for hash in old_certs {
                let _ = Command::new("security")
                    .args(["delete-certificate", "-Z", &hash])
                    .arg(self.get_user_keychain()?)
                    .output();
                debug!("Removed old certificate with hash: {}", hash);
            }
        }

        Ok(())
    }

    fn get_user_keychain(&self) -> Result<String> {
        let output = Command::new("security")
            .arg("default-keychain")
            .arg("-d")
            .arg("user")
            .output()
            .context("Failed to get default keychain")?;

        if !output.status.success() {
            anyhow::bail!("Failed to determine default keychain");
        }

        let keychain_path = String::from_utf8_lossy(&output.stdout)
            .trim()
            .trim_matches('"')
            .to_string();

        if keychain_path.is_empty() {
            anyhow::bail!("Could not determine user keychain path");
        }

        Ok(keychain_path)
    }

    fn get_cert_info(&self, cert_pem: &str) -> Result<String> {
        // Use openssl to parse certificate info
        use std::io::Write;
        use std::process::Stdio;

        let mut child = Command::new("openssl")
            .args([
                "x509",
                "-noout",
                "-subject",
                "-issuer",
                "-dates",
                "-fingerprint",
                "-sha256",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn openssl")?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(cert_pem.as_bytes())
                .context("Failed to write to openssl")?;
        }

        let output = child
            .wait_with_output()
            .context("Failed to read openssl output")?;

        if !output.status.success() {
            return Ok("unknown certificate".to_string());
        }

        let info_str = String::from_utf8_lossy(&output.stdout);
        let mut info_parts = Vec::new();

        for line in info_str.lines() {
            if line.starts_with("subject=") {
                if let Some(cn) = line.split("CN=").nth(1) {
                    if let Some(cn_value) = cn.split(',').next() {
                        info_parts.push(format!("CN={}", cn_value.trim()));
                    }
                }
            } else if line.starts_with("notAfter=") {
                let expiry = line.strip_prefix("notAfter=").unwrap_or("");
                info_parts.push(format!("expires {}", expiry));
            } else if line.starts_with("SHA256 Fingerprint=") {
                if let Some(fp) = line.split('=').nth(1) {
                    // Take first 16 chars of fingerprint for brevity
                    let short_fp = fp
                        .chars()
                        .filter(|c| *c != ':')
                        .take(16)
                        .collect::<String>();
                    info_parts.push(format!("SHA256:{}", short_fp));
                }
            }
        }

        if info_parts.is_empty() {
            Ok("certificate".to_string())
        } else {
            Ok(info_parts.join(", "))
        }
    }

    pub fn check_keychain_unlocked(&self) -> Result<bool> {
        let output = Command::new("security")
            .args(["show-keychain-info"])
            .arg(self.get_user_keychain()?)
            .output()
            .context("Failed to check keychain status")?;

        Ok(output.status.success())
    }
}

#[cfg(not(target_os = "macos"))]
pub struct KeychainManager;

#[cfg(not(target_os = "macos"))]
impl Default for KeychainManager {
    fn default() -> Self {
        Self
    }
}

#[cfg(not(target_os = "macos"))]
impl KeychainManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_ca_trusted(&self) -> Result<bool> {
        Ok(false)
    }

    pub fn install_ca(&self, _cert_path: &Path) -> Result<()> {
        anyhow::bail!("Keychain integration is only available on macOS")
    }

    pub fn uninstall_ca(&self) -> Result<()> {
        anyhow::bail!("Keychain integration is only available on macOS")
    }

    pub fn check_keychain_unlocked(&self) -> Result<bool> {
        Ok(false)
    }
}
