use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;
use tracing::{debug, info};

#[cfg(target_os = "macos")]
pub struct KeychainManager {
    ca_name: String,
}

#[cfg(target_os = "macos")]
impl Default for KeychainManager {
    fn default() -> Self {
        Self {
            ca_name: "httpjail CA".to_string(),
        }
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
            .args(["find-certificate", "-c", &self.ca_name, "-p"])
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

        info!("Installing httpjail CA to user keychain...");
        println!("\n⚠️  Security Notice:");
        println!("You are about to install the httpjail CA certificate to your user keychain.");
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

        info!("Successfully installed httpjail CA to keychain");
        Ok(())
    }

    pub fn uninstall_ca(&self) -> Result<()> {
        info!("Removing httpjail CA from keychain...");

        let sha1_output = Command::new("security")
            .args(["find-certificate", "-a", "-c", &self.ca_name, "-Z"])
            .arg(self.get_user_keychain()?)
            .output()
            .context("Failed to find certificates")?;

        if !sha1_output.status.success() {
            info!("No httpjail CA found in keychain");
            return Ok(());
        }

        let output_str = String::from_utf8_lossy(&sha1_output.stdout);
        let mut removed_count = 0;

        for line in output_str.lines() {
            if line.contains("SHA-1 hash:")
                && let Some(hash) = line.split_whitespace().last()
            {
                let delete_output = Command::new("security")
                    .args(["delete-certificate", "-Z", hash])
                    .arg(self.get_user_keychain()?)
                    .output()
                    .context("Failed to delete certificate")?;

                if delete_output.status.success() {
                    removed_count += 1;
                    debug!("Removed certificate with SHA-1: {}", hash);
                }
            }
        }

        if removed_count > 0 {
            info!(
                "Removed {} httpjail CA certificate(s) from keychain",
                removed_count
            );
        } else {
            info!("No httpjail CA certificates found to remove");
        }

        Ok(())
    }

    fn cleanup_old_certificates(&self) -> Result<()> {
        let sha1_output = Command::new("security")
            .args(["find-certificate", "-a", "-c", &self.ca_name, "-Z"])
            .arg(self.get_user_keychain()?)
            .output()
            .context("Failed to find existing certificates")?;

        if !sha1_output.status.success() {
            return Ok(());
        }

        let output_str = String::from_utf8_lossy(&sha1_output.stdout);
        let mut old_certs = Vec::new();

        for line in output_str.lines() {
            if line.contains("SHA-1 hash:")
                && let Some(hash) = line.split_whitespace().last()
            {
                old_certs.push(hash.to_string());
            }
        }

        if !old_certs.is_empty() {
            info!(
                "Found {} existing httpjail CA certificate(s), removing old ones...",
                old_certs.len()
            );
            for hash in old_certs {
                let _ = Command::new("security")
                    .args(["delete-certificate", "-Z", &hash])
                    .arg(self.get_user_keychain()?)
                    .output();
                debug!("Removed old certificate with SHA-1: {}", hash);
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
