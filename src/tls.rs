use anyhow::{Context, Result};
use camino::Utf8PathBuf;
use lru::LruCache;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
#[cfg(target_os = "macos")]
use tracing::warn;
use tracing::{debug, info};

#[cfg(target_os = "macos")]
use crate::macos_keychain::KeychainManager;

fn default_ca_dir() -> Result<Utf8PathBuf> {
    #[cfg(target_os = "linux")]
    if unsafe { libc::geteuid() == 0 } {
        let dir = std::path::Path::new("/var/lib/httpjail/ca");
        crate::jail::ensure_trusted_root_dir(dir)?;
        // The signing key remains 0600, but jailed clients must traverse these
        // trusted directories to read the public certificate.
        use std::os::unix::fs::PermissionsExt;
        for public_dir in [dir.parent().expect("CA parent"), dir] {
            std::fs::set_permissions(public_dir, std::fs::Permissions::from_mode(0o755))?;
        }
        return dir
            .to_path_buf()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid CA directory path"));
    }
    dirs::config_dir()
        .context("Could not find user config directory")?
        .join("httpjail")
        .try_into()
        .context("Config directory path is not valid UTF-8")
}

const CERT_CACHE_SIZE: usize = 1024;

/// Manages TLS certificates for HTTPS interception
pub struct CertificateManager {
    /// Root CA certificate
    ca_cert: Certificate,
    /// CA key pair (for signing)
    ca_key_pair: KeyPair,
    /// Shared key pair for all server certificates (for performance)
    server_key_pair: KeyPair,
    /// Private key in DER format (cached for reuse)
    server_key_der: PrivateKeyDer<'static>,
    /// LRU cache of generated certificates per hostname
    cert_cache: Arc<RwLock<LruCache<String, Vec<CertificateDer<'static>>>>>,
    /// Custom config directory (for testing)
    #[allow(dead_code)]
    config_dir: Option<Utf8PathBuf>,
}

impl CertificateManager {
    /// Load or generate CA certificate and key with custom dir
    fn load_or_generate_ca_with_dir(
        config_dir: Option<&Utf8PathBuf>,
    ) -> Result<(Certificate, KeyPair)> {
        let config_dir = if let Some(dir) = config_dir {
            dir.clone()
        } else {
            default_ca_dir()?
        };

        // Create directory if it doesn't exist
        fs::create_dir_all(&config_dir).context("Failed to create config directory")?;

        #[cfg(target_os = "linux")]
        let _ca_lock = if unsafe { libc::geteuid() == 0 } {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::OpenOptionsExt;
            // Concurrent strong jails must not see a half-written cert/key pair.
            let lock = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(config_dir.join(".ca.lock"))?;
            use std::os::unix::fs::MetadataExt;
            let metadata = lock.metadata()?;
            anyhow::ensure!(
                metadata.is_file() && metadata.uid() == 0,
                "CA lock must be root-owned and regular"
            );
            anyhow::ensure!(
                unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == 0,
                "Failed to lock CA directory"
            );
            Some(lock)
        } else {
            None
        };

        let ca_cert_path = config_dir.join("ca-cert.pem");
        let ca_key_path = config_dir.join("ca-key.pem");

        // Try to load existing CA
        if ca_cert_path.exists() && ca_key_path.exists() {
            debug!("Loading cached CA certificate from {:?}", ca_cert_path);

            #[cfg(target_os = "linux")]
            let _cert_pem = if unsafe { libc::geteuid() == 0 } {
                use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
                let mut cert = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&ca_cert_path)
                    .context("Failed to open public CA certificate")?;
                let metadata = cert.metadata()?;
                anyhow::ensure!(
                    metadata.is_file() && metadata.uid() == 0,
                    "CA certificate must be root-owned and regular"
                );
                cert.set_permissions(fs::Permissions::from_mode(0o644))?;
                let mut pem = String::new();
                cert.read_to_string(&mut pem)?;
                pem
            } else {
                fs::read_to_string(&ca_cert_path).context("Failed to read CA certificate")?
            };
            #[cfg(not(target_os = "linux"))]
            let _cert_pem =
                fs::read_to_string(&ca_cert_path).context("Failed to read CA certificate")?;
            #[cfg(unix)]
            let key_pem = {
                use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
                let mut key = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&ca_key_path)
                    .context("Failed to open CA key")?;
                let metadata = key.metadata()?;
                anyhow::ensure!(metadata.is_file(), "CA key must be a regular file");
                #[cfg(target_os = "linux")]
                if unsafe { libc::geteuid() == 0 } {
                    use std::os::unix::fs::MetadataExt;
                    anyhow::ensure!(metadata.uid() == 0, "Privileged CA key must be root-owned");
                }
                if metadata.permissions().mode() & 0o077 != 0 {
                    key.set_permissions(fs::Permissions::from_mode(0o600))
                        .context("Failed to restrict existing CA key permissions")?;
                }
                let mut pem = String::new();
                key.read_to_string(&mut pem)
                    .context("Failed to read CA key")?;
                pem
            };
            #[cfg(not(unix))]
            let key_pem = fs::read_to_string(&ca_key_path).context("Failed to read CA key")?;

            // Parse the PEM files
            let key_pair = KeyPair::from_pem(&key_pem).context("Failed to parse CA key")?;

            // Recreate the CA certificate from the stored files
            // Since rcgen doesn't support loading existing certificates,
            // we'll need to regenerate if this fails
            // For now, just return the key pair and cert as stored
            // This is a limitation of rcgen - in production you'd use a different approach

            // Generate new params but use existing key
            let mut ca_params = CertificateParams::default();
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

            let mut dn = DistinguishedName::new();
            dn.push(DnType::CountryName, "US");
            dn.push(DnType::OrganizationName, "httpjail");
            dn.push(DnType::CommonName, "httpjail CA");
            ca_params.distinguished_name = dn;

            ca_params.key_usages = vec![
                rcgen::KeyUsagePurpose::DigitalSignature,
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::CrlSign,
            ];

            let ca_cert = ca_params
                .self_signed(&key_pair)
                .context("Failed to recreate CA certificate")?;

            info!("Loaded cached CA certificate from {}", ca_cert_path);
            return Ok((ca_cert, key_pair));
        }

        // Generate new CA certificate
        info!("Generating new CA certificate");
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CountryName, "US");
        dn.push(DnType::OrganizationName, "httpjail");
        dn.push(DnType::CommonName, "httpjail CA");
        ca_params.distinguished_name = dn;

        ca_params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        let ca_key_pair = KeyPair::generate()?;
        let ca_cert = ca_params
            .self_signed(&ca_key_pair)
            .context("Failed to generate CA certificate")?;

        // Never follow a preexisting cert symlink into an unrelated root-owned file.
        let mut cert_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&ca_cert_path)
            .context("Failed to create exclusive CA certificate")?;
        cert_file
            .write_all(ca_cert.pem().as_bytes())
            .context("Failed to write CA certificate")?;
        #[cfg(target_os = "linux")]
        if unsafe { libc::geteuid() == 0 } {
            use std::os::unix::fs::PermissionsExt;
            cert_file.set_permissions(fs::Permissions::from_mode(0o644))?;
        }
        // Restrict permissions at creation, before any private-key bytes are written.
        let mut key_file = OpenOptions::new();
        key_file.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            key_file.mode(0o600);
        }
        key_file
            .open(&ca_key_path)
            .and_then(|mut file| file.write_all(ca_key_pair.serialize_pem().as_bytes()))
            .context("Failed to write CA key")?;

        info!("Saved new CA certificate to {}", ca_cert_path);

        // On macOS, install the CA to the keychain (unless disabled for testing)
        #[cfg(target_os = "macos")]
        {
            // Skip automatic keychain installation if:
            // 1. Explicitly disabled via environment variable (for tests)
            // 2. Not running in a TTY (non-interactive, CI/automation)
            let skip_env = std::env::var("HTTPJAIL_SKIP_KEYCHAIN_INSTALL").is_ok();
            let is_tty = atty::is(atty::Stream::Stdout);

            if skip_env {
                debug!(
                    "Skipping automatic keychain installation (HTTPJAIL_SKIP_KEYCHAIN_INSTALL set)"
                );
            } else if !is_tty {
                debug!("Skipping automatic keychain installation (not running in TTY)");
            } else {
                let keychain_manager = KeychainManager::new();
                if let Err(e) = keychain_manager.install_ca(ca_cert_path.as_std_path()) {
                    warn!("CA not installed to keychain: {}", e);
                    warn!(
                        "Applications may fail with certificate errors. Run 'httpjail trust --install' to trust the CA."
                    );
                } else {
                    info!("CA certificate automatically installed to macOS keychain");
                }
            }
        }

        Ok((ca_cert, ca_key_pair))
    }

    /// Create a new certificate manager with a self-signed CA
    pub fn new() -> Result<Self> {
        Self::with_config_dir(None)
    }

    /// Create a new certificate manager with a custom config directory (for testing)
    pub fn with_config_dir(config_dir: Option<Utf8PathBuf>) -> Result<Self> {
        // Load or generate CA certificate with custom config dir
        let (ca_cert, ca_key_pair) = Self::load_or_generate_ca_with_dir(config_dir.as_ref())?;

        // Generate a single key pair to be used for all server certificates
        let server_key_pair = KeyPair::generate().context("Failed to generate server key pair")?;

        // Cache the private key in DER format
        let key_der_vec = server_key_pair.serialize_der();
        let server_key_der = PrivateKeyDer::try_from(key_der_vec.clone())
            .map_err(|_| anyhow::anyhow!("Failed to convert private key to DER"))?;

        info!("Certificate manager initialized");

        let cache_size = NonZeroUsize::new(CERT_CACHE_SIZE).expect("Cache size must be non-zero");

        Ok(Self {
            ca_cert,
            ca_key_pair,
            server_key_pair,
            server_key_der,
            cert_cache: Arc::new(RwLock::new(LruCache::new(cache_size))),
            config_dir,
        })
    }

    /// Check if the CA certificate is trusted on macOS
    #[cfg(target_os = "macos")]
    pub fn is_ca_trusted() -> bool {
        let keychain_manager = KeychainManager::new();
        keychain_manager.is_ca_trusted().unwrap_or(false)
    }

    #[cfg(not(target_os = "macos"))]
    pub fn is_ca_trusted() -> bool {
        // On non-macOS systems, we rely on environment variables
        true
    }

    /// Get or generate a certificate for a hostname
    pub fn get_cert_for_host(
        &self,
        hostname: &str,
    ) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        // Check cache first
        {
            let mut cache = self.cert_cache.write().unwrap();
            if let Some(cert_chain) = cache.get(hostname) {
                debug!("Using cached certificate for {}", hostname);
                // Return cached cert with the shared key
                return Ok((cert_chain.clone(), self.server_key_der.clone_key()));
            }
        }

        // Generate new certificate
        debug!("Generating certificate for {}", hostname);
        info!(
            "Certificate generation: hostname={}, key_type=ECDSA-P256",
            hostname
        );

        let mut params = CertificateParams::new(vec![hostname.to_string()])
            .context("Failed to create certificate params")?;

        params.subject_alt_names = vec![SanType::DnsName(hostname.try_into()?)];

        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, hostname);
        params.distinguished_name = dn;

        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyAgreement,
        ];

        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

        // Set serial number explicitly to avoid potential issues with OpenSSL 3.0.x
        params.serial_number = Some(rcgen::SerialNumber::from(vec![1, 2, 3, 4]));

        // Set validity period - 1 year from now
        // Use shorter validity period to ensure UTCTime format for OpenSSL 3.0 compatibility
        use chrono::{Datelike, Utc};
        let now = Utc::now();
        // Ensure we use UTCTime format (years < 2050) for OpenSSL 3.0 compatibility
        let end_year = std::cmp::min(now.year() + 1, 2049);
        let not_before = rcgen::date_time_ymd(now.year(), now.month() as u8, now.day() as u8);
        let not_after = rcgen::date_time_ymd(end_year, now.month() as u8, now.day() as u8);
        params.not_before = not_before;
        params.not_after = not_after;

        // Sign certificate with CA using the shared key pair
        let cert = params.signed_by(&self.server_key_pair, &self.ca_cert, &self.ca_key_pair)?;
        let cert_der = cert.der().clone();

        // Debug certificate details for OpenSSL compatibility issues
        debug!(
            "Generated certificate for {}: {} bytes",
            hostname,
            cert_der.len()
        );

        // Also include CA cert in chain
        let ca_cert_der = self.ca_cert.der().clone();
        // ca_cert_der is already the correct type
        let cert_chain = vec![cert_der, ca_cert_der];

        // Cache the certificate chain (not the key, since it's shared)
        {
            let mut cache = self.cert_cache.write().unwrap();
            cache.put(hostname.to_string(), cert_chain.clone());
        }

        Ok((cert_chain, self.server_key_der.clone_key()))
    }

    /// Get the CA certificate in PEM format (for client trust)
    #[allow(dead_code)]
    pub fn get_ca_cert_pem(&self) -> String {
        self.ca_cert.pem()
    }

    /// Get the CA certificate in DER format (for adding to trust stores)
    pub fn get_ca_cert_der(&self) -> rustls::pki_types::CertificateDer<'static> {
        self.ca_cert.der().clone()
    }

    /// Get the path to the CA certificate file
    pub fn get_ca_cert_path() -> Result<Utf8PathBuf> {
        Ok(default_ca_dir()?.join("ca-cert.pem"))
    }

    /// Generate environment variables for common tools to use the CA certificate
    pub fn get_ca_env_vars() -> Result<Vec<(String, String)>> {
        // Try multiple possible locations for the CA certificate
        // This handles cases where the effective user changes (e.g., sudo in CI)
        let mut ca_path = Self::get_ca_cert_path()?;

        #[cfg(target_os = "linux")]
        if unsafe { libc::geteuid() == 0 } {
            anyhow::ensure!(
                ca_path.exists(),
                "Privileged CA certificate missing from trusted root directory"
            );
        }

        if !ca_path.exists() {
            // If not found in current user's config, check common locations
            let possible_paths = [
                // Check SUDO_USER's config directory
                std::env::var("SUDO_USER").ok().and_then(|sudo_user| {
                    dirs::home_dir().map(|home| {
                        home.parent()
                            .unwrap_or(&home)
                            .join(sudo_user)
                            .join(".config/httpjail/ca-cert.pem")
                    })
                }),
                // Check /home/runner for CI
                Some(PathBuf::from("/home/runner/.config/httpjail/ca-cert.pem")),
                // Check root's config
                Some(PathBuf::from("/root/.config/httpjail/ca-cert.pem")),
            ];

            for path in possible_paths.iter().flatten() {
                if path.exists() {
                    ca_path = Utf8PathBuf::try_from(path.clone())
                        .context("CA cert path is not valid UTF-8")?;
                    debug!("Found CA certificate at alternate location: {}", ca_path);
                    break;
                }
            }

            if !ca_path.exists() {
                anyhow::bail!(
                    "CA certificate not found. Searched: {:?} and common locations",
                    ca_path
                );
            }
        }

        let ca_path_str = ca_path.to_string();
        let ca_dir = ca_path
            .parent()
            .map(|p| p.to_string())
            .unwrap_or_else(|| ".".to_string());

        let env_vars = vec![
            // OpenSSL/LibreSSL-based tools (generic)
            ("SSL_CERT_FILE".to_string(), ca_path_str.clone()),
            ("SSL_CERT_DIR".to_string(), ca_dir),
            // curl (works with OpenSSL/LibreSSL builds)
            ("CURL_CA_BUNDLE".to_string(), ca_path_str.clone()),
            // Git
            ("GIT_SSL_CAINFO".to_string(), ca_path_str.clone()),
            // Python requests
            ("REQUESTS_CA_BUNDLE".to_string(), ca_path_str.clone()),
            // Node.js
            ("NODE_EXTRA_CA_CERTS".to_string(), ca_path_str.clone()),
            // Deno
            ("DENO_CERT".to_string(), ca_path_str),
        ];

        Ok(env_vars)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn ca_creation_refuses_preexisting_cert_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let config = Utf8PathBuf::from_path_buf(dir.path().join("ca")).unwrap();
        fs::create_dir(&config).unwrap();
        let sentinel = dir.path().join("sentinel");
        fs::write(&sentinel, "unchanged").unwrap();
        std::os::unix::fs::symlink(&sentinel, config.join("ca-cert.pem")).unwrap();
        assert!(CertificateManager::load_or_generate_ca_with_dir(Some(&config)).is_err());
        assert_eq!(fs::read_to_string(&sentinel).unwrap(), "unchanged");
    }

    #[test]
    fn ca_key_is_private_on_creation_and_cached_load() {
        let dir = tempfile::tempdir().unwrap();
        let config = Utf8PathBuf::from_path_buf(dir.path().join("ca")).unwrap();
        CertificateManager::load_or_generate_ca_with_dir(Some(&config)).unwrap();
        let key = config.join("ca-key.pem");
        assert_eq!(
            fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );

        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        CertificateManager::load_or_generate_ca_with_dir(Some(&config)).unwrap();
        assert_eq!(
            fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
