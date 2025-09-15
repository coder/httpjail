use anyhow::{Context, Result};
use camino::Utf8PathBuf;
use lru::LruCache;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};

#[cfg(target_os = "macos")]
use crate::macos_keychain::KeychainManager;

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
            dirs::config_dir()
                .context("Could not find user config directory")?
                .join("httpjail")
                .try_into()
                .context("Config directory path is not valid UTF-8")?
        };

        // Create directory if it doesn't exist
        fs::create_dir_all(&config_dir).context("Failed to create config directory")?;

        let ca_cert_path = config_dir.join("ca-cert.pem");
        let ca_key_path = config_dir.join("ca-key.pem");

        // Try to load existing CA
        if ca_cert_path.exists() && ca_key_path.exists() {
            debug!("Loading cached CA certificate from {:?}", ca_cert_path);

            let _cert_pem =
                fs::read_to_string(&ca_cert_path).context("Failed to read CA certificate")?;
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

        // Save to disk
        fs::write(&ca_cert_path, ca_cert.pem()).context("Failed to write CA certificate")?;
        fs::write(&ca_key_path, ca_key_pair.serialize_pem()).context("Failed to write CA key")?;

        // Set permissions to 600 (read/write for owner only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&ca_key_path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&ca_key_path, perms)?;
        }

        info!("Saved new CA certificate to {}", ca_cert_path);

        // On macOS, install the CA to the keychain (unless disabled for testing)
        #[cfg(target_os = "macos")]
        {
            // Skip automatic keychain installation during tests or when explicitly disabled
            if std::env::var("HTTPJAIL_SKIP_KEYCHAIN_INSTALL").is_err() {
                let keychain_manager = KeychainManager::new();
                if let Err(e) = keychain_manager.install_ca(ca_cert_path.as_std_path()) {
                    warn!("CA not installed to keychain: {}", e);
                    warn!(
                        "Applications may fail with certificate errors. Run 'httpjail trust --install' to trust the CA."
                    );
                } else {
                    info!("CA certificate automatically installed to macOS keychain");
                }
            } else {
                debug!(
                    "Skipping automatic keychain installation (HTTPJAIL_SKIP_KEYCHAIN_INSTALL set)"
                );
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
        let config_dir = dirs::config_dir()
            .context("Could not find user config directory")?
            .join("httpjail");
        let config_dir: Utf8PathBuf = config_dir
            .try_into()
            .context("Config directory path is not valid UTF-8")?;
        Ok(config_dir.join("ca-cert.pem"))
    }

    /// Generate environment variables for common tools to use the CA certificate
    pub fn get_ca_env_vars() -> Result<Vec<(String, String)>> {
        // Try multiple possible locations for the CA certificate
        // This handles cases where the effective user changes (e.g., sudo in CI)
        let mut ca_path = Self::get_ca_cert_path()?;

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
            ("NODE_EXTRA_CA_CERTS".to_string(), ca_path_str),
        ];

        Ok(env_vars)
    }
}
