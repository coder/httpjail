use anyhow::{Context, Result};
use lru::LruCache;
use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::num::NonZeroUsize;
use std::sync::{Arc, RwLock};
use tracing::{debug, info};

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
}

impl CertificateManager {
    /// Create a new certificate manager with a self-signed CA
    pub fn new() -> Result<Self> {
        // Generate CA certificate
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
        let ca_cert = ca_params.self_signed(&ca_key_pair)
            .context("Failed to generate CA certificate")?;

        // Generate a single key pair to be used for all server certificates
        let server_key_pair = KeyPair::generate().context("Failed to generate server key pair")?;

        // Cache the private key in DER format
        let key_der_vec = server_key_pair.serialize_der();
        let server_key_der = PrivateKeyDer::try_from(key_der_vec.clone())
            .map_err(|_| anyhow::anyhow!("Failed to convert private key to DER"))?;

        info!("Generated CA certificate and server key pair for HTTPS interception");

        let cache_size = NonZeroUsize::new(CERT_CACHE_SIZE).expect("Cache size must be non-zero");

        Ok(Self {
            ca_cert,
            ca_key_pair,
            server_key_pair,
            server_key_der,
            cert_cache: Arc::new(RwLock::new(LruCache::new(cache_size))),
        })
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

        // Sign certificate with CA using the shared key pair
        let cert = params.signed_by(&self.server_key_pair, &self.ca_cert, &self.ca_key_pair)?;
        let cert_der = CertificateDer::from(cert.der().clone());

        // Also include CA cert in chain
        let ca_cert_der = self.ca_cert.der().clone();
        let ca_cert_der = CertificateDer::from(ca_cert_der);
        let cert_chain = vec![cert_der, ca_cert_der];

        // Cache the certificate chain (not the key, since it's shared)
        {
            let mut cache = self.cert_cache.write().unwrap();
            cache.put(hostname.to_string(), cert_chain.clone());
        }

        Ok((cert_chain, self.server_key_der.clone_key()))
    }

    /// Get the CA certificate in PEM format (for client trust)
    pub fn get_ca_cert_pem(&self) -> String {
        self.ca_cert.pem()
    }
}
