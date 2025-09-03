use std::sync::Arc;
use tracing::{debug, warn};

#[derive(Debug)]
pub struct DangerousAcceptAnyVerifier;

impl rustls::client::danger::ServerCertVerifier for DangerousAcceptAnyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        debug!("=== Certificate chain verification (BYPASSED) ===");
        debug!("Server name: {:?}", server_name);
        debug!("End entity certificate length: {} bytes", end_entity.len());
        debug!(
            "Number of intermediate certificates: {}",
            intermediates.len()
        );

        for (i, intermediate) in intermediates.iter().enumerate() {
            debug!(
                "Intermediate certificate #{}: {} bytes",
                i + 1,
                intermediate.len()
            );
        }

        warn!("DANGER: Accepting certificate without verification!");

        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        debug!("TLS 1.2 signature verification (BYPASSED)");
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        debug!("TLS 1.3 signature verification (BYPASSED)");
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

pub fn create_dangerous_client_config() -> rustls::ClientConfig {
    warn!("DANGEROUS: Creating TLS client with certificate validation DISABLED!");

    rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DangerousAcceptAnyVerifier))
        .with_no_client_auth()
}
