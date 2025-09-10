/// Common proxy utilities for HTTP and HTTPS.
use crate::dangerous_verifier::create_dangerous_client_config;
use crate::rules::{Action, RuleEngine};
#[allow(unused_imports)]
use crate::tls::CertificateManager;
use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Error as HyperError, Request, Response, StatusCode, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rand::Rng;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

pub const HTTPJAIL_HEADER: &str = "HTTPJAIL";
pub const HTTPJAIL_HEADER_VALUE: &str = "true";
pub const BLOCKED_MESSAGE: &str = "Request blocked by httpjail\n";

/// Create a raw HTTP/1.1 403 Forbidden response for CONNECT tunnels
pub fn create_connect_403_response() -> &'static [u8] {
    b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 27\r\n\r\nRequest blocked by httpjail"
}

// Shared HTTP/HTTPS client for upstream requests
static HTTPS_CLIENT: OnceLock<
    Client<
        hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        BoxBody<Bytes, HyperError>,
    >,
> = OnceLock::new();

/// Prepare a request for forwarding to upstream server
/// Removes proxy-specific headers and converts body to BoxBody
pub fn prepare_upstream_request(
    req: Request<Incoming>,
    target_uri: Uri,
) -> Request<BoxBody<Bytes, HyperError>> {
    let (mut parts, incoming_body) = req.into_parts();

    // Update the URI
    parts.uri = target_uri;

    // Remove proxy-specific headers only
    // Don't remove connection-related headers as the client will handle them
    parts.headers.remove("proxy-connection");
    parts.headers.remove("proxy-authorization");
    parts.headers.remove("proxy-authenticate");

    // Convert incoming body to boxed body
    let boxed_request_body = incoming_body.boxed();

    // Create new request with boxed body
    Request::from_parts(parts, boxed_request_body)
}

/// Create a client config that trusts both webpki roots and the httpjail CA
/// We use webpki-roots (Mozilla's trusted roots) instead of native roots to ensure
/// consistent behavior across platforms and avoid potential issues with system cert stores
fn create_client_config_with_ca(
    ca_cert_der: rustls::pki_types::CertificateDer<'static>,
) -> rustls::ClientConfig {
    use rustls::RootCertStore;

    // Start with webpki roots (Mozilla's trusted roots - same as Firefox)
    let mut roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Add our httpjail CA certificate
    roots
        .add(ca_cert_der)
        .expect("Failed to add httpjail CA to trust store");

    debug!(
        "Created HTTPS client config with {} trusted roots (including httpjail CA)",
        roots.len()
    );

    rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// Initialize the HTTP client with the httpjail CA certificate
pub fn init_client_with_ca(ca_cert_der: rustls::pki_types::CertificateDer<'static>) {
    HTTPS_CLIENT.get_or_init(|| {
        // Check if we should dangerously disable cert validation (TESTING ONLY!)
        let https = if std::env::var("HTTPJAIL_DANGER_DISABLE_CERT_VALIDATION").is_ok() {
            let config = create_dangerous_client_config();

            hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(config)
                .https_or_http()
                .enable_http1()
                .build()
        } else {
            // Normal path - use webpki roots + httpjail CA
            let config = create_client_config_with_ca(ca_cert_der);
            // Build an HttpConnector with fast IPv6->IPv4 fallback
            let mut http = hyper_util::client::legacy::connect::HttpConnector::new();
            http.enforce_http(false);
            http.set_happy_eyeballs_timeout(Some(Duration::from_millis(250)));
            let https = hyper_rustls::HttpsConnector::from((http, config));
            info!("HTTPS connector initialized with webpki roots and httpjail CA");
            https
        };

        Client::builder(TokioExecutor::new())
            // Keep minimal pooling but with shorter timeouts
            .pool_idle_timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(1)
            .http1_title_case_headers(false)
            .http1_preserve_header_case(true)
            .build(https)
    });
}

/// Get or create the shared HTTP/HTTPS client
pub fn get_client() -> &'static Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    BoxBody<Bytes, HyperError>,
> {
    HTTPS_CLIENT.get_or_init(|| {
        // Fallback initialization if not already initialized with CA
        // This should not happen in normal operation
        warn!("HTTP client accessed before CA initialization, using native roots only");

        let https = HttpsConnectorBuilder::new()
            .with_native_roots()
            .expect("Failed to load native roots")
            .https_or_http()
            .enable_http1()
            .build();

        Client::builder(TokioExecutor::new())
            // Keep minimal pooling but with shorter timeouts
            .pool_idle_timeout(Duration::from_secs(5))
            .pool_max_idle_per_host(1)
            .http1_title_case_headers(false)
            .http1_preserve_header_case(true)
            .build(https)
    })
}

/// Try to bind to an available port in the given range (up to 16 attempts)
async fn bind_to_available_port(start: u16, end: u16, bind_addr: [u8; 4]) -> Result<TcpListener> {
    let mut rng = rand::thread_rng();

    for _ in 0..16 {
        let port = rng.gen_range(start..=end);
        match TcpListener::bind(SocketAddr::from((bind_addr, port))).await {
            Ok(listener) => {
                debug!("Successfully bound to port {}", port);
                return Ok(listener);
            }
            Err(_) => continue,
        }
    }
    anyhow::bail!(
        "No available port found after 16 attempts in range {}-{}",
        start,
        end
    )
}

pub struct ProxyServer {
    http_port: Option<u16>,
    https_port: Option<u16>,
    rule_engine: Arc<RuleEngine>,
    cert_manager: Arc<CertificateManager>,
    bind_address: [u8; 4],
}

impl ProxyServer {
    pub fn new(
        http_port: Option<u16>,
        https_port: Option<u16>,
        rule_engine: RuleEngine,
        bind_address: Option<[u8; 4]>,
    ) -> Self {
        let cert_manager = CertificateManager::new().expect("Failed to create certificate manager");

        // Initialize the HTTP client with our CA certificate
        let ca_cert_der = cert_manager.get_ca_cert_der();
        init_client_with_ca(ca_cert_der);

        ProxyServer {
            http_port,
            https_port,
            rule_engine: Arc::new(rule_engine),
            cert_manager: Arc::new(cert_manager),
            bind_address: bind_address.unwrap_or([127, 0, 0, 1]),
        }
    }

    pub async fn start(&mut self) -> Result<(u16, u16)> {
        // Start HTTP proxy
        let http_listener = if let Some(port) = self.http_port {
            // If port is 0, let OS choose any available port
            // Otherwise bind to the specified port
            TcpListener::bind(SocketAddr::from((self.bind_address, port))).await?
        } else {
            // No port specified, find available port in 8000-8999 range
            let listener = bind_to_available_port(8000, 8999, self.bind_address).await?;
            self.http_port = Some(listener.local_addr()?.port());
            listener
        };

        let http_port = http_listener.local_addr()?.port();
        info!("Starting HTTP proxy on port {}", http_port);

        let rule_engine = Arc::clone(&self.rule_engine);
        let cert_manager = Arc::clone(&self.cert_manager);

        // Start HTTP proxy task
        tokio::spawn(async move {
            loop {
                match http_listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!("New HTTP connection from {}", addr);
                        let rule_engine = Arc::clone(&rule_engine);
                        let cert_manager = Arc::clone(&cert_manager);

                        tokio::spawn(async move {
                            if let Err(e) =
                                handle_http_connection(stream, rule_engine, cert_manager).await
                            {
                                error!("Error handling HTTP connection: {:?}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept HTTP connection: {}", e);
                    }
                }
            }
        });

        // IPv6-specific listener not required; IPv4 listener suffices for jail routing

        // Start HTTPS proxy
        let https_listener = if let Some(port) = self.https_port {
            // If port is 0, let OS choose any available port
            // Otherwise bind to the specified port
            TcpListener::bind(SocketAddr::from((self.bind_address, port))).await?
        } else {
            // No port specified, find available port in 8000-8999 range
            let listener = bind_to_available_port(8000, 8999, self.bind_address).await?;
            self.https_port = Some(listener.local_addr()?.port());
            listener
        };

        let https_port = https_listener.local_addr()?.port();
        info!("Starting HTTPS proxy on port {}", https_port);

        let rule_engine = Arc::clone(&self.rule_engine);
        let cert_manager = Arc::clone(&self.cert_manager);

        // Start HTTPS proxy task
        tokio::spawn(async move {
            loop {
                match https_listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!("New HTTPS connection from {}", addr);
                        let rule_engine = Arc::clone(&rule_engine);
                        let cert_manager = Arc::clone(&cert_manager);

                        tokio::spawn(async move {
                            if let Err(e) =
                                handle_https_connection(stream, rule_engine, cert_manager).await
                            {
                                error!("Error handling HTTPS connection: {:?}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept HTTPS connection: {}", e);
                    }
                }
            }
        });

        // IPv6-specific listener not required; IPv4 listener suffices for jail routing

        Ok((http_port, https_port))
    }

    /// Get the CA certificate for client trust
    #[allow(dead_code)]
    pub fn get_ca_cert_pem(&self) -> String {
        self.cert_manager.get_ca_cert_pem()
    }
}

async fn handle_http_connection(
    stream: TcpStream,
    rule_engine: Arc<RuleEngine>,
    cert_manager: Arc<CertificateManager>,
) -> Result<()> {
    let io = TokioIo::new(stream);
    let service = service_fn(move |req| {
        handle_http_request(req, Arc::clone(&rule_engine), Arc::clone(&cert_manager))
    });

    http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(false)
        .serve_connection(io, service)
        .await?;

    Ok(())
}

async fn handle_https_connection(
    stream: TcpStream,
    rule_engine: Arc<RuleEngine>,
    cert_manager: Arc<CertificateManager>,
) -> Result<()> {
    // Delegate to the TLS-specific module
    crate::proxy_tls::handle_https_connection(stream, rule_engine, cert_manager).await
}

pub async fn handle_http_request(
    req: Request<Incoming>,
    rule_engine: Arc<RuleEngine>,
    _cert_manager: Arc<CertificateManager>,
) -> Result<Response<BoxBody<Bytes, HyperError>>, std::convert::Infallible> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    // Check if the URI already contains the full URL (proxy request)
    let full_url = if uri.scheme().is_some() && uri.authority().is_some() {
        // This is a proxy request with absolute URL (e.g., GET http://example.com/ HTTP/1.1)
        uri.to_string()
    } else {
        // This is a regular request, build the full URL from headers
        let host = headers
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("unknown");

        let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
        format!("http://{}{}", host, path)
    };

    info!("Proxying HTTP request: {} {}", method, full_url);

    // Evaluate rules with method
    match rule_engine.evaluate(method, &full_url) {
        Action::Allow => {
            debug!("Request allowed: {}", full_url);
            match proxy_request(req, &full_url).await {
                Ok(resp) => Ok(resp),
                Err(e) => {
                    error!("Proxy error: {}", e);
                    create_error_response(StatusCode::BAD_GATEWAY, "Proxy error")
                }
            }
        }
        Action::Deny => {
            warn!("Request denied: {}", full_url);
            create_forbidden_response()
        }
    }
}

async fn proxy_request(
    req: Request<Incoming>,
    full_url: &str,
) -> Result<Response<BoxBody<Bytes, HyperError>>> {
    // Parse the target URL
    let target_uri = full_url.parse::<Uri>()?;

    // Prepare request for upstream
    let new_req = prepare_upstream_request(req, target_uri);

    // Use the shared HTTP/HTTPS client
    let client = get_client();

    // Forward the request - no timeout to support long-running connections
    debug!("Sending HTTP request to upstream server: {}", full_url);
    let start = Instant::now();
    let resp = match client.request(new_req).await {
        Ok(r) => {
            let elapsed = start.elapsed();
            if elapsed > Duration::from_secs(2) {
                warn!("HTTP request took {}ms: {}", elapsed.as_millis(), full_url);
            } else {
                debug!("HTTP request completed in {}ms", elapsed.as_millis());
            }
            r
        }
        Err(e) => {
            let elapsed = start.elapsed();
            error!(
                "Failed to forward HTTP request after {}ms: {}",
                elapsed.as_millis(),
                e
            );
            return Err(e.into());
        }
    };

    debug!(
        "Received HTTP response from upstream server: {:?}",
        resp.status()
    );

    // Convert the response body to BoxBody for uniform type
    let (mut parts, body) = resp.into_parts();

    // Add HTTPJAIL header to indicate this response went through our proxy
    parts
        .headers
        .insert(HTTPJAIL_HEADER, HTTPJAIL_HEADER_VALUE.parse().unwrap());

    let boxed_body = body.boxed();

    Ok(Response::from_parts(parts, boxed_body))
}

/// Create a 403 Forbidden error response
pub fn create_forbidden_response()
-> Result<Response<BoxBody<Bytes, HyperError>>, std::convert::Infallible> {
    create_error_response(StatusCode::FORBIDDEN, BLOCKED_MESSAGE)
}

pub fn create_error_response(
    status: StatusCode,
    message: &str,
) -> Result<Response<BoxBody<Bytes, HyperError>>, std::convert::Infallible> {
    let body = Full::new(Bytes::from(message.to_string()))
        .map_err(|never| match never {})
        .boxed();

    Ok(Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .header("Content-Length", message.len().to_string())
        .header(HTTPJAIL_HEADER, HTTPJAIL_HEADER_VALUE)
        .body(body)
        .unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Rule;

    #[tokio::test]
    async fn test_proxy_server_creation() {
        let rules = vec![
            Rule::new(Action::Allow, r"github\.com").unwrap(),
            Rule::new(Action::Deny, r".*").unwrap(),
        ];

        let rule_engine = RuleEngine::new(rules, None);
        let proxy = ProxyServer::new(Some(8080), Some(8443), rule_engine, None);

        assert_eq!(proxy.http_port, Some(8080));
        assert_eq!(proxy.https_port, Some(8443));
    }

    #[tokio::test]
    async fn test_proxy_server_auto_port() {
        let rules = vec![Rule::new(Action::Allow, r".*").unwrap()];

        let rule_engine = RuleEngine::new(rules, None);
        let mut proxy = ProxyServer::new(None, None, rule_engine, None);

        let (http_port, https_port) = proxy.start().await.unwrap();

        assert!((8000..=8999).contains(&http_port));
        assert!((8000..=8999).contains(&https_port));
        assert_ne!(http_port, https_port);
    }
}
