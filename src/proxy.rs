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

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

#[cfg(target_os = "linux")]
use socket2::{Domain, Protocol, Socket, Type};

use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

pub const HTTPJAIL_HEADER: &str = "HTTPJAIL";
pub const HTTPJAIL_HEADER_VALUE: &str = "true";
pub const BLOCKED_MESSAGE: &str = "Request blocked by httpjail";

/// Create a raw HTTP/1.1 403 Forbidden response for CONNECT tunnels
pub fn create_connect_403_response() -> &'static [u8] {
    b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 27\r\n\r\nRequest blocked by httpjail"
}

/// Create a raw HTTP/1.1 403 Forbidden response for CONNECT tunnels with context
pub fn create_connect_403_response_with_context(context: Option<String>) -> Vec<u8> {
    let message = if let Some(ctx) = context {
        format!("{}\n{}", BLOCKED_MESSAGE, ctx)
    } else {
        BLOCKED_MESSAGE.to_string()
    };

    let response = format!(
        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
        message.len(),
        message
    );
    response.into_bytes()
}

// Use the limited body module for request size limiting
use crate::limited_body::LimitedBody;

/// Result of applying byte limit check to a request
pub enum ByteLimitResult {
    /// Request is within limit (or no Content-Length), proceed with wrapped body
    WithinLimit(Box<Request<BoxBody<Bytes, HyperError>>>),
    /// Request exceeds limit based on Content-Length header
    ExceedsLimit { content_length: u64, max_bytes: u64 },
}

/// Applies a byte limit to an outgoing request by wrapping its body.
///
/// This function first checks the Content-Length header as a heuristic to detect
/// requests that would exceed the limit. If Content-Length indicates the request
/// is oversized, it returns `ByteLimitResult::ExceedsLimit` so the caller can
/// reject the request with a 413 error. This prevents the request from hanging
/// and provides immediate feedback to the client.
///
/// If no Content-Length is present or the request is within limits, the body is
/// wrapped in a `LimitedBody` that enforces truncation as a fallback.
///
/// # Arguments
///
/// * `req` - The request to limit (already boxed)
/// * `max_bytes` - Maximum total bytes for the request (headers + body)
///
/// # Returns
///
/// `ByteLimitResult` indicating whether to proceed or reject the request
pub fn apply_request_byte_limit(
    req: Request<BoxBody<Bytes, HyperError>>,
    max_bytes: u64,
) -> ByteLimitResult {
    let (parts, body) = req.into_parts();

    // Calculate request header size to subtract from max_tx_bytes
    // Request line: "GET /path HTTP/1.1\r\n"
    let method_str = parts.method.as_str();
    let path_str = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let request_line_size = format!("{} {} HTTP/1.1\r\n", method_str, path_str).len() as u64;

    // Headers: each header is "name: value\r\n"
    let headers_size: u64 = parts
        .headers
        .iter()
        .map(|(name, value)| name.as_str().len() as u64 + 2 + value.len() as u64 + 2)
        .sum();

    // Final "\r\n" separator between headers and body
    let total_header_size = request_line_size + headers_size + 2;

    // Check Content-Length as a heuristic to reject oversized requests early
    // This both provides convenience (immediate error) and prevents hangs
    if let Some(content_length) = parts
        .headers
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
    {
        let total_size = total_header_size + content_length;
        if total_size > max_bytes {
            debug!(
                content_length = content_length,
                header_size = total_header_size,
                total_size = total_size,
                max_bytes = max_bytes,
                "Request exceeds byte limit based on Content-Length"
            );
            return ByteLimitResult::ExceedsLimit {
                content_length,
                max_bytes,
            };
        }
    }

    // Subtract header size from total limit to get body limit
    let body_limit = max_bytes.saturating_sub(total_header_size);

    debug!(
        max_tx_bytes = max_bytes,
        header_size = total_header_size,
        body_limit = body_limit,
        "Applying request byte limit"
    );

    let limited_body = LimitedBody::new(body, body_limit);
    ByteLimitResult::WithinLimit(Box::new(Request::from_parts(
        parts,
        BodyExt::boxed(limited_body),
    )))
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
    parts.uri = target_uri.clone();

    // Remove proxy-specific headers only
    // Don't remove connection-related headers as the client will handle them
    parts.headers.remove("proxy-connection");
    parts.headers.remove("proxy-authorization");
    parts.headers.remove("proxy-authenticate");

    // SECURITY: Ensure the Host header matches the URI to prevent routing bypasses (Issue #57)
    // This prevents attacks where an attacker sends a request to one domain but sets
    // the Host header to another domain, potentially bypassing security controls in
    // CDNs like CloudFlare that route based on the Host header.
    if let Some(authority) = target_uri.authority() {
        debug!(
            "Setting Host header to match URI authority: {}",
            authority.as_str()
        );
        parts.headers.insert(
            hyper::header::HOST,
            hyper::header::HeaderValue::from_str(authority.as_str())
                .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("unknown")),
        );
    }

    // TODO: Future improvement - Use the type system to ensure security guarantees
    // We should eventually refactor this to use types that guarantee all request
    // information passed to upstream has been validated by the RuleEngine.
    // For example, we could have a `ValidatedRequest` type that can only be
    // constructed after passing through rule evaluation, making it impossible
    // to accidentally forward unvalidated or modified headers to the upstream.

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
async fn bind_to_available_port(start: u16, end: u16, ip: std::net::IpAddr) -> Result<TcpListener> {
    let mut rng = rand::thread_rng();

    for _ in 0..16 {
        let port = rng.gen_range(start..=end);
        let addr = std::net::SocketAddr::new(ip, port);
        match bind_listener(addr).await {
            Ok(listener) => {
                debug!("Successfully bound to {}:{}", ip, port);
                return Ok(listener);
            }
            Err(_) => continue,
        }
    }
    anyhow::bail!(
        "No available port found after 16 attempts in range {}-{} on {}",
        start,
        end,
        ip
    )
}

async fn bind_listener(addr: std::net::SocketAddr) -> Result<TcpListener> {
    #[cfg(target_os = "linux")]
    {
        // Setup a raw socket to set IP_FREEBIND for specific non-loopback addresses
        let is_specific_non_loopback = match addr.ip() {
            std::net::IpAddr::V4(ip) => {
                ip != Ipv4Addr::new(127, 0, 0, 1) && ip != Ipv4Addr::new(0, 0, 0, 0)
            }
            std::net::IpAddr::V6(ip) => ip != Ipv6Addr::LOCALHOST && ip != Ipv6Addr::UNSPECIFIED,
        };
        if is_specific_non_loopback {
            let domain = match addr {
                std::net::SocketAddr::V4(_) => Domain::IPV4,
                std::net::SocketAddr::V6(_) => Domain::IPV6,
            };
            let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
            // Enabling FREEBIND for non-local address binding before interface configuration
            unsafe {
                let yes: libc::c_int = 1;
                let ret = libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_FREEBIND,
                    &yes as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&yes) as libc::socklen_t,
                );
                if ret != 0 {
                    warn!(
                        "Failed to set IP_FREEBIND on socket: errno={} (continuing)",
                        ret
                    );
                }
            }
            sock.set_reuse_address(true)?;
            sock.set_nonblocking(true)?;
            sock.bind(&addr.into())?;
            sock.listen(128)?;
            let std_listener: std::net::TcpListener = sock.into();
            std_listener.set_nonblocking(true)?;
            return Ok(TcpListener::from_std(std_listener)?);
        }
    }

    TcpListener::bind(addr).await.map_err(Into::into)
}

pub struct ProxyServer {
    http_bind: Option<std::net::SocketAddr>,
    https_bind: Option<std::net::SocketAddr>,
    rule_engine: Arc<RuleEngine>,
    cert_manager: Arc<CertificateManager>,
}

impl ProxyServer {
    pub fn new(
        http_bind: Option<std::net::SocketAddr>,
        https_bind: Option<std::net::SocketAddr>,
        rule_engine: RuleEngine,
    ) -> Self {
        let cert_manager = CertificateManager::new().expect("Failed to create certificate manager");

        // Initialize the HTTP client with our CA certificate
        let ca_cert_der = cert_manager.get_ca_cert_der();
        init_client_with_ca(ca_cert_der);

        ProxyServer {
            http_bind,
            https_bind,
            rule_engine: Arc::new(rule_engine),
            cert_manager: Arc::new(cert_manager),
        }
    }

    pub async fn start(&mut self) -> Result<(u16, u16)> {
        // Bind HTTP listener
        let http_listener = if let Some(addr) = self.http_bind {
            bind_listener(addr).await?
        } else {
            // No address specified, find available port in 8000-8999 range on localhost
            bind_to_available_port(8000, 8999, std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)).await?
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
                                handle_http_connection(stream, rule_engine, cert_manager, addr)
                                    .await
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

        // Bind HTTPS listener
        let https_listener = if let Some(addr) = self.https_bind {
            bind_listener(addr).await?
        } else {
            // No address specified, find available port in 8000-8999 range on localhost
            bind_to_available_port(8000, 8999, std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)).await?
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
                                handle_https_connection(stream, rule_engine, cert_manager, addr)
                                    .await
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
    remote_addr: SocketAddr,
) -> Result<()> {
    let io = TokioIo::new(stream);
    let service = service_fn(move |req| {
        handle_http_request(
            req,
            Arc::clone(&rule_engine),
            Arc::clone(&cert_manager),
            remote_addr,
        )
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
    remote_addr: SocketAddr,
) -> Result<()> {
    // Delegate to the TLS-specific module
    crate::proxy_tls::handle_https_connection(stream, rule_engine, cert_manager, remote_addr).await
}

pub async fn handle_http_request(
    req: Request<Incoming>,
    rule_engine: Arc<RuleEngine>,
    _cert_manager: Arc<CertificateManager>,
    remote_addr: SocketAddr,
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

    debug!(
        "Proxying HTTP request: {} {} from {}",
        method, full_url, remote_addr
    );

    // Evaluate rules with method and requester IP
    let requester_ip = remote_addr.ip().to_string();
    let evaluation = rule_engine
        .evaluate_with_context_and_ip(method, &full_url, &requester_ip)
        .await;
    match evaluation.action {
        Action::Allow => {
            debug!(
                "Request allowed: {} (max_tx_bytes: {:?})",
                full_url, evaluation.max_tx_bytes
            );
            match proxy_request(req, &full_url, evaluation.max_tx_bytes).await {
                Ok(resp) => Ok(resp),
                Err(e) => {
                    error!("Proxy error: {}", e);
                    create_error_response(StatusCode::BAD_GATEWAY, "Proxy error")
                }
            }
        }
        Action::Deny => {
            debug!("Request denied: {}", full_url);
            create_forbidden_response(evaluation.context)
        }
    }
}

async fn proxy_request(
    req: Request<Incoming>,
    full_url: &str,
    max_tx_bytes: Option<u64>,
) -> Result<Response<BoxBody<Bytes, HyperError>>> {
    // Parse the target URL
    let target_uri = full_url.parse::<Uri>()?;

    // Prepare request for upstream
    let prepared_req = prepare_upstream_request(req, target_uri.clone());

    // Apply byte limit to outgoing request if specified, converting to BoxBody
    let new_req = if let Some(max_bytes) = max_tx_bytes {
        match apply_request_byte_limit(prepared_req, max_bytes) {
            ByteLimitResult::WithinLimit(req) => *req,
            ByteLimitResult::ExceedsLimit {
                content_length,
                max_bytes,
            } => {
                // Request exceeds limit based on Content-Length - reject immediately
                let message = format!(
                    "Request body size ({} bytes) exceeds maximum allowed ({} bytes)",
                    content_length, max_bytes
                );
                return Ok(create_error_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    &message,
                )?);
            }
        }
    } else {
        // Convert to BoxBody for consistent types
        let (parts, body) = prepared_req.into_parts();
        Request::from_parts(parts, body.boxed())
    };

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

/// Create a 403 Forbidden error response with optional context
pub fn create_forbidden_response(
    context: Option<String>,
) -> Result<Response<BoxBody<Bytes, HyperError>>, std::convert::Infallible> {
    let message = if let Some(ctx) = context {
        format!("{}\n{}", BLOCKED_MESSAGE, ctx)
    } else {
        BLOCKED_MESSAGE.to_string()
    };
    create_error_response(StatusCode::FORBIDDEN, &message)
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
    use crate::rules::v8_js::V8JsRuleEngine;

    #[tokio::test]
    async fn test_proxy_server_creation() {
        let js = r"/^github\.com$/.test(r.host)";
        let engine = V8JsRuleEngine::new(js.to_string()).unwrap();
        let rule_engine = RuleEngine::from_trait(Box::new(engine), None);

        let http_bind = Some("127.0.0.1:8080".parse().unwrap());
        let https_bind = Some("127.0.0.1:8443".parse().unwrap());
        let proxy = ProxyServer::new(http_bind, https_bind, rule_engine);

        assert_eq!(proxy.http_bind.map(|s| s.port()), Some(8080));
        assert_eq!(proxy.https_bind.map(|s| s.port()), Some(8443));
    }

    #[tokio::test]
    async fn test_proxy_server_auto_port() {
        let engine = V8JsRuleEngine::new("true".to_string()).unwrap();
        let rule_engine = RuleEngine::from_trait(Box::new(engine), None);
        let mut proxy = ProxyServer::new(None, None, rule_engine);

        let (http_port, https_port) = proxy.start().await.unwrap();

        assert!((8000..=8999).contains(&http_port));
        assert!((8000..=8999).contains(&https_port));
        assert_ne!(http_port, https_port);
    }
}
