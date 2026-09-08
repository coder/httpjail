/// Common proxy utilities for HTTP and HTTPS.
use crate::dangerous_verifier::create_dangerous_client_config;
use crate::rules::{Action, RuleEngine};
#[allow(unused_imports)]
use crate::tls::CertificateManager;
use crate::upstream::{ProxyConnector, UpstreamProxies};
use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::header::PROXY_AUTHORIZATION;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Error as HyperError, Request, Response, StatusCode, Uri};
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rand::Rng;
use rustls::pki_types::CertificateDer;

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

#[cfg(target_os = "linux")]
use socket2::{Domain, Protocol, Socket, Type};

use std::net::{Ipv4Addr, SocketAddr};

#[cfg(target_os = "linux")]
use std::net::Ipv6Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

pub const HTTPJAIL_HEADER: &str = "HTTPJAIL";
pub const HTTPJAIL_HEADER_VALUE: &str = "true";
pub const BLOCKED_MESSAGE: &str = "Request blocked by httpjail";

/// Header added to outgoing requests to detect loops (Issue #84)
/// Contains comma-separated nonces of all httpjail instances in the proxy chain.
/// If we see our own nonce in an incoming request, we're in a loop.
pub const HTTPJAIL_LOOP_DETECTION_HEADER: &str = "Httpjail-Loop-Prevention";

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

/// Direct (no upstream proxy) upstream client type.
type DirectClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, BoxBody<Bytes, HyperError>>;

/// Upstream client that routes every re-originated request through an upstream
/// (corporate) proxy via a [`ProxyConnector`].
type ProxiedClient =
    Client<hyper_rustls::HttpsConnector<ProxyConnector>, BoxBody<Bytes, HyperError>>;

/// Upstream client: either contacts destinations directly or routes through a
/// configured upstream proxy. Both variants are high-level pooled clients.
pub enum UpstreamClient {
    Direct(DirectClient),
    Proxied {
        client: ProxiedClient,
        proxies: UpstreamProxies,
    },
}

impl UpstreamClient {
    /// Build the upstream client for one [`ProxyServer`]: either contacting
    /// destinations directly, or routing every re-originated request whose
    /// scheme has a configured proxy through that proxy.
    ///
    /// Each `ProxyServer` owns its own client, so the upstream configuration is
    /// exactly what the caller asked for rather than whatever the first
    /// initialization in the process happened to install.
    pub fn new(
        ca_cert_der: CertificateDer<'static>,
        upstream_proxies: Option<UpstreamProxies>,
    ) -> Self {
        // Check if we should dangerously disable cert validation (TESTING ONLY!)
        let dangerous = std::env::var("HTTPJAIL_DANGER_DISABLE_CERT_VALIDATION").is_ok();

        match upstream_proxies {
            None => {
                let https = build_direct_connector(ca_cert_der, dangerous);
                debug!("HTTPS connector initialized with webpki roots and httpjail CA");
                UpstreamClient::Direct(build_pooled_client(https))
            }
            Some(proxies) => {
                // The destination TLS, layered over the CONNECT tunnel by the
                // HttpsConnector, trusts the same roots as the direct client.
                let config = if dangerous {
                    create_dangerous_client_config()
                } else {
                    create_client_config_with_ca(ca_cert_der)
                };
                let connector = ProxyConnector::with_config(proxies.clone());
                let https = hyper_rustls::HttpsConnector::from((connector, config));
                debug!("Upstream client initialized to route through the upstream proxy");
                UpstreamClient::Proxied {
                    client: build_pooled_client(https),
                    proxies,
                }
            }
        }
    }

    /// Forward a prepared request upstream. No timeout is applied here so that
    /// long-running connections (WebSocket, gRPC, ...) keep working.
    pub async fn request(
        &self,
        mut req: Request<BoxBody<Bytes, HyperError>>,
    ) -> Result<Response<Incoming>> {
        match self {
            UpstreamClient::Direct(client) => client.request(req).await.map_err(Into::into),
            UpstreamClient::Proxied { client, proxies } => {
                if let Some(auth) = proxies.http_auth_for_uri(req.uri()) {
                    req.headers_mut().insert(PROXY_AUTHORIZATION, auth);
                }
                client.request(req).await.map_err(Into::into)
            }
        }
    }
}

/// Build a pooled hyper client over the given connector with the shared tuning.
fn build_pooled_client<C>(connector: C) -> Client<C, BoxBody<Bytes, HyperError>>
where
    C: tower_service::Service<Uri> + Clone + Send + Sync + 'static,
    C::Response: hyper_util::client::legacy::connect::Connection
        + hyper::rt::Read
        + hyper::rt::Write
        + Unpin
        + Send
        + 'static,
    C::Future: Send + Unpin + 'static,
    C::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(1)
        .http1_title_case_headers(false)
        .http1_preserve_header_case(true)
        .build(connector)
}

/// Prepare a request for forwarding to upstream server
/// Removes proxy-specific headers and converts body to BoxBody
pub fn prepare_upstream_request(
    req: Request<Incoming>,
    target_uri: Uri,
    loop_nonce: &str,
) -> Request<BoxBody<Bytes, HyperError>> {
    let (mut parts, incoming_body) = req.into_parts();

    // Update the URI
    parts.uri = target_uri.clone();

    // Remove proxy-specific headers only
    // Don't remove connection-related headers as the client will handle them
    parts.headers.remove("proxy-connection");
    parts.headers.remove("proxy-authorization");
    parts.headers.remove("proxy-authenticate");

    // SECURITY: Add our nonce to the loop detection header (Issue #84)
    // HTTP natively supports multiple values for the same header name (via append).
    // This allows chaining multiple httpjail instances while still detecting self-loops.
    // Each instance appends its nonce; if we see our own nonce in an incoming request, it's a loop.
    parts.headers.append(
        HTTPJAIL_LOOP_DETECTION_HEADER,
        hyper::header::HeaderValue::from_str(loop_nonce)
            .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("invalid")),
    );

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

/// Build the direct (no upstream proxy) HTTPS connector: webpki roots plus the
/// httpjail CA, with fast IPv6->IPv4 fallback (or the dangerous no-verification
/// config for testing).
fn build_direct_connector(
    ca_cert_der: CertificateDer<'static>,
    dangerous: bool,
) -> hyper_rustls::HttpsConnector<HttpConnector> {
    if dangerous {
        let config = create_dangerous_client_config();
        HttpsConnectorBuilder::new()
            .with_tls_config(config)
            .https_or_http()
            .enable_http1()
            .build()
    } else {
        let config = create_client_config_with_ca(ca_cert_der);
        // Build an HttpConnector with fast IPv6->IPv4 fallback
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_happy_eyeballs_timeout(Some(Duration::from_millis(250)));
        hyper_rustls::HttpsConnector::from((http, config))
    }
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

/// Context passed to all proxy handlers - reduces argument duplication
#[derive(Clone)]
pub struct ProxyContext {
    pub rule_engine: Arc<RuleEngine>,
    pub cert_manager: Arc<CertificateManager>,
    /// Client used to re-originate allowed requests towards the real
    /// destination, either directly or through an upstream proxy.
    pub upstream_client: Arc<UpstreamClient>,
    /// Unique nonce for this proxy instance, used for loop detection (Issue #84)
    pub loop_nonce: Arc<String>,
}

pub struct ProxyServer {
    http_bind: Option<std::net::SocketAddr>,
    https_bind: Option<std::net::SocketAddr>,
    context: ProxyContext,
}

impl ProxyServer {
    pub fn new(
        http_bind: Option<std::net::SocketAddr>,
        https_bind: Option<std::net::SocketAddr>,
        rule_engine: RuleEngine,
    ) -> Self {
        Self::new_with_upstream_proxies(http_bind, https_bind, rule_engine, None)
    }

    /// Like [`ProxyServer::new`], but routes httpjail's own re-originated
    /// requests through the configured upstream proxies when set.
    pub fn new_with_upstream_proxies(
        http_bind: Option<std::net::SocketAddr>,
        https_bind: Option<std::net::SocketAddr>,
        rule_engine: RuleEngine,
        upstream_proxies: Option<UpstreamProxies>,
    ) -> Self {
        let cert_manager = CertificateManager::new().expect("Failed to create certificate manager");

        // Build this server's upstream client, trusting our own CA
        let upstream_client = UpstreamClient::new(cert_manager.get_ca_cert_der(), upstream_proxies);

        // Generate a unique nonce for loop detection (Issue #84)
        // Use 16 random hex characters for a reasonably short but collision-resistant ID
        let loop_nonce = {
            let random_u64: u64 = rand::random();
            format!("{:x}", random_u64)
        };

        let context = ProxyContext {
            rule_engine: Arc::new(rule_engine),
            cert_manager: Arc::new(cert_manager),
            upstream_client: Arc::new(upstream_client),
            loop_nonce: Arc::new(loop_nonce),
        };

        ProxyServer {
            http_bind,
            https_bind,
            context,
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

        // Start HTTP proxy task
        spawn_listener_task(
            http_listener,
            self.context.clone(),
            "HTTP",
            handle_http_connection,
        );

        // Bind HTTPS listener
        let https_listener = if let Some(addr) = self.https_bind {
            bind_listener(addr).await?
        } else {
            // No address specified, find available port in 8000-8999 range on localhost
            bind_to_available_port(8000, 8999, std::net::IpAddr::V4(Ipv4Addr::LOCALHOST)).await?
        };

        let https_port = https_listener.local_addr()?.port();
        info!("Starting HTTPS proxy on port {}", https_port);

        // Start HTTPS proxy task
        spawn_listener_task(
            https_listener,
            self.context.clone(),
            "HTTPS",
            handle_https_connection,
        );

        Ok((http_port, https_port))
    }

    /// Get the CA certificate for client trust
    #[allow(dead_code)]
    pub fn get_ca_cert_pem(&self) -> String {
        self.context.cert_manager.get_ca_cert_pem()
    }
}

/// Generic listener task spawner to avoid code duplication between HTTP and HTTPS
fn spawn_listener_task<F, Fut>(
    listener: TcpListener,
    context: ProxyContext,
    protocol: &'static str,
    handler: F,
) where
    F: Fn(TcpStream, ProxyContext, SocketAddr) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<()>> + Send + 'static,
{
    let handler = Arc::new(handler);
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    debug!("New {} connection from {}", protocol, addr);
                    let context = context.clone();
                    let handler = Arc::clone(&handler);

                    tokio::spawn(async move {
                        if let Err(e) = handler(stream, context, addr).await {
                            error!("Error handling {} connection: {:?}", protocol, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept {} connection: {}", protocol, e);
                }
            }
        }
    });
}

async fn handle_http_connection(
    stream: TcpStream,
    context: ProxyContext,
    remote_addr: SocketAddr,
) -> Result<()> {
    let io = TokioIo::new(stream);
    let service = service_fn(move |req| handle_http_request(req, context.clone(), remote_addr));

    http1::Builder::new()
        .preserve_header_case(true)
        .title_case_headers(false)
        .serve_connection(io, service)
        .await?;

    Ok(())
}

async fn handle_https_connection(
    stream: TcpStream,
    context: ProxyContext,
    remote_addr: SocketAddr,
) -> Result<()> {
    // Delegate to the TLS-specific module
    crate::proxy_tls::handle_https_connection(stream, context, remote_addr).await
}

pub async fn handle_http_request(
    req: Request<Incoming>,
    context: ProxyContext,
    remote_addr: SocketAddr,
) -> Result<Response<BoxBody<Bytes, HyperError>>, std::convert::Infallible> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    // SECURITY: Check for loop detection header (Issue #84)
    // HTTP supports multiple values for the same header name.
    // Each httpjail instance adds its nonce; if we see our own, it's a loop.
    let our_nonce = context.loop_nonce.as_str();
    for value in headers.get_all(HTTPJAIL_LOOP_DETECTION_HEADER).iter() {
        if let Ok(nonce) = value.to_str() {
            if nonce == our_nonce {
                debug!(
                    "Loop detected: our nonce '{}' found in request to {}",
                    nonce, uri
                );
                return create_forbidden_response(Some(
                    "Loop detected: request already processed by this httpjail instance"
                        .to_string(),
                ));
            }
        }
    }

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
    let evaluation = context
        .rule_engine
        .evaluate_with_context_and_ip(method, &full_url, &requester_ip)
        .await;
    match evaluation.action {
        Action::Allow => {
            debug!(
                "Request allowed: {} (max_tx_bytes: {:?})",
                full_url, evaluation.max_tx_bytes
            );
            match proxy_request(
                req,
                &full_url,
                evaluation.max_tx_bytes,
                &context.loop_nonce,
                &context.upstream_client,
            )
            .await
            {
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
    loop_nonce: &str,
    client: &UpstreamClient,
) -> Result<Response<BoxBody<Bytes, HyperError>>> {
    // Parse the target URL
    let target_uri = full_url.parse::<Uri>()?;

    // Prepare request for upstream
    let prepared_req = prepare_upstream_request(req, target_uri.clone(), loop_nonce);

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
            return Err(e);
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

    /// Each server must honor the upstream configuration it was constructed
    /// with. Before the client moved onto ProxyContext, whichever server ran
    /// first installed a process-global client and the second silently inherited
    /// it, so a proxied server created after a direct one lost its proxy.
    #[tokio::test]
    async fn upstream_client_is_per_server() {
        let rule_engine = || {
            let engine = V8JsRuleEngine::new("true".to_string()).unwrap();
            RuleEngine::from_trait(Box::new(engine), None)
        };

        let direct = ProxyServer::new(None, None, rule_engine());
        let proxies =
            UpstreamProxies::all(crate::upstream::UpstreamProxy::parse("proxy:3128").unwrap());
        let proxied =
            ProxyServer::new_with_upstream_proxies(None, None, rule_engine(), Some(proxies));

        assert!(matches!(
            direct.context.upstream_client.as_ref(),
            UpstreamClient::Direct(_)
        ));
        assert!(matches!(
            proxied.context.upstream_client.as_ref(),
            UpstreamClient::Proxied { .. }
        ));
    }

    /// The whole HTTPS path in one go: the connector opens a CONNECT tunnel
    /// through the proxy, the HttpsConnector layers the destination TLS on top of
    /// it, and the request reaches the origin server.
    ///
    /// Each half is covered on its own elsewhere; nothing else checks that they
    /// compose. Skipping the CONNECT, tunneling to the wrong authority, or
    /// failing to run the destination handshake over the tunnel all fail here.
    ///
    /// Note that the origin-form assertion below records the wire shape rather
    /// than guarding the `proxied` flag: hyper-util's `absolute_form()` falls
    /// back to origin-form for HTTPS URIs on its own, so marking the tunnel
    /// proxied would not change what the origin sees.
    #[tokio::test]
    async fn https_destination_through_connect_tunnel_reaches_origin() {
        use http_body_util::Empty;
        use hyper::server::conn::http1 as server_http1;
        use hyper::service::service_fn;
        use std::sync::Mutex;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        const ORIGIN_HOST: &str = "target.test";
        const BODY: &str = "through-connect-ok";

        // Origin: a real TLS server with its own self-signed certificate, so the
        // handshake has to succeed over the tunnel for the request to arrive.
        let cert = rcgen::generate_simple_self_signed(vec![ORIGIN_HOST.to_string()]).unwrap();
        let tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_addr = origin_listener.local_addr().unwrap();
        let seen_uri = Arc::new(Mutex::new(String::new()));
        let origin_seen_uri = Arc::clone(&seen_uri);
        let origin = tokio::spawn(async move {
            let (sock, _) = origin_listener.accept().await.unwrap();
            let tls = acceptor.accept(sock).await.unwrap();
            let service = service_fn(move |req: Request<Incoming>| {
                let seen = Arc::clone(&origin_seen_uri);
                async move {
                    *seen.lock().unwrap() = req.uri().to_string();
                    Ok::<_, HyperError>(
                        Response::builder()
                            // Close after one response so the tunnel copy ends.
                            .header(hyper::header::CONNECTION, "close")
                            .body(Full::new(Bytes::from(BODY)))
                            .unwrap(),
                    )
                }
            });
            let _ = server_http1::Builder::new()
                .serve_connection(TokioIo::new(tls), service)
                .await;
        });

        // Proxy: answer CONNECT, then splice the connection to the origin.
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();
        let proxy = tokio::spawn(async move {
            let (mut client, _) = proxy_listener.accept().await.unwrap();
            let mut head = Vec::new();
            let mut byte = [0u8; 1];
            while client.read(&mut byte).await.unwrap() != 0 {
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let mut origin = TcpStream::connect(origin_addr).await.unwrap();
            client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            client.flush().await.unwrap();
            let _ = tokio::io::copy_bidirectional(&mut client, &mut origin).await;
            String::from_utf8_lossy(&head).into_owned()
        });

        let upstream =
            crate::upstream::UpstreamProxy::parse(&format!("http://{proxy_addr}")).unwrap();
        let proxies = UpstreamProxies::all(upstream);
        let connector = ProxyConnector::with_config(proxies.clone());
        // The HttpsConnector is the point of the test: it must be able to run the
        // destination handshake on top of what the connector returns.
        let https =
            hyper_rustls::HttpsConnector::from((connector, create_dangerous_client_config()));
        let client = UpstreamClient::Proxied {
            client: build_pooled_client(https),
            proxies,
        };

        let body = Empty::<Bytes>::new()
            .map_err(|never| match never {})
            .boxed();
        let req = Request::builder()
            .uri(format!(
                "https://{ORIGIN_HOST}:{}/through-connect",
                origin_addr.port()
            ))
            .body(body)
            .unwrap();

        // One bound over the whole exchange, not just the request: a regression
        // that stalls after the response headers, or leaves the tunnel copy
        // running, would otherwise hang here instead of failing.
        let exchange = async move {
            let resp = client.request(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let got = resp.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(got, Bytes::from(BODY));

            // Let the pooled connection go so the tunnel copy sees EOF.
            drop(client);
            let connect_head = proxy.await.unwrap();
            origin.await.unwrap();
            connect_head
        };
        let connect_head = tokio::time::timeout(Duration::from_secs(3), exchange)
            .await
            .expect("timed out waiting for the tunneled request to complete");

        // The proxy is dialed by address but must be asked for the destination.
        assert!(
            connect_head.starts_with(&format!(
                "CONNECT {ORIGIN_HOST}:{} HTTP/1.1\r\n",
                origin_addr.port()
            )),
            "unexpected CONNECT request: {connect_head}"
        );
        // Reaching the origin at all proves the tunnel and the destination
        // handshake worked; the path confirms the request was not rewritten on
        // the way through.
        assert_eq!(seen_uri.lock().unwrap().as_str(), "/through-connect");
    }

    /// A plain-HTTP request routed through an upstream proxy must be forwarded in
    /// absolute-form with the configured `Proxy-Authorization` header.
    #[tokio::test]
    async fn proxied_http_uses_absolute_form_with_auth() {
        use http_body_util::Empty;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // Fake upstream proxy: capture the forwarded request, then reply 200.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            while sock.read(&mut byte).await.unwrap() != 0 {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            sock.flush().await.unwrap();
            String::from_utf8_lossy(&buf).into_owned()
        });

        let proxy =
            crate::upstream::UpstreamProxy::parse(&format!("http://user:pass@{}", addr)).unwrap();
        let proxies = UpstreamProxies::all(proxy);
        let connector = ProxyConnector::with_config(proxies.clone());
        let https =
            hyper_rustls::HttpsConnector::from((connector, create_dangerous_client_config()));
        let client = UpstreamClient::Proxied {
            client: build_pooled_client(https),
            proxies,
        };

        let body = Empty::<Bytes>::new()
            .map_err(|never| match never {})
            .boxed();
        let req = Request::builder()
            .uri("http://target.example/path")
            .body(body)
            .unwrap();
        let resp = client.request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let forwarded = server.await.unwrap();
        assert!(
            forwarded.starts_with("GET http://target.example/path HTTP/1.1\r\n"),
            "expected absolute-form request line, got: {forwarded}"
        );
        // Header names are case-insensitive; base64("user:pass") == dXNlcjpwYXNz
        assert!(
            forwarded.lines().any(|l| {
                l.to_ascii_lowercase().starts_with("proxy-authorization:")
                    && l.contains("Basic dXNlcjpwYXNz")
            }),
            "missing proxy auth, got: {forwarded}"
        );
    }
}
