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
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rand::Rng;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

/// Try to bind to an available port in the given range (up to 16 attempts)
async fn bind_to_available_port(start: u16, end: u16) -> Result<TcpListener> {
    let mut rng = rand::thread_rng();

    for _ in 0..16 {
        let port = rng.gen_range(start..=end);
        match TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).await {
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
}

impl ProxyServer {
    pub fn new(http_port: Option<u16>, https_port: Option<u16>, rule_engine: RuleEngine) -> Self {
        let cert_manager = CertificateManager::new().expect("Failed to create certificate manager");

        ProxyServer {
            http_port,
            https_port,
            rule_engine: Arc::new(rule_engine),
            cert_manager: Arc::new(cert_manager),
        }
    }

    pub async fn start(&mut self) -> Result<(u16, u16)> {
        // Start HTTP proxy
        let http_listener = if let Some(port) = self.http_port {
            TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).await?
        } else {
            // Find available port in 8000-8999 range
            let listener = bind_to_available_port(8000, 8999).await?;
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

        // Start HTTPS proxy
        let https_listener = if let Some(port) = self.https_port {
            TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).await?
        } else {
            // Find available port in 8000-8999 range
            let listener = bind_to_available_port(8000, 8999).await?;
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

    // Build the full URL for rule evaluation
    let host = headers
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    let scheme = if uri.scheme_str().is_some() {
        uri.scheme_str().unwrap()
    } else {
        "http"
    };

    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    let full_url = format!("{}://{}{}", scheme, host, path);

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
            create_error_response(StatusCode::FORBIDDEN, "Request blocked by httpjail")
        }
    }
}

async fn proxy_request(
    mut req: Request<Incoming>,
    full_url: &str,
) -> Result<Response<BoxBody<Bytes, HyperError>>> {
    // Parse the target URL
    let target_uri = full_url.parse::<Uri>()?;

    // Update the request URI to the target
    *req.uri_mut() = target_uri;

    // Create HTTP client
    let client = Client::builder(TokioExecutor::new()).build_http();

    // Forward the request and stream the response directly
    let resp = client.request(req).await?;

    // Convert the response body to BoxBody for uniform type
    let (parts, body) = resp.into_parts();
    let boxed_body = body.boxed();

    Ok(Response::from_parts(parts, boxed_body))
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

        let rule_engine = RuleEngine::new(rules, false, false);
        let proxy = ProxyServer::new(Some(8080), Some(8443), rule_engine);

        assert_eq!(proxy.http_port, Some(8080));
        assert_eq!(proxy.https_port, Some(8443));
    }

    #[tokio::test]
    async fn test_proxy_server_auto_port() {
        let rules = vec![Rule::new(Action::Allow, r".*").unwrap()];

        let rule_engine = RuleEngine::new(rules, false, false);
        let mut proxy = ProxyServer::new(None, None, rule_engine);

        let (http_port, https_port) = proxy.start().await.unwrap();

        assert!(http_port >= 8000 && http_port <= 8999);
        assert!(https_port >= 8000 && https_port <= 8999);
        assert_ne!(http_port, https_port);
    }
}
