use crate::rules::{Action, RuleEngine};
use anyhow::Result;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Uri, Error as HyperError};
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

pub struct ProxyServer {
    http_port: u16,
    https_port: u16,
    rule_engine: Arc<RuleEngine>,
}

impl ProxyServer {
    pub fn new(http_port: u16, https_port: u16, rule_engine: RuleEngine) -> Self {
        ProxyServer {
            http_port,
            https_port,
            rule_engine: Arc::new(rule_engine),
        }
    }

    pub async fn start(&self) -> Result<()> {
        let http_addr = SocketAddr::from(([127, 0, 0, 1], self.http_port));
        let rule_engine = Arc::clone(&self.rule_engine);

        info!("Starting HTTP proxy on {}", http_addr);

        let listener = TcpListener::bind(http_addr).await?;

        // Start accepting connections
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        debug!("New connection from {}", addr);
                        let rule_engine = Arc::clone(&rule_engine);
                        
                        tokio::spawn(async move {
                            let io = TokioIo::new(stream);
                            let service = service_fn(move |req| {
                                handle_request(req, Arc::clone(&rule_engine))
                            });

                            if let Err(err) = http1::Builder::new()
                                .serve_connection(io, service)
                                .await
                            {
                                error!("Error serving connection: {:?}", err);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
        });

        Ok(())
    }
}

async fn handle_request(
    req: Request<Incoming>,
    rule_engine: Arc<RuleEngine>,
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
    
    let path = uri.path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    
    let full_url = format!("{}://{}{}", scheme, host, path);
    
    info!("Proxying request: {} {}", method, full_url);
    
    // Evaluate rules
    match rule_engine.evaluate(&full_url) {
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

// Helper function to create error responses with the same body type
fn create_error_response(
    status: StatusCode,
    message: &str,
) -> Result<Response<BoxBody<Bytes, HyperError>>, std::convert::Infallible> {
    // Create a response with a boxed body
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
        let proxy = ProxyServer::new(8080, 8443, rule_engine);
        
        assert_eq!(proxy.http_port, 8080);
        assert_eq!(proxy.https_port, 8443);
    }
}