// Test for max_tx_bytes feature using Hyper HTTP server
// Separated into its own file for clarity

mod common;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;

/// Backend server that counts all incoming request bytes (headers + body)
async fn handle_request(
    req: Request<Incoming>,
    bytes_counter: Arc<Mutex<usize>>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    // Calculate request line size: "POST /upload HTTP/1.1\r\n"
    let method = req.method().as_str();
    let path = req.uri().path();
    let request_line_size = format!("{} {} HTTP/1.1\r\n", method, path).len();

    // Calculate headers size: each header is "name: value\r\n"
    let headers_size: usize = req
        .headers()
        .iter()
        .map(|(name, value)| name.as_str().len() + 2 + value.len() + 2)
        .sum();

    // Final "\r\n" separator between headers and body
    let header_total = request_line_size + headers_size + 2;

    // Read body bytes frame by frame to handle truncated requests
    let body = req.into_body();
    let mut body_size = 0usize;

    // Try to read all body frames with timeout on each frame

    let mut body_pin = std::pin::pin!(body);
    loop {
        match tokio::time::timeout(Duration::from_millis(100), body_pin.as_mut().frame()).await {
            Ok(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    body_size += data.len();
                }
            }
            Ok(Some(Err(_))) => break, // Error reading frame
            Ok(None) => break,         // End of stream
            Err(_) => break,           // Timeout - connection likely closed
        }
    }

    let total_bytes = header_total + body_size;

    // Store the total received bytes
    *bytes_counter.lock().unwrap() = total_bytes;

    // Send response
    Ok(Response::new(Full::new(Bytes::from("OK"))))
}

/// Test helper: common backend server setup
async fn setup_backend() -> (TcpListener, u16, Arc<Mutex<usize>>) {
    let bytes_counter = Arc::new(Mutex::new(0usize));
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind backend server");
    let backend_port = backend_listener.local_addr().unwrap().port();
    (backend_listener, backend_port, bytes_counter)
}

/// Test helper: spawn backend server
fn spawn_backend(
    backend_listener: TcpListener,
    bytes_counter: Arc<Mutex<usize>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Ok((stream, _)) = backend_listener.accept().await {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| {
                let counter = bytes_counter.clone();
                handle_request(req, counter)
            });
            let _ = http1::Builder::new().serve_connection(io, service).await;
        }
    })
}

/// Test helper: start httpjail server
async fn start_httpjail(js_config: &str, proxy_port: u16) -> std::process::Child {
    let httpjail_path: &str = env!("CARGO_BIN_EXE_httpjail");

    let mut httpjail = Command::new(httpjail_path)
        .arg("--server")
        .arg("--js")
        .arg(js_config)
        .env("HTTPJAIL_HTTP_BIND", proxy_port.to_string())
        .env("HTTPJAIL_SKIP_KEYCHAIN_INSTALL", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start httpjail server");

    // Wait for httpjail to start listening
    let mut connected = false;
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(100)).await;

        if let Ok(Some(status)) = httpjail.try_wait() {
            let mut stderr = httpjail.stderr.take().unwrap();
            let mut stderr_content = String::new();
            let _ = std::io::Read::read_to_string(&mut stderr, &mut stderr_content);
            panic!(
                "httpjail server exited early with status: {}\nStderr: {}",
                status, stderr_content
            );
        }

        if tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .is_ok()
        {
            connected = true;
            break;
        }
    }

    if !connected {
        let _ = httpjail.kill();
        panic!(
            "httpjail server did not start listening on port {} within 1 second",
            proxy_port
        );
    }

    httpjail
}

#[tokio::test]
async fn test_max_tx_bytes_truncates_without_content_length() {
    let (backend_listener, backend_port, bytes_counter) = setup_backend().await;
    let backend_handle = spawn_backend(backend_listener, bytes_counter.clone());

    tokio::time::sleep(Duration::from_millis(100)).await;

    let proxy_port = 18080u16;
    let mut httpjail = start_httpjail("({allow: {max_tx_bytes: 1024}})", proxy_port).await;

    // Send POST request with large body (5KB) through proxy WITHOUT Content-Length
    // This tests the LimitedBody truncation path
    let large_body = "X".repeat(5000);
    let target_url = format!("http://127.0.0.1:{}/upload", backend_port);

    // Build request without Content-Length header (chunked encoding)
    let req = Request::builder()
        .method("POST")
        .uri(&target_url)
        .header("Host", format!("127.0.0.1:{}", backend_port))
        .header("Transfer-Encoding", "chunked")
        .body(Full::new(Bytes::from(large_body)))
        .unwrap();

    // Send request through proxy by connecting to proxy address
    // Note: For this test we need to manually connect to the proxy
    let proxy_stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .expect("Failed to connect to proxy");

    let io = TokioIo::new(proxy_stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();

    // Spawn connection handler
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // Send the request with timeout
    let response = tokio::time::timeout(Duration::from_secs(1), sender.send_request(req)).await;

    // Kill httpjail server
    let _ = httpjail.kill();
    let _ = httpjail.wait();

    // Wait for backend to finish (with tight timeout)
    let _ = tokio::time::timeout(Duration::from_millis(500), backend_handle).await;

    // Verify the response succeeded (proxy allowed it)
    assert!(
        response.is_ok(),
        "Request should not timeout (got: {:?})",
        response
    );
    let inner_response = response.unwrap();
    assert!(
        inner_response.is_ok(),
        "Request should succeed through proxy (got: {:?})",
        inner_response
    );

    let bytes_received = *bytes_counter.lock().unwrap();
    println!("Backend server received: {} bytes", bytes_received);

    // Backend server should have received <= 1024 bytes (including headers + body)
    assert!(
        bytes_received <= 1024,
        "Backend should receive at most 1024 bytes, but received {} bytes",
        bytes_received
    );

    // Backend server should have received some data (not zero)
    assert!(bytes_received > 0, "Backend should have received some data");
}

#[tokio::test]
async fn test_max_tx_bytes_rejects_with_content_length() {
    let (backend_listener, backend_port, bytes_counter) = setup_backend().await;
    let backend_handle = spawn_backend(backend_listener, bytes_counter.clone());

    tokio::time::sleep(Duration::from_millis(100)).await;

    let proxy_port = 18081u16;
    let mut httpjail = start_httpjail("({allow: {max_tx_bytes: 1024}})", proxy_port).await;

    // Send POST request with large body (5KB) WITH Content-Length header
    // This tests the early rejection path based on Content-Length
    let large_body = "X".repeat(5000);
    let target_url = format!("http://127.0.0.1:{}/upload", backend_port);

    let req = Request::builder()
        .method("POST")
        .uri(&target_url)
        .header("Host", format!("127.0.0.1:{}", backend_port))
        .header("Content-Length", large_body.len())
        .body(Full::new(Bytes::from(large_body)))
        .unwrap();

    // Send request through proxy
    let proxy_stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", proxy_port))
        .await
        .expect("Failed to connect to proxy");

    let io = TokioIo::new(proxy_stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.unwrap();

    tokio::spawn(async move {
        let _ = conn.await;
    });

    // Send the request with timeout
    let response = tokio::time::timeout(Duration::from_secs(1), sender.send_request(req))
        .await
        .expect("Request should not timeout")
        .expect("Request should complete");

    // Kill httpjail server
    let _ = httpjail.kill();
    let _ = httpjail.wait();

    // Backend should not have been contacted
    let bytes_received = *bytes_counter.lock().unwrap();
    assert_eq!(
        bytes_received, 0,
        "Backend should not receive any data when Content-Length exceeds limit"
    );

    // Response should be 413 Payload Too Large
    assert_eq!(
        response.status(),
        hyper::StatusCode::PAYLOAD_TOO_LARGE,
        "Should receive 413 Payload Too Large status"
    );

    // Read response body to verify error message
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("Failed to read response body")
        .to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);
    assert!(
        body_str.contains("exceeds maximum allowed"),
        "Error message should indicate size limit exceeded, got: {}",
        body_str
    );

    // Clean up backend
    let _ = tokio::time::timeout(Duration::from_millis(100), backend_handle).await;
}
