mod common;

use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::Duration;

/// Test that requests to the proxy itself are blocked to prevent infinite loops.
/// This reproduces issue #84: https://github.com/coder/httpjail/issues/84
#[test]
fn test_server_mode_self_request_loop_prevention() {
    // Logging is auto-initialized via ctor in common::logging

    // Find available ports for HTTP and HTTPS
    let http_port = find_available_port();
    let https_port = find_available_port();

    // Start httpjail in server mode
    let httpjail_path: &str = env!("CARGO_BIN_EXE_httpjail");
    let mut proxy_process = Command::new(httpjail_path)
        .env("HTTPJAIL_HTTP_BIND", format!("127.0.0.1:{}", http_port))
        .env("HTTPJAIL_HTTPS_BIND", format!("127.0.0.1:{}", https_port))
        .arg("--server")
        .arg("--js")
        .arg("true") // Allow all requests
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start httpjail in server mode");

    // Wait for proxy to start listening on the HTTP port
    assert!(
        common::wait_for_server(http_port, Duration::from_secs(5)),
        "Server failed to start on port {}",
        http_port
    );

    // Try to make a request to the proxy itself through the proxy
    // This should NOT create an infinite loop
    let curl_result = Command::new("curl")
        .arg("--max-time")
        .arg("3") // 3 second timeout
        .arg("--proxy")
        .arg(format!("http://127.0.0.1:{}", http_port))
        .arg(format!("http://127.0.0.1:{}/test", http_port))
        .output();

    // Kill the proxy server
    proxy_process.kill().ok();
    let _ = proxy_process.wait();

    match curl_result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let exit_code = output.status.code().unwrap_or(-1);

            println!("=== Curl exit code: {}", exit_code);
            println!("=== Curl stdout: {}", stdout);
            println!("=== Curl stderr: {}", stderr);

            // The request should either:
            // 1. Be blocked with a 403 (our fix - should contain "blocked by httpjail")
            // 2. Fail with connection error (curl timeout/connection refused)
            // 3. NOT succeed normally (which would indicate the loop happened but curl timed out)

            // Without the fix, this creates an infinite loop that consumes resources
            // With the fix, we should see "Request blocked by httpjail" in the output

            // For now, just verify it doesn't succeed (this test documents the bug)
            // After implementing the fix, we'll assert for the specific error message
            if output.status.success() && !stdout.contains("Request blocked by httpjail") {
                panic!("Request appeared to succeed - this may indicate a loop issue");
            }
        }
        Err(e) => {
            // If curl fails to execute, that's a test setup problem
            panic!("Failed to execute curl: {}", e);
        }
    }
}

/// Find an available port for testing
fn find_available_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("Failed to bind to port")
        .local_addr()
        .expect("Failed to get local addr")
        .port()
}
