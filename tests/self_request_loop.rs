mod common;

use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::Duration;
use tracing::debug;

/// Test that requests to the proxy itself are blocked to prevent infinite loops (issue #84)
#[tokio::test]
async fn test_server_mode_self_request_loop_prevention() {
    let http_port = find_available_port();
    let https_port = find_available_port();

    let httpjail_path: &str = env!("CARGO_BIN_EXE_httpjail");
    let mut proxy_process = Command::new(httpjail_path)
        .env("HTTPJAIL_HTTP_BIND", format!("127.0.0.1:{}", http_port))
        .env("HTTPJAIL_HTTPS_BIND", format!("127.0.0.1:{}", https_port))
        .arg("--server")
        .arg("--js")
        .arg("true")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start httpjail");

    assert!(
        common::wait_for_server(http_port, Duration::from_secs(5)).await,
        "Server failed to start on port {}",
        http_port
    );

    let output = Command::new("curl")
        .arg("--max-time")
        .arg("3")
        .arg("--proxy")
        .arg(format!("http://127.0.0.1:{}", http_port))
        .arg(format!("http://127.0.0.1:{}/test", http_port))
        .output()
        .expect("Failed to execute curl");

    proxy_process.kill().ok();
    let _ = proxy_process.wait();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    debug!("curl exit code: {}", output.status.code().unwrap_or(-1));
    debug!("curl stdout: {}", stdout);
    debug!("curl stderr: {}", stderr);

    assert!(
        stdout.contains("Loop detected"),
        "Expected loop detection message, got: {}",
        stdout
    );
}

/// Find an available port for testing
fn find_available_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("Failed to bind to port")
        .local_addr()
        .expect("Failed to get local addr")
        .port()
}
