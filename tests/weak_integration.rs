mod common;

use common::{HttpjailCommand, test_https_allow, test_https_blocking};
use serial_test::serial;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::thread;
use std::time::Duration;

#[test]
fn test_weak_mode_blocks_https_correctly() {
    // Use the common test function with weak mode (no sudo)
    test_https_blocking(false);
}

#[test]
fn test_weak_mode_allows_https_with_allow_rule() {
    // Use the common test function with weak mode (no sudo)
    test_https_allow(false);
}

#[test]
fn test_weak_mode_blocks_http_correctly() {
    // Test that HTTP to ifconfig.me is blocked in weak mode
    let result = HttpjailCommand::new()
        .weak()
        .js("false")
        .verbose(2)
        .command(vec!["curl", "--max-time", "3", "http://ifconfig.me"])
        .execute();

    match result {
        Ok((exit_code, stdout, stderr)) => {
            println!("Exit code: {}", exit_code);
            println!("Stdout: {}", stdout);
            println!("Stderr: {}", stderr);

            // HTTP blocking returns a 403 response, so curl succeeds but with forbidden message
            // Should contain the blocked message
            assert!(
                stdout.contains("Request blocked by httpjail") || exit_code != 0,
                "Expected request to be blocked, but got normal response"
            );

            // Should not contain actual response (IP address)
            assert!(std::net::Ipv4Addr::from_str(stdout.trim()).is_err());
        }
        Err(e) => {
            panic!("Failed to execute httpjail: {}", e);
        }
    }
}

// MacOS does not have `timeout` by default. Other options here could be `gtimeout`
// if coreutils is install or a simple perl script which mac has by default (these suggestions
// are courtesy of claude).
#[cfg(not(target_os = "macos"))]
#[test]
fn test_weak_mode_timeout_works() {
    // Test that the timeout mechanism works correctly (should complete in ~2 seconds)
    // This test uses a command that would normally hang
    let result = HttpjailCommand::new()
        .weak()
        .js("true")
        .verbose(2)
        .timeout(2) // Set 2-second timeout for fast test completion
        .command(vec!["bash", "-c", "sleep 3"]) // Sleep longer than timeout
        .execute();

    match result {
        Ok((exit_code, _stdout, _stderr)) => {
            // Should timeout with exit code 124
            assert_eq!(
                exit_code, 124,
                "Expected timeout exit code 124, got: {}",
                exit_code
            );
        }
        Err(e) => {
            panic!("Failed to execute httpjail: {}", e);
        }
    }
}

#[test]
fn test_weak_mode_allows_localhost() {
    // Test that localhost connections work (for the proxy itself)
    let result = HttpjailCommand::new()
        .weak()
        .js("r.host === 'localhost' || r.host === '127.0.0.1'")
        .verbose(1)
        .command(vec!["curl", "--max-time", "3", "http://localhost:80"])
        // may fail but should be allowed by rules
        .execute();

    match result {
        Ok((exit_code, _stdout, stderr)) => {
            println!("Exit code: {}", exit_code);
            println!("Stderr: {}", stderr);

            // This should fail with connection refused (no server on port 80)
            // but NOT be blocked by the proxy
            // Exit code 7 = Failed to connect (expected - no server)
            // Exit code 28 = Timeout (connection attempt timed out - also valid)
            // Exit code 52 = Empty reply from server (proxy allowed but no backend)
            assert!(
                exit_code == 7 || exit_code == 28 || exit_code == 52,
                "Expected connection refused (7), timeout (28), or empty reply (52), got: {}",
                exit_code
            );

            // The error should be about connection, not forbidden
            assert!(
                !stderr.contains("403") && !stderr.contains("Forbidden"),
                "Request should not be forbidden by proxy"
            );
        }
        Err(e) => {
            panic!("Failed to execute httpjail: {}", e);
        }
    }
}

#[test]
fn test_weak_mode_appends_no_proxy() {
    // Ensure existing NO_PROXY values are preserved and localhost entries appended
    let result = HttpjailCommand::new()
        .weak()
        .js("true")
        .env("NO_PROXY", "example.com")
        .verbose(2)
        .command(vec!["env"])
        .execute();

    match result {
        Ok((exit_code, stdout, _stderr)) => {
            assert_eq!(exit_code, 0, "env command should succeed");

            let mut found_upper = false;
            let mut found_lower = false;

            for line in stdout.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    if key == "NO_PROXY" {
                        found_upper = true;
                        assert!(
                            value.contains("example.com")
                                && value.contains("localhost")
                                && value.contains("127.0.0.1")
                                && value.contains("::1"),
                            "NO_PROXY missing expected entries: {}",
                            value
                        );
                    } else if key == "no_proxy" {
                        found_lower = true;
                        assert!(
                            value.contains("example.com")
                                && value.contains("localhost")
                                && value.contains("127.0.0.1")
                                && value.contains("::1"),
                            "no_proxy missing expected entries: {}",
                            value
                        );
                    }
                }
            }

            assert!(found_upper, "NO_PROXY variable not found");
            assert!(found_lower, "no_proxy variable not found");
        }
        Err(e) => panic!("Failed to execute httpjail: {}", e),
    }
}

// Simple server start function - we know the ports we're setting
fn start_server(http_port: u16, https_port: u16) -> Result<std::process::Child, String> {
    let httpjail_path: &str = env!("CARGO_BIN_EXE_httpjail");

    let mut cmd = Command::new(httpjail_path);
    cmd.arg("--server")
        .arg("--js")
        .arg("true")
        .arg("-vv")
        .env("HTTPJAIL_HTTP_BIND", format!("127.0.0.1:{}", http_port))
        .env("HTTPJAIL_HTTPS_BIND", format!("127.0.0.1:{}", https_port))
        .env("HTTPJAIL_SKIP_KEYCHAIN_INSTALL", "1") // Skip automatic keychain installation during tests
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    let child = cmd
        .spawn()
        .map_err(|e| format!("Failed to start server: {}", e))?;

    // Wait for the server to start listening
    if !wait_for_server(http_port, Duration::from_secs(5)) {
        return Err(format!("Server failed to start on port {}", http_port));
    }

    Ok(child)
}

fn wait_for_server(port: u16, max_wait: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < max_wait {
        if std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() {
            // Give the server a bit more time to fully initialize
            thread::sleep(Duration::from_millis(500));
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

fn test_curl_through_proxy(http_port: u16, _https_port: u16) -> Result<String, String> {
    // First, verify the proxy port is actually listening
    if !verify_bind_address(http_port, "127.0.0.1") {
        return Err(format!("Proxy port {} is not listening", http_port));
    }

    // Use a simple HTTP endpoint that should work in CI
    // Try with verbose output for debugging
    let output = Command::new("curl")
        .arg("-x")
        .arg(format!("http://127.0.0.1:{}", http_port))
        .arg("--max-time")
        .arg("10") // Increase timeout for CI
        .arg("-s")
        .arg("-S") // Show errors
        .arg("-w")
        .arg("\nHTTP_CODE:%{http_code}")
        .arg("http://example.com/")
        .output()
        .map_err(|e| format!("Failed to run curl: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Check if curl succeeded (exit code 0)
    if !output.status.success() {
        // For debugging in CI
        eprintln!("Curl failed - stdout: {}", stdout);
        eprintln!("Curl failed - stderr: {}", stderr);
        return Err(format!(
            "Curl failed with status: {}, stderr: {}",
            output.status, stderr
        ));
    }

    // Check if we got a valid HTTP response
    if stdout.contains("HTTP_CODE:200") || stdout.contains("Example Domain") {
        Ok(stdout.to_string())
    } else if stdout.contains("HTTP_CODE:403") {
        // Request was blocked by proxy (which is also fine for testing)
        Ok("Blocked by proxy".to_string())
    } else {
        Err(format!("Unexpected response: {}", stdout))
    }
}

fn verify_bind_address(port: u16, expected_ip: &str) -> bool {
    // Try to connect to the expected IP
    std::net::TcpStream::connect(format!("{}:{}", expected_ip, port)).is_ok()
}

#[test]
fn test_server_mode() {
    // Test server mode with specific ports
    let http_port = 19876;
    let https_port = 19877;

    let mut server = start_server(http_port, https_port).expect("Failed to start server");

    // Test HTTP proxy works
    match test_curl_through_proxy(http_port, https_port) {
        Ok(_response) => {
            // Success - proxy is working
        }
        Err(e) => panic!("Curl test failed: {}", e),
    }

    // Verify binds to localhost only
    assert!(
        verify_bind_address(http_port, "127.0.0.1"),
        "Server should bind to localhost"
    );

    // Cleanup
    let _ = server.kill();
    let _ = server.wait();
}

// Helper to start server with custom bind config
fn start_server_with_bind(http_bind: &str, https_bind: &str) -> (std::process::Child, u16) {
    let httpjail_path: &str = env!("CARGO_BIN_EXE_httpjail");

    let mut child = Command::new(httpjail_path)
        .arg("--server")
        .arg("--js")
        .arg("true")
        .env("HTTPJAIL_HTTP_BIND", http_bind)
        .env("HTTPJAIL_HTTPS_BIND", https_bind)
        .env("HTTPJAIL_SKIP_KEYCHAIN_INSTALL", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn server");

    // Parse expected port from bind config (server mode uses defaults for unspecified)
    let expected_port = if let Ok(port) = http_bind.parse::<u16>() {
        port
    } else if let Some(port_str) = http_bind.strip_prefix(':') {
        // Handle :port format
        port_str.parse::<u16>().unwrap_or(8080)
    } else if let Ok(addr) = http_bind.parse::<std::net::SocketAddr>() {
        addr.port()
    } else {
        8080 // Default port for server mode
    };

    // Wait for server to bind
    if !wait_for_server(expected_port, Duration::from_secs(3)) {
        child.kill().ok();
        panic!("Server failed to bind to port {}", expected_port);
    }

    (child, expected_port)
}

#[test]
#[serial]
fn test_server_bind_defaults() {
    let (mut server, port) = start_server_with_bind("", "");
    assert_eq!(port, 8080, "Server should default to port 8080");
    server.kill().ok();
}

#[test]
#[serial]
fn test_server_bind_port_only() {
    // Port-only should bind to all interfaces (0.0.0.0)
    let (mut server, port) = start_server_with_bind("19882", "19883");
    assert_eq!(
        port, 19882,
        "Server should bind to specified port on all interfaces"
    );
    server.kill().ok();
}

#[test]
#[serial]
fn test_server_bind_colon_prefix_port() {
    // :port (Go-style) should bind to all interfaces (0.0.0.0)
    let (mut server, port) = start_server_with_bind(":19892", ":19893");
    assert_eq!(
        port, 19892,
        "Server should bind to specified port on all interfaces with :port format"
    );
    server.kill().ok();
}

#[test]
#[serial]
fn test_server_bind_all_interfaces() {
    let (mut server, port) = start_server_with_bind("0.0.0.0:19884", "0.0.0.0:19885");
    assert_eq!(
        port, 19884,
        "Server should bind to specified port on 0.0.0.0"
    );
    server.kill().ok();
}

#[test]
#[serial]
fn test_server_bind_ip_without_port() {
    let (mut server, port) = start_server_with_bind("127.0.0.1", "127.0.0.1");
    assert_eq!(
        port, 8080,
        "Server should use default port 8080 when only IP specified"
    );
    server.kill().ok();
}

#[test]
#[serial]
fn test_server_bind_explicit_port_zero() {
    // Explicit port 0 should be respected (OS auto-select), not overridden to 8080
    let httpjail_path: &str = env!("CARGO_BIN_EXE_httpjail");

    let mut child = Command::new(httpjail_path)
        .arg("--server")
        .arg("--js")
        .arg("true")
        .env("HTTPJAIL_HTTP_BIND", "0") // Explicit port 0
        .env("HTTPJAIL_HTTPS_BIND", "0")
        .env("HTTPJAIL_SKIP_KEYCHAIN_INSTALL", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn server");

    // Give server a moment to bind to an OS-selected port
    thread::sleep(Duration::from_millis(500));

    // Verify it's NOT bound to the default port 8080 (it should be random)
    let not_on_default = std::net::TcpStream::connect("127.0.0.1:8080").is_err();
    assert!(
        not_on_default,
        "Server should not bind to default port 8080 when explicit :0 provided"
    );

    // Server should still be running successfully
    assert!(
        child.try_wait().unwrap().is_none(),
        "Server should be running"
    );

    child.kill().ok();
}

/// Test for Host header security (Issue #57)
/// Verifies that httpjail corrects mismatched Host headers to prevent
/// CDN routing bypasses and other Host header attacks.
///
/// This test uses httpbingo.org/headers which echoes back the received headers,
/// allowing us to verify that httpjail corrects the Host header to match the
/// actual destination URL rather than relying on external service blocking behavior.
#[test]
fn test_host_header_security() {
    use std::process::Command;

    // Test 1: Direct curl with mismatched Host header
    // httpbingo.org/headers echoes back all headers it receives
    let direct_result = Command::new("curl")
        .args([
            "-s",
            "-H",
            "Host: evil.com",
            "--max-time",
            "5",
            "https://httpbingo.org/headers",
        ])
        .output()
        .expect("Failed to execute curl directly");

    let direct_stdout = String::from_utf8_lossy(&direct_result.stdout);

    // Verify curl sends the mismatched Host header as-is
    assert!(
        direct_stdout.contains("\"Host\"") && direct_stdout.contains("evil.com"),
        "Direct curl should send mismatched Host header (got: {})",
        direct_stdout
    );

    // Test 2: Same curl command through httpjail - should correct the Host header
    let httpjail_result = HttpjailCommand::new()
        .weak()
        .js("true") // Allow all requests
        .command(vec![
            "curl",
            "-s",
            "-H",
            "Host: evil.com",
            "--max-time",
            "5",
            "https://httpbingo.org/headers",
        ])
        .execute();

    assert!(httpjail_result.is_ok(), "Httpjail request should complete");
    let (exit_code, stdout, _) = httpjail_result.unwrap();
    assert_eq!(exit_code, 0, "Httpjail request should succeed");

    // Verify httpjail corrected the Host header to match the actual destination
    assert!(
        stdout.contains("\"Host\"") && stdout.contains("httpbingo.org"),
        "Httpjail should correct Host header to httpbingo.org (got: {})",
        stdout
    );

    // Verify the mismatched header was NOT forwarded
    assert!(
        !stdout.contains("evil.com"),
        "Httpjail should not forward mismatched Host header evil.com (got: {})",
        stdout
    );

    // This demonstrates that httpjail prevents Host header bypass attacks
    // by correcting the Host header to match the actual destination URL
}

// The proc/JS parity tests have been moved to tests/json_parity.rs
// which directly tests the rule engines without the fragility of
// going through the full httpjail binary and external processes

// The max_tx_bytes test has been moved to tests/weak_integration_max_tx_bytes.rs
