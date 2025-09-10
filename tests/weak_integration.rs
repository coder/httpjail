mod common;

use common::{HttpjailCommand, build_httpjail, test_https_allow, test_https_blocking};
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
        .rule("deny: .*")
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
    // Test that the timeout mechanism works correctly
    // This test uses a command that would normally hang
    let result = HttpjailCommand::new()
        .weak()
        .rule("allow: .*")
        .verbose(2)
        .command(vec!["sh", "-c", "sleep 15"])
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
        .rule("allow: localhost")
        .rule("allow: 127\\.0\\.0\\.1")
        .verbose(2)
        .command(vec![
            "curl",
            "--max-time",
            "3",
            "http://127.0.0.1:8080/test",
        ])
        .execute();

    match result {
        Ok((exit_code, _stdout, stderr)) => {
            println!("Exit code: {}", exit_code);
            println!("Stderr: {}", stderr);

            // This should fail with connection refused (no server on 8080)
            // but NOT be blocked by the proxy
            // Exit code 7 = Failed to connect (expected - no server)
            // Exit code 52 = Empty reply from server (proxy allowed but no backend)
            assert!(
                exit_code == 7 || exit_code == 52,
                "Expected connection refused (7) or empty reply (52), got: {}",
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

// Server mode tests - DRY helper functions
fn start_server_with_config(
    port_config: Option<(&str, &str)>,
    bind_ip: Option<&str>,
) -> Result<std::process::Child, String> {
    let httpjail_path = build_httpjail()?;

    let mut cmd = Command::new(&httpjail_path);
    cmd.arg("--server")
        .arg("-r")
        .arg("allow: .*")
        .arg("-vv")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Set environment variables for ports and/or IP binding
    if let Some((http_port, https_port)) = port_config {
        if let Some(ip) = bind_ip {
            cmd.env("HTTPJAIL_HTTP_BIND", format!("{}:{}", ip, http_port));
            cmd.env("HTTPJAIL_HTTPS_BIND", format!("{}:{}", ip, https_port));
        } else {
            cmd.env("HTTPJAIL_HTTP_BIND", http_port);
            cmd.env("HTTPJAIL_HTTPS_BIND", https_port);
        }
    }

    cmd.spawn()
        .map_err(|e| format!("Failed to start server: {}", e))
}

fn wait_for_server(port: u16, max_wait: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < max_wait {
        if std::net::TcpStream::connect(format!("127.0.0.1:{}", port)).is_ok() {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

fn test_curl_through_proxy(http_port: u16, _https_port: u16) -> Result<String, String> {
    let output = Command::new("curl")
        .arg("-x")
        .arg(format!("http://127.0.0.1:{}", http_port))
        .arg("--max-time")
        .arg("3")
        .arg("-s")
        .arg("http://httpbin.org/ip")
        .output()
        .map_err(|e| format!("Failed to run curl: {}", e))?;

    if !output.status.success() {
        return Err(format!("Curl failed with status: {}", output.status));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn verify_bind_address(port: u16, expected_ip: &str) -> bool {
    // Try to connect to the expected IP
    std::net::TcpStream::connect(format!("{}:{}", expected_ip, port)).is_ok()
}

#[test]
fn test_server_mode_default_ports() {
    // Test 1: Server with default ports (8080/8443)
    let mut server = start_server_with_config(None, None).expect("Failed to start server");

    // Wait for server to start
    assert!(
        wait_for_server(8080, Duration::from_secs(5)),
        "Server failed to start on default port 8080"
    );

    // Test HTTP proxy works
    match test_curl_through_proxy(8080, 8443) {
        Ok(response) => {
            assert!(
                response.contains("\"origin\"") || response.contains("origin"),
                "Expected valid response from httpbin, got: {}",
                response
            );
        }
        Err(e) => panic!("Curl test failed: {}", e),
    }

    // Verify binds to localhost only
    assert!(
        verify_bind_address(8080, "127.0.0.1"),
        "Server should bind to localhost"
    );

    // Cleanup
    let _ = server.kill();
    let _ = server.wait();
}

#[test]
fn test_server_mode_custom_ports() {
    // Test 2: Server with custom ports
    let mut server = start_server_with_config(Some(("9090", "9091")), None)
        .expect("Failed to start server with custom ports");

    // Wait for server to start
    assert!(
        wait_for_server(9090, Duration::from_secs(5)),
        "Server failed to start on custom port 9090"
    );

    // Test HTTP proxy works on custom port
    match test_curl_through_proxy(9090, 9091) {
        Ok(response) => {
            assert!(
                response.contains("\"origin\"") || response.contains("origin"),
                "Expected valid response from httpbin, got: {}",
                response
            );
        }
        Err(e) => panic!("Curl test failed: {}", e),
    }

    // Verify binds to localhost only
    assert!(
        verify_bind_address(9090, "127.0.0.1"),
        "Server should bind to localhost"
    );

    // Cleanup
    let _ = server.kill();
    let _ = server.wait();
}

#[test]
fn test_server_mode_specific_ip() {
    // Test 3: Server with specific IP (localhost)
    let mut server = start_server_with_config(Some(("9092", "9093")), Some("127.0.0.1"))
        .expect("Failed to start server with specific IP");

    // Wait for server to start
    assert!(
        wait_for_server(9092, Duration::from_secs(5)),
        "Server failed to start on port 9092 with specific IP"
    );

    // Test HTTP proxy works
    match test_curl_through_proxy(9092, 9093) {
        Ok(response) => {
            assert!(
                response.contains("\"origin\"") || response.contains("origin"),
                "Expected valid response from httpbin, got: {}",
                response
            );
        }
        Err(e) => panic!("Curl test failed: {}", e),
    }

    // Verify binds to specified IP
    assert!(
        verify_bind_address(9092, "127.0.0.1"),
        "Server should bind to specified IP"
    );

    // Cleanup
    let _ = server.kill();
    let _ = server.wait();
}
