mod common;

use common::{HttpjailCommand, test_https_allow, test_https_blocking};
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
        .env("HTTPJAIL_HTTP_BIND", http_port.to_string())
        .env("HTTPJAIL_HTTPS_BIND", https_port.to_string())
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

/// Test for Host header security (Issue #57)
/// Verifies that httpjail corrects mismatched Host headers to prevent
/// CloudFlare and other CDN routing bypasses.
#[test]
fn test_host_header_security() {
    use std::process::Command;

    // Define the same curl command that attempts to set a mismatched Host header
    let curl_args = vec![
        "-s",
        "-H",
        "Host: evil.com",
        "--max-time",
        "3",
        "http://httpbin.org/headers",
    ];

    // Test 1: Direct curl execution (without httpjail) - shows the vulnerability
    let direct_result = Command::new("curl")
        .args(&curl_args)
        .output()
        .expect("Failed to execute curl directly");

    let direct_stdout = String::from_utf8_lossy(&direct_result.stdout);
    assert!(
        direct_stdout.contains("\"Host\": \"evil.com\""),
        "Direct curl should pass through the evil.com Host header unchanged"
    );

    // Test 2: Same curl command through httpjail - shows the fix
    let httpjail_result = HttpjailCommand::new()
        .weak()
        .js("true") // Allow all requests
        .command(vec!["curl"].into_iter().chain(curl_args).collect())
        .execute();

    assert!(httpjail_result.is_ok(), "Httpjail request should complete");
    let (exit_code, stdout, _) = httpjail_result.unwrap();
    assert_eq!(exit_code, 0, "Httpjail request should succeed");

    // Httpjail should have corrected the Host header to match the URI
    assert!(
        stdout.contains("\"Host\": \"httpbin.org\""),
        "Httpjail should correct the Host header to httpbin.org"
    );
    assert!(
        !stdout.contains("\"Host\": \"evil.com\""),
        "Httpjail should not pass through the evil.com Host header"
    );

    // This demonstrates that httpjail prevents the Host header bypass attack
    // that would otherwise be possible with direct curl execution
}

#[test]
fn test_proc_js_json_parity() {
    // This test verifies perfect parity between proc and JS engines
    // Both should receive exactly the same JSON request object and
    // handle responses identically

    use std::fs;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Create a proc program that echoes back the JSON it receives
    // Use sh instead of Python for better portability
    let mut proc_program = NamedTempFile::new().unwrap();
    // Simple approach using awk for JSON escaping, as it's more portable than sed
    // The JS does {deny_message: JSON.stringify(r)} which creates a stringified JSON
    let program_content = r#"#!/bin/sh
# Read lines from stdin and echo back the JSON as a deny message
while IFS= read -r line; do
    # Use awk to escape JSON string - more portable than sed
    # This escapes backslashes and quotes properly
    escaped=$(printf '%s' "$line" | awk '{
        gsub(/\\/, "\\\\");
        gsub(/"/, "\\\"");
        gsub(/\t/, "\\t");
        gsub(/\n/, "\\n");
        gsub(/\r/, "\\r");
        print
    }')
    printf '{"deny_message":"%s"}\n' "$escaped"
done
"#;
    proc_program.write_all(program_content.as_bytes()).unwrap();
    proc_program.flush().unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(proc_program.path()).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(proc_program.path(), perms).unwrap();
    }

    // Test with proc engine - use HTTP to get response body in weak mode
    let proc_result = HttpjailCommand::new()
        .weak()
        .proc_path(proc_program.path().to_str().unwrap())
        .command(vec![
            "curl",
            "--max-time",
            "3",
            "http://example.com/test?foo=bar",
        ])
        .execute();

    let proc_json = match proc_result {
        Ok((_, stdout, _)) => {
            // Extract the JSON from the deny message
            assert!(
                stdout.contains("Request blocked by httpjail"),
                "Stdout should contain 'Request blocked by httpjail'"
            );
            // The JSON is on the second line of the response
            let lines: Vec<&str> = stdout.lines().collect();
            assert!(lines.len() >= 2, "Expected at least 2 lines in response");
            lines[1].to_string()
        }
        Err(e) => panic!("Failed to execute proc test: {}", e),
    };

    // Test with JS engine that does the same thing
    let js_code = r#"
        ({deny_message: JSON.stringify(r)})
    "#;

    let js_result = HttpjailCommand::new()
        .weak()
        .js(js_code)
        .command(vec![
            "curl",
            "--max-time",
            "3",
            "http://example.com/test?foo=bar",
        ])
        .execute();

    let js_json = match js_result {
        Ok((_, stdout, _)) => {
            // Extract the JSON from the deny message
            assert!(stdout.contains("Request blocked by httpjail"));
            // The JSON is on the second line of the response
            let lines: Vec<&str> = stdout.lines().collect();
            assert!(lines.len() >= 2, "Expected at least 2 lines in JS response");
            lines[1].to_string()
        }
        Err(e) => panic!("Failed to execute JS test: {}", e),
    };

    // Parse and compare the JSON objects
    let proc_parsed: serde_json::Value =
        serde_json::from_str(&proc_json).expect("Failed to parse proc JSON");
    let js_parsed: serde_json::Value =
        serde_json::from_str(&js_json).expect("Failed to parse JS JSON");

    // Both should have exactly the same structure
    assert_eq!(
        proc_parsed, js_parsed,
        "Proc and JS engines should receive identical JSON request objects"
    );

    // Verify expected fields are present
    assert_eq!(proc_parsed["url"], "http://example.com/test?foo=bar");
    assert_eq!(proc_parsed["method"], "GET");
    assert_eq!(proc_parsed["scheme"], "http");
    assert_eq!(proc_parsed["host"], "example.com");
    assert_eq!(proc_parsed["path"], "/test");
    assert!(proc_parsed["requester_ip"].is_string());

    // Verify no extra fields (exactly 6 fields)
    assert_eq!(
        proc_parsed.as_object().unwrap().len(),
        6,
        "Request object should have exactly 6 fields"
    );
}

#[test]
fn test_proc_js_response_parity() {
    // Test that both engines handle various response formats identically
    use std::fs;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Test cases: (response_output, expected_allow)
    let test_cases = vec![
        ("true", true),
        ("false", false),
        (r#"{"allow": true}"#, true),
        (r#"{"allow": false, "deny_message": "blocked"}"#, false),
        (r#"{"deny_message": "shorthand deny"}"#, false),
        ("arbitrary text message", false),
    ];

    for (response, expected_allow) in test_cases {
        // Create proc program that returns the test response
        // Use sh for portability
        let mut proc_program = NamedTempFile::new().unwrap();
        // All responses should be echoed directly as-is
        let program_content = format!(
            r#"#!/bin/sh
# Echo the exact response for each line of input
while IFS= read -r line; do
    echo '{}'
done
"#,
            response
        );

        proc_program.write_all(program_content.as_bytes()).unwrap();
        proc_program.flush().unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(proc_program.path()).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(proc_program.path(), perms).unwrap();
        }

        // Test with proc engine
        let proc_result = HttpjailCommand::new()
            .weak()
            .proc_path(proc_program.path().to_str().unwrap())
            .command(vec![
                "curl",
                "--max-time",
                "3",
                "https://httpbin.org/status/200",
            ])
            .execute();

        // Test with JS engine returning the same response
        let js_code = if response == "true" || response == "false" {
            response.to_string()
        } else if response.starts_with('{') {
            format!("({})", response)
        } else {
            format!(r#""{}"#, response)
        };

        let js_result = HttpjailCommand::new()
            .weak()
            .js(&js_code)
            .command(vec![
                "curl",
                "--max-time",
                "3",
                "https://httpbin.org/status/200",
            ])
            .execute();

        // Both should handle the response identically
        // For HTTP requests, check if we got the actual HTTP status response
        let proc_allowed = proc_result
            .as_ref()
            .map(|(exit_code, stdout, _)| {
                // If we get exit code 0 and no "Request blocked" message, it was allowed
                *exit_code == 0 && !stdout.contains("Request blocked by httpjail")
            })
            .unwrap_or(false);
        let js_allowed = js_result
            .as_ref()
            .map(|(exit_code, stdout, _)| {
                *exit_code == 0 && !stdout.contains("Request blocked by httpjail")
            })
            .unwrap_or(false);

        assert_eq!(
            proc_allowed, js_allowed,
            "Proc and JS should handle response '{}' identically",
            response
        );
        assert_eq!(
            proc_allowed, expected_allow,
            "Response '{}' should be allowed={}",
            response, expected_allow
        );

        // If denied with a message, verify the message is the same
        if !expected_allow && response.contains("deny_message") {
            let proc_stdout = &proc_result.unwrap().1;
            let js_stdout = &js_result.unwrap().1;

            // Extract context messages if present
            if let Some(proc_ctx_start) = proc_stdout.find("Context: ") {
                let proc_ctx_end = proc_stdout[proc_ctx_start..]
                    .find('<')
                    .unwrap_or(proc_stdout.len() - proc_ctx_start);
                let proc_context = &proc_stdout[proc_ctx_start + 9..proc_ctx_start + proc_ctx_end];

                if let Some(js_ctx_start) = js_stdout.find("Context: ") {
                    let js_ctx_end = js_stdout[js_ctx_start..]
                        .find('<')
                        .unwrap_or(js_stdout.len() - js_ctx_start);
                    let js_context = &js_stdout[js_ctx_start + 9..js_ctx_start + js_ctx_end];

                    assert_eq!(
                        proc_context, js_context,
                        "Proc and JS should have identical context messages for response '{}'",
                        response
                    );
                }
            }
        }
    }
}
