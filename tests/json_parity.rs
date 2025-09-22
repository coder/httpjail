// Tests for verifying parity between JavaScript (V8) and Proc rule engines.
// These tests directly instantiate and test the rule engines without going through
// the full httpjail binary, making them more robust and portable across platforms.

use httpjail::rules::proc::ProcRuleEngine;
use httpjail::rules::v8_js::V8JsRuleEngine;
use httpjail::rules::{Action, RuleEngineTrait};
use hyper::Method;
use std::fs;
use std::io::Write;
use tempfile::NamedTempFile;

/// Helper to create a temporary executable script file
fn create_temp_script(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("Failed to create temp file");
    file.write_all(content.as_bytes())
        .expect("Failed to write to temp file");
    file.flush().expect("Failed to flush temp file");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(file.path())
            .expect("Failed to get file metadata")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(file.path(), perms).expect("Failed to set file permissions");
    }

    file
}

/// Test that both engines receive and parse the same JSON request structure
#[tokio::test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Proc tests have environment-specific issues on Linux CI"
)]
async fn test_json_request_parity() {
    // Create a proc program that echoes back the JSON it receives
    // Use Python for reliable JSON handling across platforms
    let proc_script = create_temp_script(
        r#"#!/usr/bin/env python3
import sys
import json

for line in sys.stdin:
    request = json.loads(line.strip())
    # Echo the request back as a stringified JSON in deny_message
    print(json.dumps({"deny_message": json.dumps(request)}))
    sys.stdout.flush()
"#,
    );

    // Create the proc engine
    let proc_engine = ProcRuleEngine::new(proc_script.path().to_str().unwrap().to_string());

    // Create equivalent JS engine that also echoes the request
    let js_code = "({deny_message: JSON.stringify(r)})";
    let js_engine = V8JsRuleEngine::new(js_code.to_string()).expect("Failed to create JS engine");

    // Test various URLs to ensure both engines see the same request structure
    let test_cases = vec![
        ("GET", "https://example.com/path?query=value"),
        ("POST", "http://api.example.org/v1/users"),
        ("PUT", "https://test.io:8080/resource"),
        ("DELETE", "http://localhost/item/123"),
    ];

    for (method, url) in test_cases {
        let method_enum = match method {
            "GET" => Method::GET,
            "POST" => Method::POST,
            "PUT" => Method::PUT,
            "DELETE" => Method::DELETE,
            _ => panic!("Unknown method"),
        };

        let requester_ip = "127.0.0.1";

        // Get responses from both engines
        let proc_result = proc_engine
            .evaluate(method_enum.clone(), url, requester_ip)
            .await;
        let js_result = js_engine
            .evaluate(method_enum.clone(), url, requester_ip)
            .await;

        // Both should deny with the request JSON as the message
        assert!(
            matches!(proc_result.action, Action::Deny),
            "Proc should deny for {}",
            url
        );
        assert!(
            matches!(js_result.action, Action::Deny),
            "JS should deny for {}",
            url
        );

        // Parse the JSON from the context messages
        let proc_json: serde_json::Value = serde_json::from_str(
            proc_result
                .context
                .as_ref()
                .expect("Proc should have context message"),
        )
        .expect("Failed to parse proc JSON");

        let js_json: serde_json::Value = serde_json::from_str(
            js_result
                .context
                .as_ref()
                .expect("JS should have context message"),
        )
        .expect("Failed to parse JS JSON");

        // Verify both engines received the same request structure
        assert_eq!(proc_json["url"], js_json["url"], "URL mismatch for {}", url);
        assert_eq!(
            proc_json["method"], js_json["method"],
            "Method mismatch for {}",
            url
        );
        assert_eq!(
            proc_json["host"], js_json["host"],
            "Host mismatch for {}",
            url
        );
        assert_eq!(
            proc_json["scheme"], js_json["scheme"],
            "Scheme mismatch for {}",
            url
        );
        assert_eq!(
            proc_json["path"], js_json["path"],
            "Path mismatch for {}",
            url
        );
        assert_eq!(
            proc_json["requester_ip"], js_json["requester_ip"],
            "Requester IP mismatch for {}",
            url
        );
    }
}

/// Test that both engines handle various response formats identically
#[tokio::test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Proc tests have environment-specific issues on Linux CI"
)]
async fn test_response_format_parity() {
    // Test cases with different response formats
    let test_cases = vec![
        // (proc_response, js_code, expected_allow, expected_message)
        ("true", "true", true, None),
        ("false", "false", false, None),
        (r#"{"allow": true}"#, "({allow: true})", true, None),
        (
            r#"{"allow": false, "deny_message": "blocked"}"#,
            r#"({allow: false, deny_message: "blocked"})"#,
            false,
            Some("blocked"),
        ),
        (
            r#"{"deny_message": "shorthand deny"}"#,
            r#"({deny_message: "shorthand deny"})"#,
            false,
            Some("shorthand deny"),
        ),
        // Non-JSON response should be treated as deny with the response as message
        (
            "arbitrary text message",
            r#""arbitrary text message""#,
            false,
            Some("arbitrary text message"),
        ),
    ];

    for (proc_response, js_code, expected_allow, expected_message) in test_cases {
        // Create proc script that returns the specified response
        let proc_script = create_temp_script(&format!(
            r#"#!/bin/sh
# Return a fixed response for testing
while IFS= read -r line; do
    echo '{}'
done
"#,
            proc_response
        ));

        let proc_engine = ProcRuleEngine::new(proc_script.path().to_str().unwrap().to_string());
        let js_engine =
            V8JsRuleEngine::new(js_code.to_string()).expect("Failed to create JS engine");

        // Test with a sample request
        let method = Method::GET;
        let url = "https://example.com/test";
        let requester_ip = "127.0.0.1";

        let proc_result = proc_engine
            .evaluate(method.clone(), url, requester_ip)
            .await;
        let js_result = js_engine.evaluate(method, url, requester_ip).await;

        // Verify both engines interpret the response the same way
        let proc_allowed = matches!(proc_result.action, Action::Allow);
        let js_allowed = matches!(js_result.action, Action::Allow);

        assert_eq!(
            proc_allowed, expected_allow,
            "Proc allow mismatch for response: {}",
            proc_response
        );
        assert_eq!(
            js_allowed, expected_allow,
            "JS allow mismatch for code: {}",
            js_code
        );
        assert_eq!(
            proc_result.context,
            expected_message.map(|s| s.to_string()),
            "Proc message mismatch for response: {}",
            proc_response
        );
        assert_eq!(
            js_result.context,
            expected_message.map(|s| s.to_string()),
            "JS message mismatch for code: {}",
            js_code
        );
    }
}

/// Test that both engines handle errors and edge cases consistently
#[tokio::test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Proc tests have environment-specific issues on Linux CI"
)]
async fn test_error_handling_parity() {
    // Test malformed JSON response from proc
    let proc_script = create_temp_script(
        r#"#!/bin/sh
# Return malformed JSON
while IFS= read -r line; do
    echo '{"allow": malformed}'
done
"#,
    );

    let proc_engine = ProcRuleEngine::new(proc_script.path().to_str().unwrap().to_string());

    // JS engine with syntax error (unterminated string)
    let js_engine = V8JsRuleEngine::new("'unterminated string".to_string());

    // JS engine creation should fail with invalid syntax
    assert!(
        js_engine.is_err(),
        "JS engine should fail with invalid syntax"
    );

    // For proc, malformed JSON should result in the response being treated as a deny message
    let proc_result = proc_engine
        .evaluate(Method::GET, "https://example.com", "127.0.0.1")
        .await;

    assert!(
        matches!(proc_result.action, Action::Deny),
        "Malformed JSON should deny"
    );
    assert_eq!(
        proc_result.context,
        Some(r#"{"allow": malformed}"#.to_string()),
        "Malformed JSON should become the context message"
    );

    // Test empty response from proc
    let empty_proc_script = create_temp_script(
        r#"#!/bin/sh
# Return nothing
while IFS= read -r line; do
    echo ""
done
"#,
    );

    let empty_proc_engine =
        ProcRuleEngine::new(empty_proc_script.path().to_str().unwrap().to_string());

    let empty_result = empty_proc_engine
        .evaluate(Method::GET, "https://example.com", "127.0.0.1")
        .await;

    // Empty response should be treated as deny
    assert!(
        matches!(empty_result.action, Action::Deny),
        "Empty response should deny"
    );
}

/// Test complex filtering logic works the same in both engines
#[tokio::test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Proc tests have environment-specific issues on Linux CI"
)]
async fn test_complex_logic_parity() {
    // Create a proc script with complex logic
    let proc_script = create_temp_script(
        r#"#!/usr/bin/env python3
import json
import sys

for line in sys.stdin:
    request = json.loads(line.strip())
    
    # Complex logic matching the JS version
    if request['host'] == 'github.com':
        if request['method'] == 'GET':
            print('true')
        else:
            print(json.dumps({"deny_message": "Only GET allowed for github.com"}))
    elif request['host'].endswith('.internal'):
        print(json.dumps({"allow": True}))
    elif request['scheme'] == 'http':
        print(json.dumps({"deny_message": "HTTPS required"}))
    else:
        print('false')
    
    sys.stdout.flush()
"#,
    );

    // Equivalent JS logic (as a single expression)
    let js_code = "r.host === 'github.com' ? (r.method === 'GET' ? true : {deny_message: 'Only GET allowed for github.com'}) : r.host.endsWith('.internal') ? {allow: true} : r.scheme === 'http' ? {deny_message: 'HTTPS required'} : false";

    let proc_engine = ProcRuleEngine::new(proc_script.path().to_str().unwrap().to_string());
    let js_engine = V8JsRuleEngine::new(js_code.to_string()).expect("Failed to create JS engine");

    // Test cases that exercise different branches
    let test_cases = vec![
        (Method::GET, "https://github.com/repo", true, None),
        (
            Method::POST,
            "https://github.com/repo",
            false,
            Some("Only GET allowed for github.com"),
        ),
        (Method::GET, "https://app.internal/api", true, None),
        (
            Method::GET,
            "http://example.com",
            false,
            Some("HTTPS required"),
        ),
        (Method::GET, "https://example.com", false, None),
    ];

    for (method, url, expected_allow, expected_message) in test_cases {
        let proc_result = proc_engine.evaluate(method.clone(), url, "127.0.0.1").await;
        let js_result = js_engine.evaluate(method, url, "127.0.0.1").await;

        let proc_allowed = matches!(proc_result.action, Action::Allow);
        let js_allowed = matches!(js_result.action, Action::Allow);

        assert_eq!(
            proc_allowed, expected_allow,
            "Proc allow mismatch for {}",
            url
        );
        assert_eq!(js_allowed, expected_allow, "JS allow mismatch for {}", url);
        assert_eq!(
            proc_result.context,
            expected_message.map(|s| s.to_string()),
            "Proc message mismatch for {}",
            url
        );
        assert_eq!(
            js_result.context,
            expected_message.map(|s| s.to_string()),
            "JS message mismatch for {}",
            url
        );
    }
}

/// Test stateful processing works correctly with proc engine
#[tokio::test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Proc tests have environment-specific issues on Linux CI"
)]
async fn test_proc_stateful_processing() {
    // Create a stateful proc script that counts requests
    let proc_script = create_temp_script(
        r#"#!/usr/bin/env python3
import json
import sys

count = 0
for line in sys.stdin:
    count += 1
    request = json.loads(line.strip())
    
    if count <= 2:
        print('true')
    else:
        print(json.dumps({"deny_message": f"Rate limit exceeded: {count} requests"}))
    
    sys.stdout.flush()
"#,
    );

    let proc_engine = ProcRuleEngine::new(proc_script.path().to_str().unwrap().to_string());

    // Make multiple requests to test statefulness
    for i in 1..=5 {
        let result = proc_engine
            .evaluate(Method::GET, "https://example.com", "127.0.0.1")
            .await;

        if i <= 2 {
            assert!(
                matches!(result.action, Action::Allow),
                "Request {} should be allowed",
                i
            );
        } else {
            assert!(
                matches!(result.action, Action::Deny),
                "Request {} should be denied",
                i
            );
            assert!(
                result.context.is_some(),
                "Request {} should have context message",
                i
            );
        }
    }
}
