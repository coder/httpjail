// Minimal tests verifying parity between JavaScript (V8) and Proc rule engines.

// Import common test utilities including automatic logging setup
mod common;

use httpjail::rules::proc::ProcRuleEngine;
use httpjail::rules::v8_js::V8JsRuleEngine;
use httpjail::rules::{Action, RuleEngineTrait};
use hyper::Method;
use std::fs;
use std::io::Write;
use tempfile::NamedTempFile;

fn create_temp_script(content: &str) -> tempfile::TempPath {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(content.as_bytes()).unwrap();
    file.flush().unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(file.path()).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(file.path(), perms).unwrap();
    }

    // IMPORTANT: Convert to TempPath to close the file handle while keeping the file
    // This prevents "Text file busy" error on Linux when executing the script
    file.into_temp_path()
}

#[tokio::test]
async fn test_json_parity() {
    // Test that both engines receive identical request JSON
    let proc_script = create_temp_script(
        r#"#!/usr/bin/env python3
import sys
import json
for line in sys.stdin:
    request = json.loads(line.strip())
    print(json.dumps({"deny_message": json.dumps(request)}))
    sys.stdout.flush()
"#,
    );

    let proc_engine = ProcRuleEngine::new(proc_script.to_str().unwrap().to_string());
    let js_engine = V8JsRuleEngine::new("({deny_message: JSON.stringify(r)})".to_string()).unwrap();

    let proc_result = proc_engine
        .evaluate(Method::GET, "https://example.com/test?foo=bar", "127.0.0.1")
        .await;
    let js_result = js_engine
        .evaluate(Method::GET, "https://example.com/test?foo=bar", "127.0.0.1")
        .await;

    // Both should deny with the request JSON as context
    assert!(matches!(proc_result.action, Action::Deny));
    assert!(matches!(js_result.action, Action::Deny));

    // Parse and compare the JSON
    let proc_json: serde_json::Value = serde_json::from_str(&proc_result.context.unwrap()).unwrap();
    let js_json: serde_json::Value = serde_json::from_str(&js_result.context.unwrap()).unwrap();

    assert_eq!(proc_json, js_json, "Engines should receive identical JSON");
}

#[tokio::test]
async fn test_response_parity() {
    // Test that both engines handle responses identically
    let test_cases = [
        ("true", "true", true),
        ("false", "false", false),
        (
            r#"{"deny_message": "blocked"}"#,
            r#"({deny_message: "blocked"})"#,
            false,
        ),
    ];

    for (proc_response, js_code, expected_allow) in test_cases {
        let proc_script = create_temp_script(&format!(
            "#!/bin/sh\nwhile read line; do echo '{}'; done",
            proc_response
        ));

        let proc_engine = ProcRuleEngine::new(proc_script.to_str().unwrap().to_string());
        let js_engine = V8JsRuleEngine::new(js_code.to_string()).unwrap();

        let proc_result = proc_engine
            .evaluate(Method::GET, "https://example.com", "127.0.0.1")
            .await;
        let js_result = js_engine
            .evaluate(Method::GET, "https://example.com", "127.0.0.1")
            .await;

        assert_eq!(
            matches!(proc_result.action, Action::Allow),
            expected_allow,
            "Proc mismatch for {}",
            proc_response
        );
        assert_eq!(
            matches!(js_result.action, Action::Allow),
            expected_allow,
            "JS mismatch for {}",
            js_code
        );

        // If denied with message, verify it's the same
        if !expected_allow && proc_response.contains("deny_message") {
            assert_eq!(proc_result.context, Some("blocked".to_string()));
            assert_eq!(js_result.context, Some("blocked".to_string()));
        }
    }
}

#[tokio::test]
async fn test_console_api() {
    // Test that all console methods work in JavaScript rules
    // The output should appear in appropriate log levels
    let js_engine = V8JsRuleEngine::new(
        r#"
        console.debug("Testing console.debug");
        console.log("Testing console.log");
        console.info("Testing console.info");
        console.warn("Testing console.warn");
        console.error("Testing console.error");
        
        // Test with various types
        console.log("String:", "hello");
        console.log("Number:", 42);
        console.log("Boolean:", true);
        console.log("Object:", {foo: "bar", count: 123});
        console.log("Array:", [1, 2, 3]);
        console.log("Multiple", "arguments", "test");
        
        true
        "#
        .to_string(),
    )
    .unwrap();

    let result = js_engine
        .evaluate(Method::GET, "https://example.com", "127.0.0.1")
        .await;

    // Should allow since the expression returns true
    assert!(matches!(result.action, Action::Allow));

    // The console output should be visible in logs at appropriate levels:
    // RUST_LOG=debug: shows debug, log, info, warn, error
    // RUST_LOG=info: shows info, warn, error
    // RUST_LOG=warn: shows warn, error
    // To verify manually: RUST_LOG=debug cargo test test_console_api -- --nocapture
}
