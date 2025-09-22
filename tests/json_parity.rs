// Minimal tests verifying parity between JavaScript (V8) and Proc rule engines.

use httpjail::rules::proc::ProcRuleEngine;
use httpjail::rules::v8_js::V8JsRuleEngine;
use httpjail::rules::{Action, RuleEngineTrait};
use hyper::Method;
use std::fs;
use std::io::Write;
use tempfile::NamedTempFile;

fn create_temp_script(content: &str) -> NamedTempFile {
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

    file
}

#[tokio::test]
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Proc tests have environment-specific issues on Linux CI"
)]
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

    let proc_engine = ProcRuleEngine::new(proc_script.path().to_str().unwrap().to_string());
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
#[cfg_attr(
    not(target_os = "macos"),
    ignore = "Proc tests have environment-specific issues on Linux CI"
)]
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

        let proc_engine = ProcRuleEngine::new(proc_script.path().to_str().unwrap().to_string());
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
