use httpjail::rules::script::ScriptRuleEngine;
use httpjail::rules::{Action, RuleEngineTrait};
use hyper::Method;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tempfile::NamedTempFile;

#[test]
fn test_script_allows_github() {
    let script_file = NamedTempFile::new().unwrap();
    let script = r#"#!/bin/sh
if [ "$HTTPJAIL_HOST" = "github.com" ]; then
    exit 0
else
    echo "Only github.com is allowed"
    exit 1
fi
"#;
    fs::write(script_file.path(), script).unwrap();

    let mut perms = fs::metadata(script_file.path()).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(script_file.path(), perms).unwrap();

    let engine = ScriptRuleEngine::new(script_file.path().to_str().unwrap().to_string());

    // Test allowed request
    let result = engine.evaluate(Method::GET, "https://github.com/user/repo");
    assert!(matches!(result.action, Action::Allow));

    // Test denied request with context
    let result = engine.evaluate(Method::POST, "https://example.com/api");
    assert!(matches!(result.action, Action::Deny));
    assert_eq!(
        result.context,
        Some("Only github.com is allowed".to_string())
    );
}

#[test]
fn test_script_with_method_filtering() {
    let script_file = NamedTempFile::new().unwrap();
    let script = r#"#!/bin/sh
if [ "$HTTPJAIL_METHOD" = "GET" ] || [ "$HTTPJAIL_METHOD" = "HEAD" ]; then
    exit 0
else
    echo "Method $HTTPJAIL_METHOD not allowed"
    exit 1
fi
"#;
    fs::write(script_file.path(), script).unwrap();

    let mut perms = fs::metadata(script_file.path()).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(script_file.path(), perms).unwrap();

    let engine = ScriptRuleEngine::new(script_file.path().to_str().unwrap().to_string());

    // Test allowed methods
    let result = engine.evaluate(Method::GET, "https://example.com/api");
    assert!(matches!(result.action, Action::Allow));

    let result = engine.evaluate(Method::HEAD, "https://example.com/api");
    assert!(matches!(result.action, Action::Allow));

    // Test denied method with context
    let result = engine.evaluate(Method::POST, "https://example.com/api");
    assert!(matches!(result.action, Action::Deny));
    assert_eq!(result.context, Some("Method POST not allowed".to_string()));
}

#[test]
fn test_inline_script_evaluation() {
    // Test inline script (with spaces, executed via shell)
    let engine = ScriptRuleEngine::new(
        r#"[ "$HTTPJAIL_PATH" = "/api/v1/health" ] && exit 0 || exit 1"#.to_string(),
    );

    let result = engine.evaluate(Method::GET, "https://example.com/api/v1/health");
    assert!(matches!(result.action, Action::Allow));

    let result = engine.evaluate(Method::GET, "https://example.com/api/v2/users");
    assert!(matches!(result.action, Action::Deny));
}

#[test]
fn test_script_with_complex_logic() {
    let script_file = NamedTempFile::new().unwrap();
    let script = r#"#!/bin/sh
# Complex logic: allow GET to github.com, POST to api.example.com, deny everything else

if [ "$HTTPJAIL_METHOD" = "GET" ] && [ "$HTTPJAIL_HOST" = "github.com" ]; then
    echo "GitHub read access allowed"
    exit 0
elif [ "$HTTPJAIL_METHOD" = "POST" ] && [ "$HTTPJAIL_HOST" = "api.example.com" ]; then
    echo "API write access allowed"
    exit 0
else
    echo "Request blocked by security policy: $HTTPJAIL_METHOD to $HTTPJAIL_HOST"
    exit 1
fi
"#;
    fs::write(script_file.path(), script).unwrap();

    let mut perms = fs::metadata(script_file.path()).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(script_file.path(), perms).unwrap();

    let engine = ScriptRuleEngine::new(script_file.path().to_str().unwrap().to_string());

    // Test allowed GitHub GET
    let result = engine.evaluate(Method::GET, "https://github.com/user/repo");
    assert!(matches!(result.action, Action::Allow));
    assert_eq!(
        result.context,
        Some("GitHub read access allowed".to_string())
    );

    // Test allowed API POST
    let result = engine.evaluate(Method::POST, "https://api.example.com/users");
    assert!(matches!(result.action, Action::Allow));
    assert_eq!(result.context, Some("API write access allowed".to_string()));

    // Test denied request
    let result = engine.evaluate(Method::POST, "https://github.com/user/repo");
    assert!(matches!(result.action, Action::Deny));
    assert!(
        result
            .context
            .unwrap()
            .contains("Request blocked by security policy")
    );
}
