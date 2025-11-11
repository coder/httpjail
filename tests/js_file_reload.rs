use httpjail::rules::RuleEngineTrait;
use httpjail::rules::v8_js::V8JsRuleEngine;
use hyper::Method;
use std::fs;
use std::path::PathBuf;
use tempfile::NamedTempFile;

#[tokio::test(flavor = "multi_thread")]
async fn test_js_file_reload() {
    // Create a temporary JS file and persist it to avoid early deletion
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let (file, path) = temp_file.into_parts();
    let file_path = PathBuf::from(&path);
    drop(file); // Close the file handle

    // Write initial rule (allow all requests)
    fs::write(&file_path, "true").expect("Failed to write initial rule");

    // Create engine with file watching
    let code = fs::read_to_string(&file_path).expect("Failed to read file");
    let engine = V8JsRuleEngine::new_with_file(code, Some(file_path.clone()))
        .expect("Failed to create engine");

    // Test initial rule (should allow)
    let result = engine
        .evaluate(Method::GET, "https://example.com", "127.0.0.1")
        .await;
    assert!(matches!(result.action, httpjail::rules::Action::Allow));

    // Update the JS file (deny all requests)
    fs::write(&file_path, "false").expect("Failed to write updated rule");

    // Reload happens on next evaluate call - no waiting needed

    // Test updated rule (should deny)
    let result = engine
        .evaluate(Method::GET, "https://example.com", "127.0.0.1")
        .await;
    assert!(matches!(result.action, httpjail::rules::Action::Deny));

    // Update again with a more complex rule
    fs::write(&file_path, "r.host === 'allowed.com'").expect("Failed to write complex rule");

    // Reload happens on next evaluate call - no waiting needed

    // Test with allowed host
    let result = engine
        .evaluate(Method::GET, "https://allowed.com/path", "127.0.0.1")
        .await;
    assert!(matches!(result.action, httpjail::rules::Action::Allow));

    // Test with denied host
    let result = engine
        .evaluate(Method::GET, "https://denied.com/path", "127.0.0.1")
        .await;
    assert!(matches!(result.action, httpjail::rules::Action::Deny));

    // Clean up
    let _ = fs::remove_file(&file_path);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_js_file_reload_syntax_error() {
    // Create a temporary JS file and persist it
    let temp_file = NamedTempFile::new().expect("Failed to create temp file");
    let (file, path) = temp_file.into_parts();
    let file_path = PathBuf::from(&path);
    drop(file);

    // Write initial valid rule
    fs::write(&file_path, "true").expect("Failed to write initial rule");

    // Create engine with file watching
    let code = fs::read_to_string(&file_path).expect("Failed to read file");
    let engine = V8JsRuleEngine::new_with_file(code, Some(file_path.clone()))
        .expect("Failed to create engine");

    // Test initial rule (should allow)
    let result = engine
        .evaluate(Method::GET, "https://example.com", "127.0.0.1")
        .await;
    assert!(matches!(result.action, httpjail::rules::Action::Allow));

    // Update the JS file with syntax error
    fs::write(&file_path, "this is not valid javascript {{[")
        .expect("Failed to write invalid rule");

    // Reload check happens on next evaluate call - no waiting needed

    // Test that the old rule is still in effect (reload should have been rejected)
    let result = engine
        .evaluate(Method::GET, "https://example.com", "127.0.0.1")
        .await;
    assert!(matches!(result.action, httpjail::rules::Action::Allow));

    // Clean up
    let _ = fs::remove_file(&file_path);
}

#[tokio::test]
async fn test_js_engine_without_file_path() {
    // Create engine without file path (no file watching)
    let engine = V8JsRuleEngine::new("true".to_string()).expect("Failed to create engine");

    // Test that it works normally
    let result = engine
        .evaluate(Method::GET, "https://example.com", "127.0.0.1")
        .await;
    assert!(matches!(result.action, httpjail::rules::Action::Allow));
}
