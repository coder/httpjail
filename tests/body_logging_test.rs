use httpjail::request_log::{FileRequestLogger, NoopLogger};
use httpjail::rules::v8_js::V8JsRuleEngine;
use httpjail::rules::{Action, RuleEngine};
use hyper::Method;
use std::fs::OpenOptions;
use std::sync::{Arc, Mutex};
use tempfile::NamedTempFile;

#[tokio::test]
async fn test_request_logging_with_body() {
    // Create a temporary log file
    let log_file = NamedTempFile::new().unwrap();
    let file = OpenOptions::new()
        .append(true)
        .open(log_file.path())
        .unwrap();

    // Create a rule engine that allows all requests with body logging enabled
    let js_engine = V8JsRuleEngine::new("true".to_string()).unwrap();
    let logger = Arc::new(FileRequestLogger::new(Arc::new(Mutex::new(file)), true));
    let rule_engine = RuleEngine::from_trait(Box::new(js_engine), logger);

    // Evaluate a request - this should generate a request ID
    let evaluation = rule_engine
        .evaluate_with_context_and_ip(Method::POST, "https://api.example.com/users", "127.0.0.1")
        .await;

    assert_eq!(evaluation.action, Action::Allow);
    assert!(!evaluation.request_id.is_empty());

    // Check that the log file contains the expected entry with request ID
    let contents = std::fs::read_to_string(log_file.path()).unwrap();
    assert!(contents.contains("-->"));
    assert!(contents.contains("+ POST https://api.example.com/users"));
    assert!(contents.contains(&evaluation.request_id));
}

#[tokio::test]
async fn test_request_logging_without_body() {
    // Create a temporary log file
    let log_file = NamedTempFile::new().unwrap();
    let file = OpenOptions::new()
        .append(true)
        .open(log_file.path())
        .unwrap();

    // Create a rule engine that allows all requests with body logging disabled
    let js_engine = V8JsRuleEngine::new("true".to_string()).unwrap();
    let logger = Arc::new(FileRequestLogger::new(Arc::new(Mutex::new(file)), false));
    let rule_engine = RuleEngine::from_trait(Box::new(js_engine), logger);

    // The body log config should be None when env var is not set
    let body_log_config = rule_engine.get_body_log_config("test123".to_string());
    assert!(body_log_config.is_none());
}

#[tokio::test]
async fn test_denied_request_logging() {
    // Create a temporary log file
    let log_file = NamedTempFile::new().unwrap();
    let file = OpenOptions::new()
        .append(true)
        .open(log_file.path())
        .unwrap();

    // Create a rule engine that denies all requests with body logging enabled
    let js_engine = V8JsRuleEngine::new("false".to_string()).unwrap();
    let logger = Arc::new(FileRequestLogger::new(Arc::new(Mutex::new(file)), true));
    let rule_engine = RuleEngine::from_trait(Box::new(js_engine), logger);

    // Evaluate a request - this should be denied
    let evaluation = rule_engine
        .evaluate_with_context_and_ip(Method::GET, "https://blocked.site/data", "192.168.1.1")
        .await;

    assert_eq!(evaluation.action, Action::Deny);
    assert!(!evaluation.request_id.is_empty());

    // Check that the log file contains the denied entry
    let contents = std::fs::read_to_string(log_file.path()).unwrap();
    assert!(contents.contains("-->"));
    assert!(contents.contains("- GET https://blocked.site/data"));
    assert!(contents.contains(&evaluation.request_id));
}

#[tokio::test]
async fn test_request_id_generation() {
    // Create a temporary log file
    let log_file = NamedTempFile::new().unwrap();
    let file = OpenOptions::new()
        .append(true)
        .open(log_file.path())
        .unwrap();

    // Create a rule engine with body logging enabled
    let js_engine = V8JsRuleEngine::new("true".to_string()).unwrap();
    let logger = Arc::new(FileRequestLogger::new(Arc::new(Mutex::new(file)), true));
    let rule_engine = RuleEngine::from_trait(Box::new(js_engine), logger);

    // Generate multiple requests and ensure IDs are unique
    let mut request_ids = Vec::new();
    for i in 0..10 {
        let url = format!("https://example.com/test{}", i);
        let evaluation = rule_engine
            .evaluate_with_context_and_ip(Method::GET, &url, "127.0.0.1")
            .await;

        // Check that request ID is not empty and follows format
        assert!(!evaluation.request_id.is_empty());
        assert_eq!(evaluation.request_id.len(), 4); // Should be 4 hex chars

        // Check uniqueness
        assert!(!request_ids.contains(&evaluation.request_id));
        request_ids.push(evaluation.request_id);
    }
}

#[tokio::test]
async fn test_noop_logger() {
    // Create a rule engine with NoopLogger
    let js_engine = V8JsRuleEngine::new("true".to_string()).unwrap();
    let logger = Arc::new(NoopLogger);
    let rule_engine = RuleEngine::from_trait(Box::new(js_engine), logger);

    // The body log config should be None for NoopLogger
    let body_log_config = rule_engine.get_body_log_config("test123".to_string());
    assert!(body_log_config.is_none());

    // Evaluate a request - should work without logging
    let evaluation = rule_engine
        .evaluate_with_context_and_ip(Method::GET, "https://example.com", "127.0.0.1")
        .await;

    assert_eq!(evaluation.action, Action::Allow);
    assert!(!evaluation.request_id.is_empty());
}
