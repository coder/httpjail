//! V8 JavaScript rule engine implementation.
//!
//! This module provides a rule engine that evaluates HTTP requests using JavaScript
//! code executed via the V8 engine. It supports automatic file reloading when rules
//! are loaded from a file path.

use crate::rules::common::{RequestInfo, RuleResponse};
use crate::rules::console_log;
use crate::rules::{EvaluationResult, RuleEngineTrait};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use hyper::Method;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// V8-based JavaScript rule engine with automatic file reloading support.
///
/// The engine uses a lock-free ArcSwap for reading JavaScript code on every request,
/// and employs a singleflight pattern (via Mutex) to prevent concurrent file reloads.
pub struct V8JsRuleEngine {
    /// JavaScript code and its last modified time (lock-free atomic updates)
    js_code: ArcSwap<(String, Option<SystemTime>)>,
    /// Optional file path for automatic reloading
    js_file_path: Option<PathBuf>,
    /// Lock to prevent concurrent file reloads (singleflight pattern)
    reload_lock: Arc<Mutex<()>>,
}

impl V8JsRuleEngine {
    pub fn new(js_code: String) -> Result<Self, Box<dyn std::error::Error>> {
        Self::new_with_file(js_code, None)
    }

    pub fn new_with_file(
        js_code: String,
        js_file_path: Option<PathBuf>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Initialize V8 platform once and keep it alive for the lifetime of the program
        use std::sync::OnceLock;
        static V8_PLATFORM: OnceLock<v8::SharedRef<v8::Platform>> = OnceLock::new();

        V8_PLATFORM.get_or_init(|| {
            let platform = v8::new_default_platform(0, false).make_shared();
            v8::V8::initialize_platform(platform.clone());
            v8::V8::initialize();
            platform
        });

        // Compile the JavaScript to check for syntax errors
        Self::validate_js_code(&js_code)?;

        // Get initial mtime if file path is provided
        let initial_mtime = js_file_path
            .as_ref()
            .and_then(|path| std::fs::metadata(path).ok().and_then(|m| m.modified().ok()));

        let js_code_swap = ArcSwap::from(Arc::new((js_code, initial_mtime)));

        if js_file_path.is_some() {
            info!("File watching enabled for JS rules - will check for changes on each request");
        }

        info!("V8 JavaScript rule engine initialized");
        Ok(Self {
            js_code: js_code_swap,
            js_file_path,
            reload_lock: Arc::new(Mutex::new(())),
        })
    }

    /// Validate JavaScript code by compiling it with V8
    fn validate_js_code(js_code: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut isolate = v8::Isolate::new(v8::CreateParams::default());
        let handle_scope = &mut v8::HandleScope::new(&mut isolate);
        let context = v8::Context::new(handle_scope, Default::default());
        let context_scope = &mut v8::ContextScope::new(handle_scope, context);

        let source = v8::String::new(context_scope, js_code).ok_or("Failed to create V8 string")?;

        v8::Script::compile(context_scope, source, None)
            .ok_or("Failed to compile JavaScript expression")?;

        Ok(())
    }

    /// Execute JavaScript rules against a request (public API).
    /// For internal use, prefer calling `evaluate()` via the RuleEngineTrait.
    pub async fn execute(
        &self,
        method: &Method,
        url: &str,
        requester_ip: &str,
    ) -> (bool, Option<String>, Option<u64>) {
        let request_info = match RequestInfo::from_request(method, url, requester_ip) {
            Ok(info) => info,
            Err(e) => {
                warn!("Failed to parse request info: {}", e);
                return (false, Some("Invalid request format".to_string()), None);
            }
        };

        // Load the current JS code (lock-free)
        let code_and_mtime = self.js_code.load();
        let (js_code, _) = &**code_and_mtime;

        match Self::execute_with_code(js_code, &request_info) {
            Ok(result) => result,
            Err(e) => {
                warn!("JavaScript execution failed: {}", e);
                (false, Some("JavaScript execution failed".to_string()), None)
            }
        }
    }

    /// Convert a V8 value to a response string that can be parsed by RuleResponse
    fn value_to_response_string(
        context_scope: &mut v8::ContextScope<v8::HandleScope>,
        global: v8::Local<v8::Object>,
        value: v8::Local<v8::Value>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        if value.is_object() && !value.is_null() && !value.is_undefined() {
            // Object - stringify it to JSON using JSON.stringify()
            let json_key = v8::String::new(context_scope, "JSON").unwrap();
            let stringify_key = v8::String::new(context_scope, "stringify").unwrap();

            let json_obj = global
                .get(context_scope, json_key.into())
                .and_then(|v| v.to_object(context_scope))
                .ok_or("Failed to get JSON object")?;

            let stringify_fn = json_obj
                .get(context_scope, stringify_key.into())
                .and_then(|v| v8::Local::<v8::Function>::try_from(v).ok())
                .ok_or("Failed to get JSON.stringify function")?;

            // Call JSON.stringify(value)
            stringify_fn
                .call(context_scope, json_obj.into(), &[value])
                .and_then(|v| v.to_string(context_scope))
                .map(|s| s.to_rust_string_lossy(context_scope))
                .ok_or_else(|| "Failed to stringify value".into())
        } else if value.is_boolean() {
            // Boolean - convert to "true" or "false" string
            Ok(if value.boolean_value(context_scope) {
                "true".to_string()
            } else {
                "false".to_string()
            })
        } else if value.is_string() {
            // String - use as-is (will be treated as deny message)
            value
                .to_string(context_scope)
                .map(|s| s.to_rust_string_lossy(context_scope))
                .ok_or_else(|| "Failed to convert string".into())
        } else {
            // Other types - default to "false"
            Ok("false".to_string())
        }
    }

    #[allow(clippy::type_complexity)]
    fn execute_with_isolate(
        isolate: &mut v8::OwnedIsolate,
        js_code: &str,
        request_info: &RequestInfo,
    ) -> Result<(bool, Option<String>, Option<u64>), Box<dyn std::error::Error>> {
        let handle_scope = &mut v8::HandleScope::new(isolate);
        let context = v8::Context::new(handle_scope, Default::default());
        let context_scope = &mut v8::ContextScope::new(handle_scope, context);

        // Set up console object with debug, log, info, warn, error methods
        console_log::setup_console(context_scope);

        let global = context.global(context_scope);

        // Serialize RequestInfo to JSON - this is the exact same JSON sent to proc
        let json_request = serde_json::to_string(&request_info)
            .map_err(|e| format!("Failed to serialize request: {}", e))?;

        // Parse the JSON in V8 to create the 'r' object
        let json_str = v8::String::new(context_scope, &json_request)
            .ok_or("Failed to create V8 string for JSON")?;
        let json_key = v8::String::new(context_scope, "JSON").unwrap();
        let parse_key = v8::String::new(context_scope, "parse").unwrap();

        let json_obj = global
            .get(context_scope, json_key.into())
            .ok_or("Failed to get JSON object")?
            .to_object(context_scope)
            .ok_or("JSON is not an object")?;

        let parse_fn = json_obj
            .get(context_scope, parse_key.into())
            .ok_or("Failed to get JSON.parse")?;

        let parse_fn = v8::Local::<v8::Function>::try_from(parse_fn)
            .map_err(|_| "JSON.parse is not a function")?;

        // Call JSON.parse to create the request object
        let r_obj = parse_fn
            .call(context_scope, json_obj.into(), &[json_str.into()])
            .ok_or("Failed to parse JSON")?;

        // Set the parsed object as 'r' in the global scope
        let r_key = v8::String::new(context_scope, "r").unwrap();
        global.set(context_scope, r_key.into(), r_obj);

        // Execute the JavaScript expression
        let source = v8::String::new(context_scope, js_code).ok_or("Failed to create V8 string")?;

        let script = v8::Script::compile(context_scope, source, None)
            .ok_or("Failed to compile JavaScript expression")?;

        // Execute the expression
        let result = script
            .run(context_scope)
            .ok_or("Expression evaluation failed")?;

        // Convert the V8 result to a JSON string for consistent parsing
        // This ensures perfect parity with the proc engine response handling
        let response_str = Self::value_to_response_string(context_scope, global, result)?;

        // Use the common RuleResponse parser - exact same logic as proc engine
        let rule_response = RuleResponse::from_string(&response_str);
        let (allowed, message, max_tx_bytes) = rule_response.to_evaluation_result();

        debug!(
            "JS rule returned {} for {} {}",
            if allowed { "ALLOW" } else { "DENY" },
            request_info.method,
            request_info.url
        );

        if let Some(ref msg) = message {
            debug!("Deny message: {}", msg);
        }

        Ok((allowed, message, max_tx_bytes))
    }

    /// Execute JavaScript code with a given code string (can be called from blocking context)
    #[allow(clippy::type_complexity)]
    fn execute_with_code(
        js_code: &str,
        request_info: &RequestInfo,
    ) -> Result<(bool, Option<String>, Option<u64>), Box<dyn std::error::Error>> {
        // Create a new isolate for each execution (simpler approach)
        let mut isolate = v8::Isolate::new(v8::CreateParams::default());
        Self::execute_with_isolate(&mut isolate, js_code, request_info)
    }

    /// Check if the JS file has changed and reload if necessary.
    /// Uses double-check locking pattern to prevent concurrent reloads.
    async fn check_and_reload_file(&self) {
        let Some(ref path) = self.js_file_path else {
            return;
        };

        let current_mtime = std::fs::metadata(path).ok().and_then(|m| m.modified().ok());

        // Fast path: check if reload needed (no lock)
        let code_and_mtime = self.js_code.load();
        let (_, last_mtime) = &**code_and_mtime;

        if current_mtime != *last_mtime && current_mtime.is_some() {
            // Slow path: acquire lock to prevent concurrent reloads (singleflight)
            let _guard = self.reload_lock.lock().await;

            // Double-check: file might have been reloaded while waiting for lock
            let code_and_mtime = self.js_code.load();
            let (_, last_mtime) = &**code_and_mtime;

            if current_mtime != *last_mtime && current_mtime.is_some() {
                info!("Detected change in JS rules file: {:?}", path);

                // Re-read and validate the file
                match std::fs::read_to_string(path) {
                    Ok(new_code) => {
                        // Validate the new code before reloading
                        if let Err(e) = Self::validate_js_code(&new_code) {
                            error!(
                                "Failed to validate updated JS code: {}. Keeping existing rules.",
                                e
                            );
                        } else {
                            // Update the code and mtime atomically (lock-free swap)
                            self.js_code.store(Arc::new((new_code, current_mtime)));
                            info!("Successfully reloaded JS rules from file");
                        }
                    }
                    Err(e) => {
                        error!(
                            "Failed to read updated JS file: {}. Keeping existing rules.",
                            e
                        );
                    }
                }
            }
        }
    }

    /// Load the current JS code from the ArcSwap (lock-free operation).
    fn load_js_code(&self) -> String {
        let code_and_mtime = self.js_code.load();
        let (js_code, _) = &**code_and_mtime;
        js_code.clone()
    }

    /// Execute JavaScript in a blocking task to handle V8's single-threaded nature.
    /// Returns (allowed, context, max_tx_bytes).
    async fn execute_js_blocking(
        js_code: String,
        method: Method,
        url: &str,
        requester_ip: &str,
    ) -> (bool, Option<String>, Option<u64>) {
        let method_clone = method.clone();
        let url_clone = url.to_string();
        let ip_clone = requester_ip.to_string();

        tokio::task::spawn_blocking(move || {
            let request_info = match RequestInfo::from_request(&method_clone, &url_clone, &ip_clone)
            {
                Ok(info) => info,
                Err(e) => {
                    warn!("Failed to parse request info: {}", e);
                    return (false, Some("Invalid request format".to_string()), None);
                }
            };

            match Self::execute_with_code(&js_code, &request_info) {
                Ok(result) => result,
                Err(e) => {
                    warn!("JavaScript execution failed: {}", e);
                    (false, Some("JavaScript execution failed".to_string()), None)
                }
            }
        })
        .await
        .unwrap_or_else(|e| {
            warn!("Failed to spawn V8 evaluation task: {}", e);
            (false, Some("Evaluation failed".to_string()), None)
        })
    }

    /// Build an EvaluationResult from the execution outcome.
    fn build_evaluation_result(
        allowed: bool,
        context: Option<String>,
        max_tx_bytes: Option<u64>,
    ) -> EvaluationResult {
        let mut result = if allowed {
            EvaluationResult::allow()
        } else {
            EvaluationResult::deny()
        };

        if let Some(ctx) = context {
            result = result.with_context(ctx);
        }

        if allowed {
            if let Some(bytes) = max_tx_bytes {
                result = result.with_max_tx_bytes(bytes);
            }
        }

        result
    }
}

#[async_trait]
impl RuleEngineTrait for V8JsRuleEngine {
    async fn evaluate(&self, method: Method, url: &str, requester_ip: &str) -> EvaluationResult {
        // Check if file has changed and reload if necessary
        self.check_and_reload_file().await;

        // Load the current JS code (lock-free operation)
        let js_code = self.load_js_code();

        // Execute JavaScript in blocking task
        let (allowed, context, max_tx_bytes) =
            Self::execute_js_blocking(js_code, method, url, requester_ip).await;

        // Build and return the result
        Self::build_evaluation_result(allowed, context, max_tx_bytes)
    }

    fn name(&self) -> &str {
        "v8_js"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_v8_js_allow() {
        let engine = V8JsRuleEngine::new("true".to_string()).unwrap();
        let result = engine
            .evaluate(Method::GET, "https://example.com", "127.0.0.1")
            .await;
        assert!(matches!(result.action, crate::rules::Action::Allow));
    }

    #[tokio::test]
    async fn test_v8_js_deny() {
        let engine = V8JsRuleEngine::new("false".to_string()).unwrap();
        let result = engine
            .evaluate(Method::GET, "https://example.com", "127.0.0.1")
            .await;
        assert!(matches!(result.action, crate::rules::Action::Deny));
    }

    #[tokio::test]
    async fn test_v8_js_with_request_info() {
        let engine = V8JsRuleEngine::new("r.host === 'example.com'".to_string()).unwrap();
        let result = engine
            .evaluate(Method::GET, "https://example.com/path", "127.0.0.1")
            .await;
        assert!(matches!(result.action, crate::rules::Action::Allow));
    }

    #[tokio::test]
    async fn test_v8_js_object_response_allow() {
        let engine = V8JsRuleEngine::new("({allow: true})".to_string()).unwrap();
        let result = engine
            .evaluate(Method::GET, "https://example.com", "127.0.0.1")
            .await;
        assert!(matches!(result.action, crate::rules::Action::Allow));
        assert_eq!(result.context, None); // No message when allowing
    }

    #[tokio::test]
    async fn test_v8_js_object_response_deny() {
        let engine =
            V8JsRuleEngine::new("({allow: false, deny_message: 'Blocked by policy'})".to_string())
                .unwrap();
        let result = engine
            .evaluate(Method::POST, "https://example.com", "127.0.0.1")
            .await;
        assert!(matches!(result.action, crate::rules::Action::Deny));
        assert_eq!(result.context, Some("Blocked by policy".to_string()));
    }

    #[tokio::test]
    async fn test_v8_js_conditional_object() {
        let engine = V8JsRuleEngine::new(
            "r.method === 'POST' ? {deny_message: 'POST not allowed'} : true".to_string(),
        )
        .unwrap();

        // Test POST (should deny with message)
        let result = engine
            .evaluate(Method::POST, "https://example.com", "127.0.0.1")
            .await;
        assert!(matches!(result.action, crate::rules::Action::Deny));
        assert_eq!(result.context, Some("POST not allowed".to_string()));

        // Test GET (should allow)
        let result = engine
            .evaluate(Method::GET, "https://example.com", "127.0.0.1")
            .await;
        assert!(matches!(result.action, crate::rules::Action::Allow));
        assert_eq!(result.context, None);
    }

    #[tokio::test]
    async fn test_v8_js_shorthand_deny_message() {
        // Test shorthand: {deny_message: "reason"} implies allow: false
        let engine =
            V8JsRuleEngine::new("({deny_message: 'Shorthand denial'})".to_string()).unwrap();
        let result = engine
            .evaluate(Method::GET, "https://example.com", "127.0.0.1")
            .await;
        assert!(matches!(result.action, crate::rules::Action::Deny));
        assert_eq!(result.context, Some("Shorthand denial".to_string()));
    }

    #[tokio::test]
    async fn test_request_field_access() {
        use crate::rules::Action;
        // Test accessing various fields of the request
        let test_cases = vec![
            (
                "r.method === 'GET'",
                Method::GET,
                "https://example.com",
                true,
            ),
            (
                "r.method === 'POST'",
                Method::GET,
                "https://example.com",
                false,
            ),
            (
                "r.host === 'example.com'",
                Method::GET,
                "https://example.com/test",
                true,
            ),
            (
                "r.host === 'other.com'",
                Method::GET,
                "https://example.com/test",
                false,
            ),
            (
                "r.path === '/test'",
                Method::GET,
                "https://example.com/test",
                true,
            ),
            (
                "r.path.startsWith('/api')",
                Method::GET,
                "https://example.com/api/v1",
                true,
            ),
            (
                "r.path.startsWith('/api')",
                Method::GET,
                "https://example.com/v1/api",
                false,
            ),
        ];

        for (js_code, method, url, expected_allow) in test_cases {
            let engine = V8JsRuleEngine::new(js_code.to_string()).unwrap();
            let result = engine.evaluate(method, url, "127.0.0.1").await;

            assert_eq!(
                matches!(result.action, Action::Allow),
                expected_allow,
                "Expression '{}' should {} request to {}",
                js_code,
                if expected_allow { "allow" } else { "deny" },
                url
            );
        }
    }

    #[tokio::test]
    async fn test_object_response() {
        use crate::rules::Action;
        // Test returning an object with allow/deny and message
        let js_code = r#"
            if (r.host === 'blocked.com') {
                ({ allow: false, deny_message: `Host ${r.host} is blocked` })
            } else {
                ({ allow: true })
            }
        "#;

        let engine = V8JsRuleEngine::new(js_code.to_string()).unwrap();

        // Test allowed request
        let result = engine
            .evaluate(Method::GET, "https://example.com/test", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));
        assert_eq!(result.context, None);

        // Test denied request with message
        let result = engine
            .evaluate(Method::GET, "https://blocked.com/test", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Deny));
        assert_eq!(
            result.context,
            Some("Host blocked.com is blocked".to_string())
        );
    }

    #[tokio::test]
    async fn test_complex_logic() {
        use crate::rules::Action;
        let js_code = r#"
            // Allow GitHub and GitLab
            const allowed_hosts = ['github.com', 'gitlab.com'];
            
            // Block certain paths
            const blocked_paths = ['/admin', '/config'];
            
            if (blocked_paths.some(p => r.path.startsWith(p))) {
                ({ deny_message: 'Access to administrative paths denied' })
            } else if (allowed_hosts.includes(r.host)) {
                true
            } else {
                false
            }
        "#;

        let engine = V8JsRuleEngine::new(js_code.to_string()).unwrap();

        // Test allowed hosts
        let result = engine
            .evaluate(Method::GET, "https://github.com/repo", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));

        let result = engine
            .evaluate(Method::GET, "https://gitlab.com/project", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));

        // Test blocked paths
        let result = engine
            .evaluate(Method::GET, "https://github.com/admin", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Deny));
        assert_eq!(
            result.context,
            Some("Access to administrative paths denied".to_string())
        );

        // Test non-allowed host
        let result = engine
            .evaluate(Method::GET, "https://example.com/test", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Deny));
    }

    #[tokio::test]
    async fn test_concurrent_evaluation() {
        use crate::rules::Action;
        use std::sync::Arc;
        // Test that multiple evaluations can run concurrently
        let engine = Arc::new(V8JsRuleEngine::new("r.host === 'example.com'".to_string()).unwrap());

        let mut tasks = vec![];
        for i in 0..10 {
            let engine_clone = engine.clone();
            let host = if i % 2 == 0 {
                "example.com"
            } else {
                "other.com"
            };
            let should_allow = i % 2 == 0;

            tasks.push(tokio::spawn(async move {
                let result = engine_clone
                    .evaluate(Method::GET, &format!("https://{}/path", host), "127.0.0.1")
                    .await;
                (should_allow, matches!(result.action, Action::Allow))
            }));
        }

        for task in tasks {
            let (should_allow, did_allow) = task.await.unwrap();
            assert_eq!(should_allow, did_allow);
        }
    }
}
