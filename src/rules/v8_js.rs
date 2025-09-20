#[cfg(test)]
use super::Action;
use super::common::RequestInfo;
use super::{EvaluationResult, RuleEngineTrait};
use async_trait::async_trait;
use hyper::Method;
use std::sync::{Once, OnceLock};
use tracing::{debug, warn};

/// V8 JavaScript rule engine that creates a fresh context for each evaluation
/// to ensure thread safety. While this is less performant than reusing contexts,
/// it's necessary because V8 isolates are not Send + Sync.
pub struct V8JsRuleEngine {
    js_code: String,
}

static V8_INIT: Once = Once::new();
static V8_PLATFORM: OnceLock<v8::SharedRef<v8::Platform>> = OnceLock::new();

impl V8JsRuleEngine {
    /// Creates a new V8 JavaScript rule engine
    ///
    /// # Arguments
    /// * `js_code` - JavaScript expression that evaluates to a boolean value
    ///   The code has access to the `r` object with properties:
    ///   - `r.url` - Full URL string
    ///   - `r.method` - HTTP method string
    ///   - `r.scheme` - URL scheme (http/https)
    ///   - `r.host` - Host part of URL
    ///   - `r.path` - Path part of URL
    ///   - `r.block_message` - Optional message to set when denying (writable)
    pub fn new(js_code: String) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Initialize V8 platform (only once per process), and keep the platform alive
        V8_INIT.call_once(|| {
            let platform = v8::new_default_platform(0, false).make_shared();
            v8::V8::initialize_platform(platform.clone());
            // Store platform so it outlives all isolates
            let _ = V8_PLATFORM.set(platform);
            v8::V8::initialize();
        });

        // Test that the JavaScript code can be compiled
        Self::test_js_compilation(&js_code)?;

        Ok(Self { js_code })
    }

    /// Test that the JavaScript code compiles successfully
    fn test_js_compilation(js_code: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut isolate = v8::Isolate::new(v8::CreateParams::default());
        let handle_scope = &mut v8::HandleScope::new(&mut isolate);
        let context = v8::Context::new(handle_scope, Default::default());
        let context_scope = &mut v8::ContextScope::new(handle_scope, context);

        // The code should be a JavaScript expression, not a function
        let source = v8::String::new(context_scope, js_code)
            .ok_or("Failed to create V8 string from JavaScript code")?;

        v8::Script::compile(context_scope, source, None)
            .ok_or("Failed to compile JavaScript expression")?;

        Ok(())
    }

    /// Evaluate the JavaScript rule against the given request
    fn execute_js_rule(
        &self,
        method: &Method,
        url: &str,
        requester_ip: &str,
    ) -> (bool, Option<String>) {
        let request_info = match RequestInfo::from_request(method, url, requester_ip) {
            Ok(info) => info,
            Err(e) => {
                debug!("Failed to parse request: {}", e);
                return (false, Some(e));
            }
        };

        debug!(
            "Executing JS rule for {} {} (host: {}, path: {})",
            request_info.method, request_info.url, request_info.host, request_info.path
        );

        // Create a new isolate and context for this evaluation
        // This ensures thread safety at the cost of some performance
        match self.create_and_execute(&request_info) {
            Ok(result) => result,
            Err(e) => {
                warn!("JavaScript execution failed: {}", e);
                (false, Some(format!("JavaScript execution failed: {}", e)))
            }
        }
    }

    fn create_and_execute(
        &self,
        request_info: &RequestInfo,
    ) -> Result<(bool, Option<String>), Box<dyn std::error::Error>> {
        let mut isolate = v8::Isolate::new(v8::CreateParams::default());
        let handle_scope = &mut v8::HandleScope::new(&mut isolate);
        let context = v8::Context::new(handle_scope, Default::default());
        let context_scope = &mut v8::ContextScope::new(handle_scope, context);

        let global = context.global(context_scope);

        // Create the 'r' object with jail-related variables
        let r_obj = v8::Object::new(context_scope);
        let r_key = v8::String::new(context_scope, "r").unwrap();
        global.set(context_scope, r_key.into(), r_obj.into());

        // Set properties on the 'r' object
        if let Some(url_str) = v8::String::new(context_scope, &request_info.url) {
            let key = v8::String::new(context_scope, "url").unwrap();
            r_obj.set(context_scope, key.into(), url_str.into());
        }

        if let Some(method_str) = v8::String::new(context_scope, &request_info.method) {
            let key = v8::String::new(context_scope, "method").unwrap();
            r_obj.set(context_scope, key.into(), method_str.into());
        }

        if let Some(scheme_str) = v8::String::new(context_scope, &request_info.scheme) {
            let key = v8::String::new(context_scope, "scheme").unwrap();
            r_obj.set(context_scope, key.into(), scheme_str.into());
        }

        if let Some(host_str) = v8::String::new(context_scope, &request_info.host) {
            let key = v8::String::new(context_scope, "host").unwrap();
            r_obj.set(context_scope, key.into(), host_str.into());
        }

        if let Some(path_str) = v8::String::new(context_scope, &request_info.path) {
            let key = v8::String::new(context_scope, "path").unwrap();
            r_obj.set(context_scope, key.into(), path_str.into());
        }

        if let Some(ip_str) = v8::String::new(context_scope, &request_info.requester_ip) {
            let key = v8::String::new(context_scope, "requester_ip").unwrap();
            r_obj.set(context_scope, key.into(), ip_str.into());
        }

        // Initialize block_message as undefined (can be set by user script)
        let block_msg_key = v8::String::new(context_scope, "block_message").unwrap();
        let undefined_val = v8::undefined(context_scope);
        r_obj.set(context_scope, block_msg_key.into(), undefined_val.into());

        // Execute the JavaScript expression directly (not wrapped in a function)
        let source =
            v8::String::new(context_scope, &self.js_code).ok_or("Failed to create V8 string")?;

        let script = v8::Script::compile(context_scope, source, None)
            .ok_or("Failed to compile JavaScript expression")?;

        // Execute the expression
        let result = script
            .run(context_scope)
            .ok_or("Expression evaluation failed")?;

        // Convert result to boolean
        let allowed = result.boolean_value(context_scope);

        // Get block_message if it was set
        let block_msg_key = v8::String::new(context_scope, "block_message").unwrap();
        let block_message = r_obj
            .get(context_scope, block_msg_key.into())
            .and_then(|v| {
                if v.is_undefined() || v.is_null() {
                    None
                } else {
                    v.to_string(context_scope)
                        .map(|s| s.to_rust_string_lossy(context_scope))
                }
            });

        debug!(
            "JS rule returned {} for {} {}",
            if allowed { "ALLOW" } else { "DENY" },
            request_info.method,
            request_info.url
        );

        if let Some(ref msg) = block_message {
            debug!("Block message: {}", msg);
        }

        Ok((allowed, block_message))
    }
}

#[async_trait]
impl RuleEngineTrait for V8JsRuleEngine {
    async fn evaluate(&self, method: Method, url: &str, requester_ip: &str) -> EvaluationResult {
        // Run the JavaScript evaluation in a blocking task to avoid
        // issues with V8's single-threaded nature
        let js_code = self.js_code.clone();
        let method_clone = method.clone();
        let url_clone = url.to_string();
        let ip_clone = requester_ip.to_string();

        let (allowed, block_message) = tokio::task::spawn_blocking(move || {
            let engine = V8JsRuleEngine { js_code };
            engine.execute_js_rule(&method_clone, &url_clone, &ip_clone)
        })
        .await
        .unwrap_or_else(|e| {
            warn!("JavaScript task panicked: {}", e);
            (false, Some("JavaScript evaluation task failed".to_string()))
        });

        if allowed {
            debug!("ALLOW: {} {} (JS rule allowed)", method, url);
            EvaluationResult::allow()
        } else {
            debug!("DENY: {} {} (JS rule denied)", method, url);
            let mut result = EvaluationResult::deny();
            if let Some(msg) = block_message {
                result = result.with_context(msg);
            }
            result
        }
    }

    fn name(&self) -> &str {
        "v8-javascript"
    }
}

// Safe cleanup is handled by V8 itself when isolates are dropped
// No explicit cleanup needed in the Drop implementation

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_js_rule_allow() {
        let js_code = r#"r.host === 'github.com'"#.to_string();

        let engine = V8JsRuleEngine::new(js_code).expect("Failed to create JS engine");

        let result = engine
            .evaluate(Method::GET, "https://github.com/test", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));
    }

    #[tokio::test]
    async fn test_js_rule_deny() {
        let js_code = r#"r.host === 'github.com'"#.to_string();

        let engine = V8JsRuleEngine::new(js_code).expect("Failed to create JS engine");

        let result = engine
            .evaluate(Method::GET, "https://example.com/test", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Deny));
    }

    #[tokio::test]
    async fn test_js_rule_with_method() {
        let js_code = r#"r.method === 'GET' && r.host === 'api.github.com'"#.to_string();

        let engine = V8JsRuleEngine::new(js_code).expect("Failed to create JS engine");

        let result = engine
            .evaluate(Method::GET, "https://api.github.com/v3", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));

        let result = engine
            .evaluate(Method::POST, "https://api.github.com/v3", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Deny));
    }

    #[tokio::test]
    async fn test_js_rule_with_path() {
        let js_code = r#"r.path.startsWith('/api/')"#.to_string();

        let engine = V8JsRuleEngine::new(js_code).expect("Failed to create JS engine");

        let result = engine
            .evaluate(Method::GET, "https://example.com/api/test", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));

        let result = engine
            .evaluate(Method::GET, "https://example.com/public/test", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Deny));
    }

    #[tokio::test]
    async fn test_js_rule_complex_logic() {
        // Using ternary operator style as mentioned in README
        let js_code = r#"(r.host.endsWith('github.com') || r.host === 'api.github.com') ? true : (r.host.includes('facebook.com') || r.host.includes('twitter.com')) ? false : (r.scheme === 'https' && r.path.startsWith('/api/')) ? true : false"#.to_string();

        let engine = V8JsRuleEngine::new(js_code).expect("Failed to create JS engine");

        // Test GitHub allow
        let result = engine
            .evaluate(Method::GET, "https://github.com/user/repo", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));

        // Test social media block
        let result = engine
            .evaluate(Method::GET, "https://facebook.com/profile", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Deny));

        // Test API allow
        let result = engine
            .evaluate(Method::POST, "https://example.com/api/data", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));

        // Test default deny
        let result = engine
            .evaluate(Method::GET, "https://example.com/public", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Deny));
    }

    #[tokio::test]
    async fn test_js_syntax_error() {
        let js_code = r#"invalid syntax here !!!"#.to_string();

        // Should fail during construction due to syntax error
        let result = V8JsRuleEngine::new(js_code);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_js_runtime_error() {
        // This will throw a runtime error because undefinedVariable is not defined
        let js_code = r#"undefinedVariable.property"#.to_string();

        let engine = V8JsRuleEngine::new(js_code).expect("Failed to create JS engine");

        // Should return deny on runtime error
        let result = engine
            .evaluate(Method::GET, "https://example.com/test", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Deny));
    }

    #[tokio::test]
    async fn test_js_block_message() {
        // Test setting a custom block message
        let js_code = r#"(r.block_message = 'Access to social media is blocked', r.host.includes('facebook.com') ? false : true)"#.to_string();

        let engine = V8JsRuleEngine::new(js_code).expect("Failed to create JS engine");

        // Should block facebook with custom message
        let result = engine
            .evaluate(Method::GET, "https://facebook.com/test", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Deny));
        assert_eq!(
            result.context,
            Some("Access to social media is blocked".to_string())
        );

        // Should allow others without message
        let result = engine
            .evaluate(Method::GET, "https://example.com/test", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));
        assert_eq!(result.context, None);
    }
}
