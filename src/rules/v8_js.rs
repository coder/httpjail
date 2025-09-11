#[cfg(test)]
use super::Action;
use super::{EvaluationResult, RuleEngineTrait};
use async_trait::async_trait;
use hyper::Method;
use tracing::{debug, warn};
use url::Url;

/// V8 JavaScript rule engine that creates a fresh context for each evaluation
/// to ensure thread safety. While this is less performant than reusing contexts,
/// it's necessary because V8 isolates are not Send + Sync.
pub struct V8JsRuleEngine {
    js_code: String,
}

static V8_INIT: std::sync::Once = std::sync::Once::new();

impl V8JsRuleEngine {
    /// Creates a new V8 JavaScript rule engine
    ///
    /// # Arguments
    /// * `js_code` - JavaScript code that should return a boolean value
    ///   The code has access to global variables:
    ///   - `url` - Full URL string
    ///   - `method` - HTTP method string
    ///   - `scheme` - URL scheme (http/https)
    ///   - `host` - Host part of URL
    ///   - `path` - Path part of URL
    pub fn new(js_code: String) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Initialize V8 platform (this should only be done once per process)
        V8_INIT.call_once(|| {
            let platform = v8::new_default_platform(0, false).make_shared();
            v8::V8::initialize_platform(platform);
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

        // Wrap the user code in a function that we can call
        let wrapped_code = format!("(function() {{ {} }})", js_code);
        let wrapped_source = v8::String::new(context_scope, &wrapped_code)
            .ok_or("Failed to create V8 string from JavaScript code")?;

        v8::Script::compile(context_scope, wrapped_source, None)
            .ok_or("Failed to compile JavaScript code")?;

        Ok(())
    }

    /// Evaluate the JavaScript rule against the given request
    fn execute_js_rule(&self, method: &Method, url: &str) -> (bool, String) {
        let parsed_url = match Url::parse(url) {
            Ok(u) => u,
            Err(e) => {
                debug!("Failed to parse URL '{}': {}", url, e);
                return (false, format!("Failed to parse URL: {}", e));
            }
        };

        let scheme = parsed_url.scheme();
        let host = parsed_url.host_str().unwrap_or("");
        let path = parsed_url.path();

        debug!(
            "Executing JS rule for {} {} (host: {}, path: {})",
            method, url, host, path
        );

        // Create a new isolate and context for this evaluation
        // This ensures thread safety at the cost of some performance
        match self.create_and_execute(method.as_str(), url, scheme, host, path) {
            Ok(result) => result,
            Err(e) => {
                warn!("JavaScript execution failed: {}", e);
                (false, format!("JavaScript execution failed: {}", e))
            }
        }
    }

    fn create_and_execute(
        &self,
        method: &str,
        url: &str,
        scheme: &str,
        host: &str,
        path: &str,
    ) -> Result<(bool, String), Box<dyn std::error::Error>> {
        let mut isolate = v8::Isolate::new(v8::CreateParams::default());
        let handle_scope = &mut v8::HandleScope::new(&mut isolate);
        let context = v8::Context::new(handle_scope, Default::default());
        let context_scope = &mut v8::ContextScope::new(handle_scope, context);

        // Set global variables that the JavaScript code can access
        let global = context.global(context_scope);

        // Set the global variables that mirror the environment variables from script engine
        if let Some(url_str) = v8::String::new(context_scope, url) {
            let key = v8::String::new(context_scope, "url").unwrap();
            global.set(context_scope, key.into(), url_str.into());
        }

        if let Some(method_str) = v8::String::new(context_scope, method) {
            let key = v8::String::new(context_scope, "method").unwrap();
            global.set(context_scope, key.into(), method_str.into());
        }

        if let Some(scheme_str) = v8::String::new(context_scope, scheme) {
            let key = v8::String::new(context_scope, "scheme").unwrap();
            global.set(context_scope, key.into(), scheme_str.into());
        }

        if let Some(host_str) = v8::String::new(context_scope, host) {
            let key = v8::String::new(context_scope, "host").unwrap();
            global.set(context_scope, key.into(), host_str.into());
        }

        if let Some(path_str) = v8::String::new(context_scope, path) {
            let key = v8::String::new(context_scope, "path").unwrap();
            global.set(context_scope, key.into(), path_str.into());
        }

        // Compile and execute the JavaScript code
        let wrapped_code = format!("(function() {{ {} }})", self.js_code);
        let wrapped_source = v8::String::new(context_scope, &wrapped_code)
            .ok_or("Failed to create wrapped V8 string")?;

        let script = v8::Script::compile(context_scope, wrapped_source, None)
            .ok_or("Failed to compile JavaScript code")?;

        // Execute the script to get the function
        let result = script.run(context_scope).ok_or("Script execution failed")?;

        // Call the function (the script returns a function)
        let function: v8::Local<v8::Function> = result
            .try_into()
            .map_err(|_| "Script did not return a function")?;

        let undefined = v8::undefined(context_scope);
        let call_result = function
            .call(context_scope, undefined.into(), &[])
            .ok_or("Function call failed")?;

        // Convert result to boolean
        let allowed = call_result.boolean_value(context_scope);
        let context_str = call_result
            .to_string(context_scope)
            .map(|s| s.to_rust_string_lossy(context_scope))
            .unwrap_or_default();

        debug!(
            "JS rule returned {} for {} {} (result: {})",
            if allowed { "ALLOW" } else { "DENY" },
            method,
            url,
            context_str
        );

        Ok((allowed, context_str))
    }
}

#[async_trait]
impl RuleEngineTrait for V8JsRuleEngine {
    async fn evaluate(&self, method: Method, url: &str) -> EvaluationResult {
        // Run the JavaScript evaluation in a blocking task to avoid
        // issues with V8's single-threaded nature
        let js_code = self.js_code.clone();
        let method_clone = method.clone();
        let url_clone = url.to_string();

        let (allowed, context) = tokio::task::spawn_blocking(move || {
            let engine = V8JsRuleEngine { js_code };
            engine.execute_js_rule(&method_clone, &url_clone)
        })
        .await
        .unwrap_or_else(|e| {
            warn!("JavaScript task panicked: {}", e);
            (false, "JavaScript evaluation task failed".to_string())
        });

        if allowed {
            debug!("ALLOW: {} {} (JS rule allowed)", method, url);
            let mut result = EvaluationResult::allow();
            if !context.is_empty() {
                result = result.with_context(context);
            }
            result
        } else {
            debug!("DENY: {} {} (JS rule denied)", method, url);
            let mut result = EvaluationResult::deny();
            if !context.is_empty() {
                result = result.with_context(context);
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
        let js_code = r#"
            return host === 'github.com';
        "#
        .to_string();

        let engine = V8JsRuleEngine::new(js_code).expect("Failed to create JS engine");

        let result = engine
            .evaluate(Method::GET, "https://github.com/test")
            .await;
        assert!(matches!(result.action, Action::Allow));
    }

    #[tokio::test]
    async fn test_js_rule_deny() {
        let js_code = r#"
            return host === 'github.com';
        "#
        .to_string();

        let engine = V8JsRuleEngine::new(js_code).expect("Failed to create JS engine");

        let result = engine
            .evaluate(Method::GET, "https://example.com/test")
            .await;
        assert!(matches!(result.action, Action::Deny));
    }

    #[tokio::test]
    async fn test_js_rule_with_method() {
        let js_code = r#"
            return method === 'GET' && host === 'api.github.com';
        "#
        .to_string();

        let engine = V8JsRuleEngine::new(js_code).expect("Failed to create JS engine");

        let result = engine
            .evaluate(Method::GET, "https://api.github.com/v3")
            .await;
        assert!(matches!(result.action, Action::Allow));

        let result = engine
            .evaluate(Method::POST, "https://api.github.com/v3")
            .await;
        assert!(matches!(result.action, Action::Deny));
    }

    #[tokio::test]
    async fn test_js_rule_with_path() {
        let js_code = r#"
            return path.startsWith('/api/');
        "#
        .to_string();

        let engine = V8JsRuleEngine::new(js_code).expect("Failed to create JS engine");

        let result = engine
            .evaluate(Method::GET, "https://example.com/api/test")
            .await;
        assert!(matches!(result.action, Action::Allow));

        let result = engine
            .evaluate(Method::GET, "https://example.com/public/test")
            .await;
        assert!(matches!(result.action, Action::Deny));
    }

    #[tokio::test]
    async fn test_js_rule_complex_logic() {
        let js_code = r#"
            // Allow GitHub and safe domains
            if (host.endsWith('github.com') || host === 'api.github.com') {
                return true;
            }
            
            // Block social media
            if (host.includes('facebook.com') || host.includes('twitter.com')) {
                return false;
            }
            
            // Allow HTTPS API calls
            if (scheme === 'https' && path.startsWith('/api/')) {
                return true;
            }
            
            // Default deny
            return false;
        "#
        .to_string();

        let engine = V8JsRuleEngine::new(js_code).expect("Failed to create JS engine");

        // Test GitHub allow
        let result = engine
            .evaluate(Method::GET, "https://github.com/user/repo")
            .await;
        assert!(matches!(result.action, Action::Allow));

        // Test social media block
        let result = engine
            .evaluate(Method::GET, "https://facebook.com/profile")
            .await;
        assert!(matches!(result.action, Action::Deny));

        // Test API allow
        let result = engine
            .evaluate(Method::POST, "https://example.com/api/data")
            .await;
        assert!(matches!(result.action, Action::Allow));

        // Test default deny
        let result = engine
            .evaluate(Method::GET, "https://example.com/public")
            .await;
        assert!(matches!(result.action, Action::Deny));
    }

    #[tokio::test]
    async fn test_js_syntax_error() {
        let js_code = r#"
            return invalid syntax here !!!
        "#
        .to_string();

        // Should fail during construction due to syntax error
        let result = V8JsRuleEngine::new(js_code);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_js_runtime_error() {
        let js_code = r#"
            throw new Error('Runtime error');
            return true;
        "#
        .to_string();

        let engine = V8JsRuleEngine::new(js_code).expect("Failed to create JS engine");

        // Should return deny on runtime error
        let result = engine
            .evaluate(Method::GET, "https://example.com/test")
            .await;
        assert!(matches!(result.action, Action::Deny));
    }
}
