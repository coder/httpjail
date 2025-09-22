use crate::rules::common::RequestInfo;
use crate::rules::{EvaluationResult, RuleEngineTrait};
use async_trait::async_trait;
use hyper::Method;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

pub struct V8JsRuleEngine {
    js_code: String,
    #[allow(dead_code)]
    runtime: Arc<Mutex<()>>, // Placeholder for V8 runtime management
}

impl V8JsRuleEngine {
    pub fn new(js_code: String) -> Result<Self, Box<dyn std::error::Error>> {
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
        {
            let mut isolate = v8::Isolate::new(v8::CreateParams::default());
            let handle_scope = &mut v8::HandleScope::new(&mut isolate);
            let context = v8::Context::new(handle_scope, Default::default());
            let context_scope = &mut v8::ContextScope::new(handle_scope, context);

            let source =
                v8::String::new(context_scope, &js_code).ok_or("Failed to create V8 string")?;

            v8::Script::compile(context_scope, source, None)
                .ok_or("Failed to compile JavaScript expression")?;
        }

        info!("V8 JavaScript rule engine initialized");
        Ok(Self {
            js_code,
            runtime: Arc::new(Mutex::new(())),
        })
    }

    pub fn execute(
        &self,
        method: &Method,
        url: &str,
        requester_ip: &str,
    ) -> (bool, Option<String>) {
        let request_info = match RequestInfo::from_request(method, url, requester_ip) {
            Ok(info) => info,
            Err(e) => {
                warn!("Failed to parse request info: {}", e);
                return (false, Some("Invalid request format".to_string()));
            }
        };

        match self.create_and_execute(&request_info) {
            Ok(result) => result,
            Err(e) => {
                warn!("JavaScript execution failed: {}", e);
                (false, Some("JavaScript execution failed".to_string()))
            }
        }
    }

    /// Helper function to set a property on a V8 object
    fn set_object_property(
        context_scope: &mut v8::ContextScope<v8::HandleScope>,
        obj: v8::Local<v8::Object>,
        key: &str,
        value: &str,
    ) {
        if let Some(key_str) = v8::String::new(context_scope, key)
            && let Some(val_str) = v8::String::new(context_scope, value)
        {
            obj.set(context_scope, key_str.into(), val_str.into());
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

        // Create the 'r' object with request properties (read-only)
        let r_obj = v8::Object::new(context_scope);
        let r_key = v8::String::new(context_scope, "r").unwrap();
        global.set(context_scope, r_key.into(), r_obj.into());

        // Set properties on the 'r' object using helper function
        Self::set_object_property(context_scope, r_obj, "url", &request_info.url);
        Self::set_object_property(context_scope, r_obj, "method", &request_info.method);
        Self::set_object_property(context_scope, r_obj, "scheme", &request_info.scheme);
        Self::set_object_property(context_scope, r_obj, "host", &request_info.host);
        Self::set_object_property(context_scope, r_obj, "path", &request_info.path);
        Self::set_object_property(
            context_scope,
            r_obj,
            "requester_ip",
            &request_info.requester_ip,
        );

        // Execute the JavaScript expression
        let source =
            v8::String::new(context_scope, &self.js_code).ok_or("Failed to create V8 string")?;

        let script = v8::Script::compile(context_scope, source, None)
            .ok_or("Failed to compile JavaScript expression")?;

        // Execute the expression
        let result = script
            .run(context_scope)
            .ok_or("Expression evaluation failed")?;

        // Check if result is an object with 'allow' and/or 'deny_message'
        if result.is_object() {
            let obj = result.to_object(context_scope).unwrap();

            // Get 'deny_message' property if present
            let deny_message_key = v8::String::new(context_scope, "deny_message").unwrap();
            let deny_message = obj
                .get(context_scope, deny_message_key.into())
                .and_then(|v| {
                    if v.is_undefined() || v.is_null() {
                        None
                    } else {
                        v.to_string(context_scope)
                            .map(|s| s.to_rust_string_lossy(context_scope))
                    }
                });

            // Get 'allow' property - if not present but deny_message exists, default to false
            let allow_key = v8::String::new(context_scope, "allow").unwrap();
            let allowed = if let Some(allow_value) = obj.get(context_scope, allow_key.into()) {
                if !allow_value.is_undefined() {
                    allow_value.boolean_value(context_scope)
                } else if deny_message.is_some() {
                    // Shorthand: if only deny_message is present, it implies allow: false
                    false
                } else {
                    // Default to false if neither is properly set
                    false
                }
            } else if deny_message.is_some() {
                // Shorthand: if only deny_message is present, it implies allow: false
                false
            } else {
                // Default to false if neither is properly set
                false
            };

            debug!(
                "JS rule returned object: allow={} for {} {}",
                allowed, request_info.method, request_info.url
            );

            if let Some(ref msg) = deny_message {
                debug!("Deny message: {}", msg);
            }

            // Only return the message if the request is denied
            let message = if !allowed { deny_message } else { None };

            Ok((allowed, message))
        } else {
            // Result is not an object, treat as boolean
            let allowed = result.boolean_value(context_scope);

            debug!(
                "JS rule returned {} for {} {}",
                if allowed { "ALLOW" } else { "DENY" },
                request_info.method,
                request_info.url
            );

            Ok((allowed, None))
        }
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

        let (allowed, context) = tokio::task::spawn_blocking(move || {
            let engine = V8JsRuleEngine::new(js_code).unwrap();
            engine.execute(&method_clone, &url_clone, &ip_clone)
        })
        .await
        .unwrap_or_else(|e| {
            warn!("Failed to spawn V8 evaluation task: {}", e);
            (false, Some("Evaluation failed".to_string()))
        });

        if allowed {
            let mut result = EvaluationResult::allow();
            if let Some(ctx) = context {
                result = result.with_context(ctx);
            }
            result
        } else {
            let mut result = EvaluationResult::deny();
            if let Some(ctx) = context {
                result = result.with_context(ctx);
            }
            result
        }
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
}
