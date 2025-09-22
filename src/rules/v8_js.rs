use crate::rules::common::{RequestInfo, RuleResponse};
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

    fn create_and_execute(
        &self,
        request_info: &RequestInfo,
    ) -> Result<(bool, Option<String>), Box<dyn std::error::Error>> {
        let mut isolate = v8::Isolate::new(v8::CreateParams::default());
        let handle_scope = &mut v8::HandleScope::new(&mut isolate);
        let context = v8::Context::new(handle_scope, Default::default());
        let context_scope = &mut v8::ContextScope::new(handle_scope, context);

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
        let source =
            v8::String::new(context_scope, &self.js_code).ok_or("Failed to create V8 string")?;

        let script = v8::Script::compile(context_scope, source, None)
            .ok_or("Failed to compile JavaScript expression")?;

        // Execute the expression
        let result = script
            .run(context_scope)
            .ok_or("Expression evaluation failed")?;

        // Convert the V8 result to a JSON string for consistent parsing
        // This ensures perfect parity with the proc engine response handling
        let response_str = if result.is_object() && !result.is_null() && !result.is_undefined() {
            // It's an object - stringify it to JSON
            let json_stringify_key = v8::String::new(context_scope, "JSON").unwrap();
            let stringify_key = v8::String::new(context_scope, "stringify").unwrap();

            let json_obj = global
                .get(context_scope, json_stringify_key.into())
                .ok_or("Failed to get JSON object")?
                .to_object(context_scope)
                .ok_or("JSON is not an object")?;

            let stringify_fn = json_obj
                .get(context_scope, stringify_key.into())
                .ok_or("Failed to get JSON.stringify")?;

            let stringify_fn = v8::Local::<v8::Function>::try_from(stringify_fn)
                .map_err(|_| "JSON.stringify is not a function")?;

            // Call JSON.stringify on the result
            let json_str = stringify_fn
                .call(context_scope, json_obj.into(), &[result])
                .ok_or("Failed to stringify result")?;

            json_str
                .to_string(context_scope)
                .map(|s| s.to_rust_string_lossy(context_scope))
                .unwrap_or_else(|| "false".to_string())
        } else if result.is_boolean() {
            // Simple boolean result
            if result.boolean_value(context_scope) {
                "true".to_string()
            } else {
                "false".to_string()
            }
        } else if result.is_string() {
            // String result - treat as deny message
            result
                .to_string(context_scope)
                .map(|s| s.to_rust_string_lossy(context_scope))
                .unwrap_or_else(|| "false".to_string())
        } else {
            // Other types - default to false
            "false".to_string()
        };

        // Use the common RuleResponse parser - exact same logic as proc engine
        let rule_response = RuleResponse::from_string(&response_str);
        let (allowed, message) = rule_response.to_evaluation_result();

        debug!(
            "JS rule returned {} for {} {}",
            if allowed { "ALLOW" } else { "DENY" },
            request_info.method,
            request_info.url
        );

        if let Some(ref msg) = message {
            debug!("Deny message: {}", msg);
        }

        Ok((allowed, message))
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
    async fn test_v8_js_json_parity() {
        // This test verifies that the V8 engine receives the exact same JSON
        // object structure as the proc engine (ensuring perfect parity)
        let engine = V8JsRuleEngine::new(
            r#"
            // Return the exact JSON we received to verify structure
            ({deny_message: JSON.stringify(r)})
            "#
            .to_string(),
        )
        .unwrap();

        let result = engine
            .evaluate(Method::POST, "https://example.com/test?foo=bar", "10.0.0.1")
            .await;

        // The deny message will contain the stringified JSON
        assert!(matches!(result.action, crate::rules::Action::Deny));

        if let Some(ref json_str) = result.context {
            let parsed: serde_json::Value = serde_json::from_str(json_str).unwrap();

            // Verify all expected fields are present with the exact same values
            // that would be sent to the proc engine
            assert_eq!(parsed["url"], "https://example.com/test?foo=bar");
            assert_eq!(parsed["method"], "POST");
            assert_eq!(parsed["scheme"], "https");
            assert_eq!(parsed["host"], "example.com");
            assert_eq!(parsed["path"], "/test");
            assert_eq!(parsed["requester_ip"], "10.0.0.1");

            // Verify no extra fields exist (exact same structure as RequestInfo)
            assert_eq!(parsed.as_object().unwrap().len(), 6);
        } else {
            panic!("Expected JSON in context");
        }
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
