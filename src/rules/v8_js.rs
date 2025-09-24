use crate::rules::common::{RequestInfo, RuleResponse};
use crate::rules::{EvaluationResult, RuleEngineTrait};
use async_trait::async_trait;
use hyper::Method;
use std::cell::RefCell;
use std::sync::Arc;
use tracing::{debug, info, warn};

thread_local! {
    /// Thread-local storage for V8 isolate and compiled script
    /// This avoids the overhead of creating a new isolate for each request
    static ISOLATE_CACHE: RefCell<Option<IsolateCache>> = RefCell::new(None);
}

/// Cached V8 isolate with compiled script
struct IsolateCache {
    isolate: v8::OwnedIsolate,
    js_code: String,
}

impl IsolateCache {
    fn new(js_code: String) -> Result<Self, Box<dyn std::error::Error>> {
        let mut isolate = v8::Isolate::new(v8::CreateParams::default());

        // Validate the script compiles
        {
            let handle_scope = &mut v8::HandleScope::new(&mut isolate);
            let context = v8::Context::new(handle_scope, Default::default());
            let context_scope = &mut v8::ContextScope::new(handle_scope, context);

            let source =
                v8::String::new(context_scope, &js_code).ok_or("Failed to create V8 string")?;

            v8::Script::compile(context_scope, source, None)
                .ok_or("Failed to compile JavaScript expression")?;
        }

        Ok(Self { isolate, js_code })
    }

    fn execute(
        &mut self,
        request_info: &RequestInfo,
    ) -> Result<(bool, Option<String>), Box<dyn std::error::Error>> {
        let handle_scope = &mut v8::HandleScope::new(&mut self.isolate);
        let context = v8::Context::new(handle_scope, Default::default());
        let context_scope = &mut v8::ContextScope::new(handle_scope, context);

        let global = context.global(context_scope);

        // Serialize RequestInfo to JSON
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

        // Compile and execute the JavaScript expression
        let source =
            v8::String::new(context_scope, &self.js_code).ok_or("Failed to create V8 string")?;

        let script = v8::Script::compile(context_scope, source, None)
            .ok_or("Failed to compile JavaScript expression")?;

        let result = script
            .run(context_scope)
            .ok_or("Expression evaluation failed")?;

        // Convert the V8 result to a response string
        let response_str = Self::value_to_response_string(context_scope, global, result)?;

        // Use the common RuleResponse parser
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
}

pub struct V8JsRuleEngine {
    js_code: Arc<String>,
}

impl V8JsRuleEngine {
    pub fn new(js_code: String) -> Result<Self, Box<dyn std::error::Error>> {
        // Initialize V8 platform once
        Self::init_v8_platform();

        // Validate the JavaScript compiles
        let _cache = IsolateCache::new(js_code.clone())?;

        info!("V8 JavaScript rule engine initialized");
        Ok(Self {
            js_code: Arc::new(js_code),
        })
    }

    fn init_v8_platform() {
        use std::sync::OnceLock;
        static V8_PLATFORM: OnceLock<v8::SharedRef<v8::Platform>> = OnceLock::new();

        V8_PLATFORM.get_or_init(|| {
            let platform = v8::new_default_platform(0, false).make_shared();
            v8::V8::initialize_platform(platform.clone());
            v8::V8::initialize();
            platform
        });
    }
}

fn execute_with_cache(
    js_code: &str,
    request_info: RequestInfo,
) -> Result<(bool, Option<String>), Box<dyn std::error::Error>> {
    ISOLATE_CACHE.with(|cache| {
        let mut cache_ref = cache.borrow_mut();

        // Check if we have a cache and if the code matches
        let needs_new_cache = match cache_ref.as_ref() {
            Some(existing) => existing.js_code != js_code,
            None => true,
        };

        // Create new cache if needed
        if needs_new_cache {
            *cache_ref = Some(IsolateCache::new(js_code.to_string())?);
        }

        // Execute with the cached isolate
        cache_ref.as_mut().unwrap().execute(&request_info)
    })
}

#[async_trait]
impl RuleEngineTrait for V8JsRuleEngine {
    async fn evaluate(&self, method: Method, url: &str, requester_ip: &str) -> EvaluationResult {
        let request_info = match RequestInfo::from_request(&method, url, requester_ip) {
            Ok(info) => info,
            Err(e) => {
                warn!("Failed to parse request info: {}", e);
                return EvaluationResult::deny().with_context("Invalid request format".to_string());
            }
        };

        let js_code = self.js_code.clone();

        // Use spawn_blocking to run V8 on a thread pool
        // Each thread will cache its own isolate
        let (allowed, context) = tokio::task::spawn_blocking(move || {
            execute_with_cache(&js_code, request_info).unwrap_or_else(|e| {
                warn!("JavaScript execution failed: {}", e);
                (false, Some("JavaScript execution failed".to_string()))
            })
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
    use crate::rules::Action;

    #[tokio::test]
    async fn test_simple_allow() {
        let engine = V8JsRuleEngine::new("true".to_string()).unwrap();
        let result = engine
            .evaluate(Method::GET, "https://example.com/test", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));
    }

    #[tokio::test]
    async fn test_simple_deny() {
        let engine = V8JsRuleEngine::new("false".to_string()).unwrap();
        let result = engine
            .evaluate(Method::GET, "https://example.com/test", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Deny));
    }

    #[tokio::test]
    async fn test_request_field_access() {
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
                "https://example.com",
                true,
            ),
            (
                "r.host === 'github.com'",
                Method::GET,
                "https://example.com",
                false,
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
        let js_code = r#"
            // Allow GitHub and GitLab
            const allowed_hosts = ['github.com', 'gitlab.com'];
            
            // Block certain paths
            const blocked_paths = ['/admin', '/internal'];
            
            // Check if host is allowed
            if (!allowed_hosts.includes(r.host)) {
                ({ allow: false, deny_message: `Host ${r.host} not in allowlist` })
            } else if (blocked_paths.some(p => r.path.startsWith(p))) {
                ({ allow: false, deny_message: `Path ${r.path} is restricted` })
            } else {
                true
            }
        "#;

        let engine = V8JsRuleEngine::new(js_code.to_string()).unwrap();

        // Test allowed host and path
        let result = engine
            .evaluate(Method::GET, "https://github.com/user/repo", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Allow));

        // Test blocked host
        let result = engine
            .evaluate(Method::GET, "https://example.com/api", "127.0.0.1")
            .await;
        assert!(matches!(result.action, Action::Deny));
        assert_eq!(
            result.context,
            Some("Host example.com not in allowlist".to_string())
        );

        // Test blocked path on allowed host
        let result = engine
            .evaluate(
                Method::GET,
                "https://github.com/admin/settings",
                "127.0.0.1",
            )
            .await;
        assert!(matches!(result.action, Action::Deny));
        assert_eq!(
            result.context,
            Some("Path /admin/settings is restricted".to_string())
        );
    }

    #[tokio::test]
    async fn test_concurrent_evaluation() {
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
            let url = format!("https://{}/path", host);

            tasks.push(tokio::spawn(async move {
                let result = engine_clone.evaluate(Method::GET, &url, "127.0.0.1").await;
                (i % 2 == 0, matches!(result.action, Action::Allow))
            }));
        }

        for task in tasks {
            let (should_allow, did_allow) = task.await.unwrap();
            assert_eq!(should_allow, did_allow);
        }
    }
}
