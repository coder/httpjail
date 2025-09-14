pub mod script;
pub mod v8_js;

use crate::request_log::{LoggingRuleEngine, RequestLogger};
use async_trait::async_trait;
use hyper::Method;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub struct EvaluationResult {
    pub action: Action,
    pub context: Option<String>,
    pub request_id: String,
}

impl EvaluationResult {
    pub fn allow() -> Self {
        Self {
            action: Action::Allow,
            context: None,
            request_id: String::new(),
        }
    }

    pub fn deny() -> Self {
        Self {
            action: Action::Deny,
            context: None,
            request_id: String::new(),
        }
    }

    pub fn with_context(mut self, context: String) -> Self {
        self.context = Some(context);
        self
    }

    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = request_id;
        self
    }
}

#[async_trait]
pub trait RuleEngineTrait: Send + Sync {
    async fn evaluate(&self, method: Method, url: &str, requester_ip: &str) -> EvaluationResult;

    fn name(&self) -> &str;
}

#[derive(Clone)]
pub struct RuleEngine {
    inner: Arc<dyn RuleEngineTrait>,
    logging_engine: Option<Arc<LoggingRuleEngine>>,
}

impl RuleEngine {
    pub fn from_trait(engine: Box<dyn RuleEngineTrait>, logger: Arc<dyn RequestLogger>) -> Self {
        let logging_engine = Arc::new(LoggingRuleEngine::new(engine, logger));
        RuleEngine {
            inner: Arc::clone(&logging_engine) as Arc<dyn RuleEngineTrait>,
            logging_engine: Some(logging_engine),
        }
    }

    /// Get body logging configuration if enabled
    pub fn get_body_log_config(
        &self,
        request_id: String,
    ) -> Option<crate::body_logger::BodyLogConfig> {
        self.logging_engine
            .as_ref()?
            .get_body_log_config(request_id)
    }

    pub async fn evaluate(&self, method: Method, url: &str) -> Action {
        self.inner.evaluate(method, url, "127.0.0.1").await.action
    }

    pub async fn evaluate_with_context(&self, method: Method, url: &str) -> EvaluationResult {
        self.inner.evaluate(method, url, "127.0.0.1").await
    }

    pub async fn evaluate_with_ip(&self, method: Method, url: &str, requester_ip: &str) -> Action {
        self.inner.evaluate(method, url, requester_ip).await.action
    }

    pub async fn evaluate_with_context_and_ip(
        &self,
        method: Method,
        url: &str,
        requester_ip: &str,
    ) -> EvaluationResult {
        self.inner.evaluate(method, url, requester_ip).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request_log::FileRequestLogger;
    use crate::rules::v8_js::V8JsRuleEngine;
    use std::fs::OpenOptions;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn test_request_logging() {
        let engine = V8JsRuleEngine::new("true".to_string()).unwrap();
        let log_file = tempfile::NamedTempFile::new().unwrap();
        let file = OpenOptions::new()
            .append(true)
            .open(log_file.path())
            .unwrap();
        let logger = Arc::new(FileRequestLogger::new(Arc::new(Mutex::new(file)), false));
        let engine = RuleEngine::from_trait(Box::new(engine), logger);

        engine.evaluate(Method::GET, "https://example.com").await;

        let contents = std::fs::read_to_string(log_file.path()).unwrap();
        assert!(contents.contains("+ GET https://example.com"));
    }

    #[tokio::test]
    async fn test_request_logging_denied() {
        let engine = V8JsRuleEngine::new("false".to_string()).unwrap();
        let log_file = tempfile::NamedTempFile::new().unwrap();
        let file = OpenOptions::new()
            .append(true)
            .open(log_file.path())
            .unwrap();
        let logger = Arc::new(FileRequestLogger::new(Arc::new(Mutex::new(file)), false));
        let engine = RuleEngine::from_trait(Box::new(engine), logger);

        engine.evaluate(Method::GET, "https://blocked.com").await;

        let contents = std::fs::read_to_string(log_file.path()).unwrap();
        assert!(contents.contains("- GET https://blocked.com"));
    }
}
