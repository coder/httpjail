pub mod script;
pub mod v8_js;

use async_trait::async_trait;
use chrono::{SecondsFormat, Utc};
use hyper::Method;
use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tracing::warn;

#[derive(Debug, Clone)]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub struct EvaluationResult {
    pub action: Action,
    pub context: Option<String>,
}

impl EvaluationResult {
    pub fn allow() -> Self {
        Self {
            action: Action::Allow,
            context: None,
        }
    }

    pub fn deny() -> Self {
        Self {
            action: Action::Deny,
            context: None,
        }
    }

    pub fn with_context(mut self, context: String) -> Self {
        self.context = Some(context);
        self
    }
}

#[async_trait]
pub trait RuleEngineTrait: Send + Sync {
    async fn evaluate(&self, method: Method, url: &str, requester_ip: &str) -> EvaluationResult;

    fn name(&self) -> &str;
}

pub struct LoggingRuleEngine {
    engine: Box<dyn RuleEngineTrait>,
    request_log: Option<Arc<Mutex<File>>>,
}

impl LoggingRuleEngine {
    pub fn new(engine: Box<dyn RuleEngineTrait>, request_log: Option<Arc<Mutex<File>>>) -> Self {
        Self {
            engine,
            request_log,
        }
    }
}

#[async_trait]
impl RuleEngineTrait for LoggingRuleEngine {
    async fn evaluate(&self, method: Method, url: &str, requester_ip: &str) -> EvaluationResult {
        let result = self
            .engine
            .evaluate(method.clone(), url, requester_ip)
            .await;

        if let Some(log) = &self.request_log
            && let Ok(mut file) = log.lock()
        {
            let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
            let status = match &result.action {
                Action::Allow => '+',
                Action::Deny => '-',
            };
            if let Err(e) = writeln!(file, "{} {} {} {}", timestamp, status, method, url) {
                warn!("Failed to write to request log: {}", e);
            }
        }

        result
    }

    fn name(&self) -> &str {
        self.engine.name()
    }
}

#[derive(Clone)]
pub struct RuleEngine {
    inner: Arc<dyn RuleEngineTrait>,
}

impl RuleEngine {
    pub fn from_trait(
        engine: Box<dyn RuleEngineTrait>,
        request_log: Option<Arc<Mutex<File>>>,
    ) -> Self {
        let engine: Box<dyn RuleEngineTrait> = if request_log.is_some() {
            Box::new(LoggingRuleEngine::new(engine, request_log))
        } else {
            engine
        };
        RuleEngine {
            inner: Arc::from(engine),
        }
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
        let engine = RuleEngine::from_trait(Box::new(engine), Some(Arc::new(Mutex::new(file))));

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
        let engine = RuleEngine::from_trait(Box::new(engine), Some(Arc::new(Mutex::new(file))));

        engine.evaluate(Method::GET, "https://blocked.com").await;

        let contents = std::fs::read_to_string(log_file.path()).unwrap();
        assert!(contents.contains("- GET https://blocked.com"));
    }
}
