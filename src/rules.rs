pub mod pattern;
pub mod script;
pub mod v8_js;

use async_trait::async_trait;
use chrono::{SecondsFormat, Utc};
use hyper::Method;
pub use pattern::{PatternRuleEngine, Rule};
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
    async fn evaluate(&self, method: Method, url: &str) -> EvaluationResult;

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
    async fn evaluate(&self, method: Method, url: &str) -> EvaluationResult {
        let result = self.engine.evaluate(method.clone(), url).await;

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
    pub fn new(rules: Vec<Rule>, request_log: Option<Arc<Mutex<File>>>) -> Self {
        let pattern_engine = Box::new(PatternRuleEngine::new(rules));
        let engine: Box<dyn RuleEngineTrait> = if request_log.is_some() {
            Box::new(LoggingRuleEngine::new(pattern_engine, request_log))
        } else {
            pattern_engine
        };

        RuleEngine {
            inner: Arc::from(engine),
        }
    }

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
        self.inner.evaluate(method, url).await.action
    }

    pub async fn evaluate_with_context(&self, method: Method, url: &str) -> EvaluationResult {
        self.inner.evaluate(method, url).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_rule_matching() {
        let rule = Rule::new(Action::Allow, r"github\.com").unwrap();
        assert!(rule.matches(Method::GET, "https://github.com/user/repo"));
        assert!(rule.matches(Method::POST, "http://api.github.com/v3/repos"));
        assert!(!rule.matches(Method::GET, "https://gitlab.com/user/repo"));
    }

    #[test]
    fn test_rule_with_methods() {
        let rule = Rule::new(Action::Allow, r"api\.example\.com")
            .unwrap()
            .with_methods(vec![Method::GET, Method::HEAD]);

        assert!(rule.matches(Method::GET, "https://api.example.com/users"));
        assert!(rule.matches(Method::HEAD, "https://api.example.com/users"));
        assert!(!rule.matches(Method::POST, "https://api.example.com/users"));
        assert!(!rule.matches(Method::DELETE, "https://api.example.com/users"));
    }

    #[tokio::test]
    async fn test_rule_engine() {
        let rules = vec![
            Rule::new(Action::Allow, r"github\.com").unwrap(),
            Rule::new(Action::Deny, r"telemetry").unwrap(),
            Rule::new(Action::Deny, r".*").unwrap(),
        ];

        let engine = RuleEngine::new(rules, None);

        assert!(matches!(
            engine.evaluate(Method::GET, "https://github.com/api").await,
            Action::Allow
        ));

        assert!(matches!(
            engine
                .evaluate(Method::POST, "https://telemetry.example.com")
                .await,
            Action::Deny
        ));

        assert!(matches!(
            engine.evaluate(Method::GET, "https://example.com").await,
            Action::Deny
        ));
    }

    #[tokio::test]
    async fn test_method_specific_rules() {
        let rules = vec![
            Rule::new(Action::Allow, r"api\.example\.com")
                .unwrap()
                .with_methods(vec![Method::GET]),
            Rule::new(Action::Deny, r".*").unwrap(),
        ];

        let engine = RuleEngine::new(rules, None);

        assert!(matches!(
            engine
                .evaluate(Method::GET, "https://api.example.com/data")
                .await,
            Action::Allow
        ));

        assert!(matches!(
            engine
                .evaluate(Method::POST, "https://api.example.com/data")
                .await,
            Action::Deny
        ));
    }

    #[tokio::test]
    async fn test_request_logging() {
        use std::fs::OpenOptions;

        let rules = vec![Rule::new(Action::Allow, r".*").unwrap()];
        let log_file = tempfile::NamedTempFile::new().unwrap();
        let file = OpenOptions::new()
            .append(true)
            .open(log_file.path())
            .unwrap();
        let engine = RuleEngine::new(rules, Some(Arc::new(Mutex::new(file))));

        engine.evaluate(Method::GET, "https://example.com").await;

        let contents = std::fs::read_to_string(log_file.path()).unwrap();
        assert!(contents.contains("+ GET https://example.com"));
    }

    #[tokio::test]
    async fn test_request_logging_denied() {
        use std::fs::OpenOptions;

        let rules = vec![Rule::new(Action::Deny, r".*").unwrap()];
        let log_file = tempfile::NamedTempFile::new().unwrap();
        let file = OpenOptions::new()
            .append(true)
            .open(log_file.path())
            .unwrap();
        let engine = RuleEngine::new(rules, Some(Arc::new(Mutex::new(file))));

        engine.evaluate(Method::GET, "https://blocked.com").await;

        let contents = std::fs::read_to_string(log_file.path()).unwrap();
        assert!(contents.contains("- GET https://blocked.com"));
    }

    #[tokio::test]
    async fn test_default_deny_with_no_rules() {
        let engine = RuleEngine::new(vec![], None);

        assert!(matches!(
            engine.evaluate(Method::GET, "https://example.com").await,
            Action::Deny
        ));
    }
}
