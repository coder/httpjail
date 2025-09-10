use anyhow::Result;
use chrono::{SecondsFormat, Utc};
use hyper::Method;
use regex::Regex;
use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub enum Action {
    Allow,
    Deny,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub action: Action,
    pub pattern: Regex,
    pub methods: Option<HashSet<Method>>, // None means all methods
}

impl Rule {
    pub fn new(action: Action, pattern: &str) -> Result<Self> {
        Ok(Rule {
            action,
            pattern: Regex::new(pattern)?,
            methods: None, // Default to matching all methods
        })
    }

    pub fn with_methods(mut self, methods: Vec<Method>) -> Self {
        self.methods = Some(methods.into_iter().collect());
        self
    }

    pub fn matches(&self, method: Method, url: &str) -> bool {
        // Check if URL matches
        if !self.pattern.is_match(url) {
            return false;
        }

        // Check if method matches (if methods are specified)
        match &self.methods {
            None => true, // No method filter means match all methods
            Some(methods) => methods.contains(&method),
        }
    }
}

#[derive(Clone)]
pub struct RuleEngine {
    pub rules: Vec<Rule>,
    pub request_log: Option<Arc<Mutex<File>>>,
}

impl RuleEngine {
    pub fn new(rules: Vec<Rule>, request_log: Option<Arc<Mutex<File>>>) -> Self {
        RuleEngine { rules, request_log }
    }

    pub fn evaluate(&self, method: Method, url: &str) -> Action {
        let mut action = Action::Deny;
        let mut matched = false;

        for rule in &self.rules {
            if rule.matches(method.clone(), url) {
                matched = true;
                match &rule.action {
                    Action::Allow => {
                        info!(
                            "ALLOW: {} {} (matched: {:?})",
                            method,
                            url,
                            rule.pattern.as_str()
                        );
                        action = Action::Allow;
                    }
                    Action::Deny => {
                        warn!(
                            "DENY: {} {} (matched: {:?})",
                            method,
                            url,
                            rule.pattern.as_str()
                        );
                        action = Action::Deny;
                    }
                }
                break;
            }
        }

        if !matched {
            warn!("DENY: {} {} (no matching rules)", method, url);
            action = Action::Deny;
        }

        if let Some(log) = &self.request_log
            && let Ok(mut file) = log.lock()
        {
            let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
            let status = match &action {
                Action::Allow => '+',
                Action::Deny => '-',
            };
            if let Err(e) = writeln!(file, "{} {} {} {}", timestamp, status, method, url) {
                warn!("Failed to write to request log: {}", e);
            }
        }

        action
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

    #[test]
    fn test_rule_engine() {
        let rules = vec![
            Rule::new(Action::Allow, r"github\.com").unwrap(),
            Rule::new(Action::Deny, r"telemetry").unwrap(),
            Rule::new(Action::Deny, r".*").unwrap(),
        ];

        let engine = RuleEngine::new(rules, None);

        // Test allow rule
        assert!(matches!(
            engine.evaluate(Method::GET, "https://github.com/api"),
            Action::Allow
        ));

        // Test deny rule
        assert!(matches!(
            engine.evaluate(Method::POST, "https://telemetry.example.com"),
            Action::Deny
        ));

        // Test default deny
        assert!(matches!(
            engine.evaluate(Method::GET, "https://example.com"),
            Action::Deny
        ));
    }

    #[test]
    fn test_method_specific_rules() {
        let rules = vec![
            Rule::new(Action::Allow, r"api\.example\.com")
                .unwrap()
                .with_methods(vec![Method::GET]),
            Rule::new(Action::Deny, r".*").unwrap(),
        ];

        let engine = RuleEngine::new(rules, None);

        // GET should be allowed
        assert!(matches!(
            engine.evaluate(Method::GET, "https://api.example.com/data"),
            Action::Allow
        ));

        // POST should be denied (doesn't match method filter)
        assert!(matches!(
            engine.evaluate(Method::POST, "https://api.example.com/data"),
            Action::Deny
        ));
    }

    #[test]
    fn test_request_logging() {
        use std::fs::OpenOptions;

        let rules = vec![Rule::new(Action::Allow, r".*").unwrap()];
        let log_file = tempfile::NamedTempFile::new().unwrap();
        let file = OpenOptions::new()
            .append(true)
            .open(log_file.path())
            .unwrap();
        let engine = RuleEngine::new(rules, Some(Arc::new(Mutex::new(file))));

        engine.evaluate(Method::GET, "https://example.com");

        let contents = std::fs::read_to_string(log_file.path()).unwrap();
        assert!(contents.contains("+ GET https://example.com"));
    }

    #[test]
    fn test_request_logging_denied() {
        use std::fs::OpenOptions;

        let rules = vec![Rule::new(Action::Deny, r".*").unwrap()];
        let log_file = tempfile::NamedTempFile::new().unwrap();
        let file = OpenOptions::new()
            .append(true)
            .open(log_file.path())
            .unwrap();
        let engine = RuleEngine::new(rules, Some(Arc::new(Mutex::new(file))));

        engine.evaluate(Method::GET, "https://blocked.com");

        let contents = std::fs::read_to_string(log_file.path()).unwrap();
        assert!(contents.contains("- GET https://blocked.com"));
    }

    #[test]
    fn test_default_deny_with_no_rules() {
        let engine = RuleEngine::new(vec![], false);

        assert!(matches!(
            engine.evaluate(Method::GET, "https://example.com"),
            Action::Deny
        ));
    }
}
