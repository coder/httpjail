use anyhow::Result;
use hyper::Method;
use regex::Regex;
use std::collections::HashSet;
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
    pub log_only: bool,
}

impl RuleEngine {
    pub fn new(rules: Vec<Rule>, log_only: bool) -> Self {
        RuleEngine { rules, log_only }
    }

    pub fn evaluate(&self, method: Method, url: &str) -> Action {
        if self.log_only {
            info!("Request: {} {}", method, url);
            return Action::Allow;
        }

        for rule in &self.rules {
            if rule.matches(method.clone(), url) {
                match &rule.action {
                    Action::Allow => {
                        info!(
                            "ALLOW: {} {} (matched: {:?})",
                            method,
                            url,
                            rule.pattern.as_str()
                        );
                        return Action::Allow;
                    }
                    Action::Deny => {
                        warn!(
                            "DENY: {} {} (matched: {:?})",
                            method,
                            url,
                            rule.pattern.as_str()
                        );
                        return Action::Deny;
                    }
                }
            }
        }

        // Default deny if no rules match
        warn!("DENY: {} {} (no matching rules)", method, url);
        Action::Deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let engine = RuleEngine::new(rules, false);

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

        let engine = RuleEngine::new(rules, false);

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
    fn test_log_only_mode() {
        let rules = vec![Rule::new(Action::Deny, r".*").unwrap()];

        let engine = RuleEngine::new(rules, true);

        // In log-only mode, everything should be allowed
        assert!(matches!(
            engine.evaluate(Method::POST, "https://example.com"),
            Action::Allow
        ));
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
