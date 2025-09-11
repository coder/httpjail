use super::{Action, EvaluationResult, RuleEngineTrait};
use anyhow::Result;
use hyper::Method;
use regex::Regex;
use std::collections::HashSet;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct Rule {
    pub action: Action,
    pub pattern: Regex,
    pub methods: Option<HashSet<Method>>,
}

impl Rule {
    pub fn new(action: Action, pattern: &str) -> Result<Self> {
        Ok(Rule {
            action,
            pattern: Regex::new(pattern)?,
            methods: None,
        })
    }

    pub fn with_methods(mut self, methods: Vec<Method>) -> Self {
        self.methods = Some(methods.into_iter().collect());
        self
    }

    pub fn matches(&self, method: Method, url: &str) -> bool {
        if !self.pattern.is_match(url) {
            return false;
        }

        match &self.methods {
            None => true,
            Some(methods) => methods.contains(&method),
        }
    }
}

#[derive(Clone)]
pub struct PatternRuleEngine {
    pub rules: Vec<Rule>,
}

impl PatternRuleEngine {
    pub fn new(rules: Vec<Rule>) -> Self {
        PatternRuleEngine { rules }
    }
}

impl RuleEngineTrait for PatternRuleEngine {
    fn evaluate(&self, method: Method, url: &str) -> EvaluationResult {
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
                        return EvaluationResult::allow()
                            .with_context(format!("Matched pattern: {}", rule.pattern.as_str()));
                    }
                    Action::Deny => {
                        warn!(
                            "DENY: {} {} (matched: {:?})",
                            method,
                            url,
                            rule.pattern.as_str()
                        );
                        return EvaluationResult::deny()
                            .with_context(format!("Matched pattern: {}", rule.pattern.as_str()));
                    }
                }
            }
        }

        warn!("DENY: {} {} (no matching rules)", method, url);
        EvaluationResult::deny().with_context("No matching rules".to_string())
    }

    fn name(&self) -> &str {
        "pattern"
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
    fn test_pattern_engine() {
        let rules = vec![
            Rule::new(Action::Allow, r"github\.com").unwrap(),
            Rule::new(Action::Deny, r"telemetry").unwrap(),
            Rule::new(Action::Deny, r".*").unwrap(),
        ];

        let engine = PatternRuleEngine::new(rules);

        assert!(matches!(
            engine
                .evaluate(Method::GET, "https://github.com/api")
                .action,
            Action::Allow
        ));

        assert!(matches!(
            engine
                .evaluate(Method::POST, "https://telemetry.example.com")
                .action,
            Action::Deny
        ));

        assert!(matches!(
            engine.evaluate(Method::GET, "https://example.com").action,
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

        let engine = PatternRuleEngine::new(rules);

        assert!(matches!(
            engine
                .evaluate(Method::GET, "https://api.example.com/data")
                .action,
            Action::Allow
        ));

        assert!(matches!(
            engine
                .evaluate(Method::POST, "https://api.example.com/data")
                .action,
            Action::Deny
        ));
    }

    #[test]
    fn test_default_deny_with_no_rules() {
        let engine = PatternRuleEngine::new(vec![]);

        assert!(matches!(
            engine.evaluate(Method::GET, "https://example.com").action,
            Action::Deny
        ));
    }
}
