use super::{Action, EvaluationResult, RuleEngineTrait};
use anyhow::Result;
use async_trait::async_trait;
use hyper::Method;
use regex::Regex;
use std::collections::HashSet;
use tracing::debug;

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
}