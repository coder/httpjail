use anyhow::Result;
use regex::Regex;
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
}

impl Rule {
    pub fn new(action: Action, pattern: &str) -> Result<Self> {
        Ok(Rule {
            action,
            pattern: Regex::new(pattern)?,
        })
    }

    pub fn matches(&self, url: &str) -> bool {
        self.pattern.is_match(url)
    }
}

#[derive(Clone)]
pub struct RuleEngine {
    pub rules: Vec<Rule>,
    pub dry_run: bool,
    pub log_only: bool,
}

impl RuleEngine {
    pub fn new(rules: Vec<Rule>, dry_run: bool, log_only: bool) -> Self {
        RuleEngine {
            rules,
            dry_run,
            log_only,
        }
    }

    pub fn evaluate(&self, url: &str) -> Action {
        if self.log_only {
            info!("Request: {}", url);
            return Action::Allow;
        }

        for rule in &self.rules {
            if rule.matches(url) {
                match &rule.action {
                    Action::Allow => {
                        info!("ALLOW: {} (matched: {:?})", url, rule.pattern.as_str());
                        if !self.dry_run {
                            return Action::Allow;
                        }
                    }
                    Action::Deny => {
                        warn!("DENY: {} (matched: {:?})", url, rule.pattern.as_str());
                        if !self.dry_run {
                            return Action::Deny;
                        }
                    }
                }
            }
        }

        // Default deny if no rules match
        warn!("DENY: {} (no matching rules)", url);
        if self.dry_run {
            Action::Allow
        } else {
            Action::Deny
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_matching() {
        let rule = Rule::new(Action::Allow, r"github\.com").unwrap();
        assert!(rule.matches("https://github.com/user/repo"));
        assert!(rule.matches("http://api.github.com/v3/repos"));
        assert!(!rule.matches("https://gitlab.com/user/repo"));
    }

    #[test]
    fn test_rule_engine() {
        let rules = vec![
            Rule::new(Action::Allow, r"github\.com").unwrap(),
            Rule::new(Action::Deny, r"telemetry").unwrap(),
            Rule::new(Action::Deny, r".*").unwrap(),
        ];

        let engine = RuleEngine::new(rules, false, false);

        // Test allow rule
        matches!(engine.evaluate("https://github.com/api"), Action::Allow);
        
        // Test deny rule
        matches!(engine.evaluate("https://telemetry.example.com"), Action::Deny);
        
        // Test default deny
        matches!(engine.evaluate("https://example.com"), Action::Deny);
    }

    #[test]
    fn test_dry_run_mode() {
        let rules = vec![
            Rule::new(Action::Deny, r".*").unwrap(),
        ];

        let engine = RuleEngine::new(rules, true, false);

        // In dry-run mode, everything should be allowed
        matches!(engine.evaluate("https://example.com"), Action::Allow);
    }

    #[test]
    fn test_log_only_mode() {
        let rules = vec![
            Rule::new(Action::Deny, r".*").unwrap(),
        ];

        let engine = RuleEngine::new(rules, false, true);

        // In log-only mode, everything should be allowed
        matches!(engine.evaluate("https://example.com"), Action::Allow);
    }
}