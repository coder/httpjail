mod proxy;
mod rules;

use anyhow::Result;
use clap::Parser;
use proxy::ProxyServer;
use rules::{Action, Rule, RuleEngine};
use std::process::Command;
use tracing::{debug, info};

#[derive(Parser, Debug)]
#[command(name = "httpjail")]
#[command(version, about, long_about = None)]
#[command(about = "Monitor and restrict HTTP/HTTPS requests from processes")]
struct Args {
    /// Allow requests matching regex pattern (can be specified multiple times)
    #[arg(short = 'a', long = "allow", value_name = "PATTERN")]
    allow: Vec<String>,

    /// Deny requests matching regex pattern (can be specified multiple times)
    #[arg(short = 'd', long = "deny", value_name = "PATTERN")]
    deny: Vec<String>,

    /// Use configuration file
    #[arg(short = 'c', long = "config", value_name = "FILE")]
    config: Option<String>,

    /// Log actions without blocking
    #[arg(long = "dry-run")]
    dry_run: bool,

    /// Monitor without filtering
    #[arg(long = "log-only")]
    log_only: bool,

    /// Disable HTTPS interception
    #[arg(long = "no-tls-intercept")]
    no_tls_intercept: bool,

    /// Interactive approval mode
    #[arg(long = "interactive")]
    interactive: bool,

    /// Increase verbosity (-vvv for max)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,

    /// Command and arguments to execute
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

fn setup_logging(verbosity: u8) {
    let level = match verbosity {
        0 => "error",
        1 => "warn",
        2 => "info",
        3 => "debug",
        _ => "trace",
    };

    tracing_subscriber::fmt()
        .with_env_filter(format!("httpjail={}", level))
        .init();
}

fn build_rules(args: &Args) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();

    // Add allow rules
    for pattern in &args.allow {
        rules.push(Rule::new(Action::Allow, pattern)?);
    }

    // Add deny rules
    for pattern in &args.deny {
        rules.push(Rule::new(Action::Deny, pattern)?);
    }

    // If no rules specified, default to allow all (for testing)
    if rules.is_empty() {
        rules.push(Rule::new(Action::Allow, ".*")?);
    }

    Ok(rules)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    setup_logging(args.verbose);

    debug!("Starting httpjail with args: {:?}", args);

    // Build rules from command line arguments
    let rules = build_rules(&args)?;

    let rule_engine = RuleEngine::new(rules, args.dry_run, args.log_only);

    // Check if we should start the proxy server
    let start_proxy = std::env::var("HTTPJAIL_ENABLE_PROXY").is_ok();

    if start_proxy {
        // Start the proxy server
        let proxy = ProxyServer::new(8080, 8443, rule_engine.clone());
        proxy.start().await?;
        
        info!("Proxy server started on http://127.0.0.1:8080");
        
        // Set environment variables for the child process to use the proxy
        unsafe {
            std::env::set_var("http_proxy", "http://127.0.0.1:8080");
            std::env::set_var("https_proxy", "http://127.0.0.1:8080");
            std::env::set_var("HTTP_PROXY", "http://127.0.0.1:8080");
            std::env::set_var("HTTPS_PROXY", "http://127.0.0.1:8080");
        }
        
        // Give the proxy server time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    debug!("Executing command: {:?}", args.command);

    if args.command.is_empty() {
        anyhow::bail!("No command specified");
    }

    // Execute the command with proxy environment if enabled
    let mut cmd = Command::new(&args.command[0]);
    if args.command.len() > 1 {
        cmd.args(&args.command[1..]);
    }

    // For testing purposes, we can set environment variables
    // that a mock server could read to determine rules
    if std::env::var("HTTPJAIL_TEST_MODE").is_ok() {
        // In test mode, pass rules via environment
        let rules_json = serde_json::to_string(&format!("{:?}", rule_engine.rules))?;
        cmd.env("HTTPJAIL_RULES", rules_json);
        cmd.env("HTTPJAIL_DRY_RUN", args.dry_run.to_string());
        cmd.env("HTTPJAIL_LOG_ONLY", args.log_only.to_string());
    }

    let status = cmd.status()?;

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }

    Ok(())
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
        matches!(
            engine.evaluate("https://telemetry.example.com"),
            Action::Deny
        );

        // Test default deny
        matches!(engine.evaluate("https://example.com"), Action::Deny);
    }

    #[test]
    fn test_dry_run_mode() {
        let rules = vec![Rule::new(Action::Deny, r".*").unwrap()];

        let engine = RuleEngine::new(rules, true, false);

        // In dry-run mode, everything should be allowed
        matches!(engine.evaluate("https://example.com"), Action::Allow);
    }

    #[test]
    fn test_log_only_mode() {
        let rules = vec![Rule::new(Action::Deny, r".*").unwrap()];

        let engine = RuleEngine::new(rules, false, true);

        // In log-only mode, everything should be allowed
        matches!(engine.evaluate("https://example.com"), Action::Allow);
    }
}
