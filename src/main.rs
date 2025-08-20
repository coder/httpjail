mod jail;
mod proxy;
mod rules;

use anyhow::Result;
use clap::Parser;
use jail::{JailConfig, create_jail};
use proxy::ProxyServer;
use rules::{Action, Rule, RuleEngine};
use tracing::{debug, info};

#[derive(Parser, Debug)]
#[command(name = "httpjail")]
#[command(version, about, long_about = None)]
#[command(about = "Monitor and restrict HTTP/HTTPS requests from processes")]
struct Args {
    /// Allow requests matching regex pattern (can be specified multiple times)
    #[arg(short = 'a', long = "allow", value_name = "PATTERN")]
    allow: Vec<String>,

    /// Allow GET requests matching regex pattern
    #[arg(long = "allow-get", value_name = "PATTERN")]
    allow_get: Vec<String>,

    /// Allow POST requests matching regex pattern
    #[arg(long = "allow-post", value_name = "PATTERN")]
    allow_post: Vec<String>,

    /// Allow PUT requests matching regex pattern
    #[arg(long = "allow-put", value_name = "PATTERN")]
    allow_put: Vec<String>,

    /// Allow DELETE requests matching regex pattern
    #[arg(long = "allow-delete", value_name = "PATTERN")]
    allow_delete: Vec<String>,

    /// Deny requests matching regex pattern (can be specified multiple times)
    #[arg(short = 'd', long = "deny", value_name = "PATTERN")]
    deny: Vec<String>,

    /// Deny GET requests matching regex pattern
    #[arg(long = "deny-get", value_name = "PATTERN")]
    deny_get: Vec<String>,

    /// Deny POST requests matching regex pattern
    #[arg(long = "deny-post", value_name = "PATTERN")]
    deny_post: Vec<String>,

    /// Deny PUT requests matching regex pattern
    #[arg(long = "deny-put", value_name = "PATTERN")]
    deny_put: Vec<String>,

    /// Deny DELETE requests matching regex pattern
    #[arg(long = "deny-delete", value_name = "PATTERN")]
    deny_delete: Vec<String>,

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
    use hyper::Method;
    let mut rules = Vec::new();

    // Add allow rules (all methods)
    for pattern in &args.allow {
        rules.push(Rule::new(Action::Allow, pattern)?);
    }

    // Add method-specific allow rules
    for pattern in &args.allow_get {
        rules.push(Rule::new(Action::Allow, pattern)?.with_methods(vec![Method::GET]));
    }
    for pattern in &args.allow_post {
        rules.push(Rule::new(Action::Allow, pattern)?.with_methods(vec![Method::POST]));
    }
    for pattern in &args.allow_put {
        rules.push(Rule::new(Action::Allow, pattern)?.with_methods(vec![Method::PUT]));
    }
    for pattern in &args.allow_delete {
        rules.push(Rule::new(Action::Allow, pattern)?.with_methods(vec![Method::DELETE]));
    }

    // Add deny rules (all methods)
    for pattern in &args.deny {
        rules.push(Rule::new(Action::Deny, pattern)?);
    }

    // Add method-specific deny rules
    for pattern in &args.deny_get {
        rules.push(Rule::new(Action::Deny, pattern)?.with_methods(vec![Method::GET]));
    }
    for pattern in &args.deny_post {
        rules.push(Rule::new(Action::Deny, pattern)?.with_methods(vec![Method::POST]));
    }
    for pattern in &args.deny_put {
        rules.push(Rule::new(Action::Deny, pattern)?.with_methods(vec![Method::PUT]));
    }
    for pattern in &args.deny_delete {
        rules.push(Rule::new(Action::Deny, pattern)?.with_methods(vec![Method::DELETE]));
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

    // Create jail configuration with default ports
    let jail_config = JailConfig {
        http_proxy_port: 8040,
        https_proxy_port: 8043,
        tls_intercept: !args.no_tls_intercept,
        jail_name: "httpjail".to_string(),
    };

    info!("Starting proxy server on ports {} (HTTP) and {} (HTTPS)", 
         jail_config.http_proxy_port, jail_config.https_proxy_port);

    // Start the proxy server
    let proxy = ProxyServer::new(
        jail_config.http_proxy_port, 
        jail_config.https_proxy_port, 
        rule_engine.clone()
    );
    proxy.start().await?;

    // Create and setup jail
    let jail = create_jail(jail_config.clone())?;

    // Initialize jail
    jail.init()?;

    // Setup jail (pass 0 as the port parameter is ignored)
    jail.setup(0)?;

    // Execute command in jail
    let status = jail.execute(&args.command)?;

    // Cleanup jail
    jail.cleanup()?;

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Method;

    #[test]
    fn test_rule_matching() {
        let rule = Rule::new(Action::Allow, r"github\.com").unwrap();
        assert!(rule.matches(Method::GET, "https://github.com/user/repo"));
        assert!(rule.matches(Method::POST, "http://api.github.com/v3/repos"));
        assert!(!rule.matches(Method::GET, "https://gitlab.com/user/repo"));
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
        matches!(
            engine.evaluate(Method::GET, "https://github.com/api"),
            Action::Allow
        );

        // Test deny rule
        matches!(
            engine.evaluate(Method::POST, "https://telemetry.example.com"),
            Action::Deny
        );

        // Test default deny
        matches!(
            engine.evaluate(Method::GET, "https://example.com"),
            Action::Deny
        );
    }

    #[test]
    fn test_dry_run_mode() {
        let rules = vec![Rule::new(Action::Deny, r".*").unwrap()];

        let engine = RuleEngine::new(rules, true, false);

        // In dry-run mode, everything should be allowed
        matches!(
            engine.evaluate(Method::GET, "https://example.com"),
            Action::Allow
        );
    }

    #[test]
    fn test_log_only_mode() {
        let rules = vec![Rule::new(Action::Deny, r".*").unwrap()];

        let engine = RuleEngine::new(rules, false, true);

        // In log-only mode, everything should be allowed
        matches!(
            engine.evaluate(Method::POST, "https://example.com"),
            Action::Allow
        );
    }
}
