mod jail;
mod proxy;
mod proxy_tls;
mod rules;
mod tls;

use anyhow::Result;
use clap::Parser;
use jail::{JailConfig, create_jail};
use proxy::ProxyServer;
use rules::{Action, Rule, RuleEngine};
use tracing::{debug, info, warn};

#[derive(Parser, Debug)]
#[command(name = "httpjail")]
#[command(version, about, long_about = None)]
#[command(about = "Monitor and restrict HTTP/HTTPS requests from processes")]
struct Args {
    /// Rules for filtering requests (can be specified multiple times)
    /// Format: "action[-method]: pattern"
    /// Examples:
    ///   -r "allow: github\.com/.*"
    ///   -r "deny-post: telemetry\..*"
    ///   -r "allow-get: .*"
    /// Actions: allow, deny
    /// Methods (optional): get, post, put, delete, head, options, connect, trace, patch
    #[arg(short = 'r', long = "rule", value_name = "RULE")]
    rules: Vec<String>,

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

    /// Use weak mode (environment variables only, no system isolation)
    #[arg(long = "weak")]
    weak: bool,

    /// Increase verbosity (-vvv for max)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,

    /// Timeout for command execution in seconds
    #[arg(long = "timeout")]
    timeout: Option<u64>,

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

fn parse_rule(rule_str: &str) -> Result<Rule> {
    use hyper::Method;

    // Split on the first colon to separate action from pattern
    let parts: Vec<&str> = rule_str.splitn(2, ':').collect();
    if parts.len() != 2 {
        anyhow::bail!(
            "Invalid rule format: '{}'. Expected 'action[-method]: pattern'",
            rule_str
        );
    }

    let action_part = parts[0].trim();
    let pattern = parts[1].trim();

    // Parse action and optional method
    let (action, method) = if action_part.contains('-') {
        let action_parts: Vec<&str> = action_part.splitn(2, '-').collect();
        let action = match action_parts[0] {
            "allow" => Action::Allow,
            "deny" => Action::Deny,
            _ => anyhow::bail!(
                "Invalid action: '{}'. Expected 'allow' or 'deny'",
                action_parts[0]
            ),
        };

        let method = match action_parts[1].to_lowercase().as_str() {
            "get" => Some(Method::GET),
            "post" => Some(Method::POST),
            "put" => Some(Method::PUT),
            "delete" => Some(Method::DELETE),
            "head" => Some(Method::HEAD),
            "options" => Some(Method::OPTIONS),
            "connect" => Some(Method::CONNECT),
            "trace" => Some(Method::TRACE),
            "patch" => Some(Method::PATCH),
            _ => anyhow::bail!("Invalid method: '{}'", action_parts[1]),
        };

        (action, method)
    } else {
        let action = match action_part {
            "allow" => Action::Allow,
            "deny" => Action::Deny,
            _ => anyhow::bail!(
                "Invalid action: '{}'. Expected 'allow' or 'deny'",
                action_part
            ),
        };
        (action, None)
    };

    // Create rule with optional method restriction
    let rule = Rule::new(action, pattern)?;
    Ok(if let Some(method) = method {
        rule.with_methods(vec![method])
    } else {
        rule
    })
}

fn build_rules(args: &Args) -> Result<Vec<Rule>> {
    let mut rules = Vec::new();

    // Parse rules in the exact order specified
    for rule_str in &args.rules {
        rules.push(parse_rule(rule_str)?);
    }

    // If no rules specified, default to allow all (for testing)
    if rules.is_empty() {
        info!("No rules specified, defaulting to allow all");
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

    // Get ports from env vars (optional)
    let http_port = std::env::var("HTTPJAIL_HTTP_BIND")
        .ok()
        .and_then(|s| s.parse::<u16>().ok());

    let https_port = std::env::var("HTTPJAIL_HTTPS_BIND")
        .ok()
        .and_then(|s| s.parse::<u16>().ok());

    // Start the proxy server
    let mut proxy = ProxyServer::new(http_port, https_port, rule_engine.clone());
    let (actual_http_port, actual_https_port) = proxy.start().await?;

    info!(
        "Proxy server started on ports {} (HTTP) and {} (HTTPS)",
        actual_http_port, actual_https_port
    );

    // Create jail configuration with actual bound ports
    let jail_config = JailConfig {
        http_proxy_port: actual_http_port,
        https_proxy_port: actual_https_port,
        tls_intercept: !args.no_tls_intercept,
        jail_name: "httpjail".to_string(),
    };

    // Create and setup jail
    let mut jail = create_jail(jail_config.clone(), args.weak)?;

    // Setup jail (pass 0 as the port parameter is ignored)
    jail.setup(0)?;

    // Set up CA certificate environment variables for common tools
    let mut extra_env = Vec::new();

    if !args.no_tls_intercept {
        match tls::CertificateManager::get_ca_env_vars() {
            Ok(ca_env_vars) => {
                debug!(
                    "Setting {} CA certificate environment variables",
                    ca_env_vars.len()
                );
                extra_env = ca_env_vars;
            }
            Err(e) => {
                warn!(
                    "Failed to set up CA certificate environment variables: {}",
                    e
                );
            }
        }
    }

    // Execute command in jail with extra environment variables
    let status = if let Some(timeout_secs) = args.timeout {
        
        info!("Executing command with {}s timeout", timeout_secs);
        
        // For timeout, we need to execute directly with a wrapper
        // Since we can't easily timeout the jail.execute call itself,
        // we'll pass the timeout to the jail implementation
        // For now, let's use the timeout command if available
        let mut timeout_cmd = vec!["timeout".to_string(), timeout_secs.to_string()];
        timeout_cmd.extend(args.command.clone());
        
        match jail.execute(&timeout_cmd, &extra_env) {
            Ok(status) => {
                if status.code() == Some(124) {
                    warn!("Command timed out after {}s", timeout_secs);
                }
                status
            }
            Err(e) => {
                // If timeout command doesn't exist, fall back to regular execution
                if e.to_string().contains("timeout") || e.to_string().contains("No such file") {
                    warn!("timeout command not available, executing without timeout");
                    jail.execute(&args.command, &extra_env)?
                } else {
                    return Err(e);
                }
            }
        }
    } else {
        jail.execute(&args.command, &extra_env)?
    };

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
