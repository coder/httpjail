use anyhow::{Context, Result};
use clap::Parser;
use httpjail::jail::{JailConfig, create_jail};
use httpjail::proxy::ProxyServer;
use httpjail::rules::{Action, Rule, RuleEngine};
use std::os::unix::process::ExitStatusExt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, info, warn};

#[derive(Parser, Debug)]
#[command(name = "httpjail")]
#[command(version = env!("VERSION_WITH_GIT_HASH"), about, long_about = None)]
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

    /// Skip jail cleanup (hidden flag for testing)
    #[arg(long = "no-jail-cleanup", hide = true)]
    no_jail_cleanup: bool,

    /// Clean up orphaned jails and exit (for debugging)
    #[arg(long = "cleanup", hide = true)]
    cleanup: bool,

    /// Run as standalone proxy server (without executing a command)
    #[arg(
        long = "server",
        conflicts_with = "cleanup",
        conflicts_with = "timeout"
    )]
    server: bool,

    /// Command and arguments to execute
    #[arg(trailing_var_arg = true, required_unless_present_any = ["cleanup", "server"])]
    command: Vec<String>,
}

fn setup_logging(verbosity: u8) {
    use tracing_subscriber::fmt::time::FormatTime;

    // Custom time format that only shows time, not date
    struct TimeOnly;
    impl FormatTime for TimeOnly {
        fn format_time(
            &self,
            w: &mut tracing_subscriber::fmt::format::Writer<'_>,
        ) -> std::fmt::Result {
            let now = chrono::Local::now();
            write!(w, "{}", now.format("%H:%M:%S%.3f"))
        }
    }

    // Check if RUST_LOG is set
    if std::env::var("RUST_LOG").is_ok() {
        // Use RUST_LOG environment variable
        tracing_subscriber::fmt()
            .with_timer(TimeOnly)
            .with_writer(std::io::stderr)
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    } else {
        // Use verbosity flag
        let level = match verbosity {
            0 => "error",
            1 => "warn",
            2 => "info",
            3 => "debug",
            _ => "trace",
        };

        tracing_subscriber::fmt()
            .with_timer(TimeOnly)
            .with_writer(std::io::stderr)
            .with_env_filter(format!("httpjail={}", level))
            .init();
    }
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

    // Load rules from config file if provided
    if let Some(config_path) = &args.config {
        let contents = std::fs::read_to_string(config_path)
            .with_context(|| format!("Failed to read config file: {}", config_path))?;
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            rules.push(parse_rule(line)?);
        }
    }

    // Parse command line rules in the exact order specified
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

/// Direct orphan cleanup without creating jails
fn cleanup_orphans() -> Result<()> {
    use anyhow::Context;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};
    use tracing::{debug, info};

    let canary_dir = PathBuf::from("/tmp/httpjail");
    let orphan_timeout = Duration::from_secs(5); // Short timeout to catch recent orphans

    debug!("Starting direct orphan cleanup scan in {:?}", canary_dir);

    // Check if directory exists
    if !canary_dir.exists() {
        debug!("Canary directory does not exist, nothing to clean up");
        return Ok(());
    }

    // Scan for stale canary files
    for entry in fs::read_dir(&canary_dir)? {
        let entry = entry?;
        let path = entry.path();

        // Skip if not a file
        if !path.is_file() {
            debug!("Skipping non-file: {:?}", path);
            continue;
        }

        // Check file age using modification time
        let metadata = fs::metadata(&path)?;
        let modified = metadata
            .modified()
            .context("Failed to get file modification time")?;
        let age = SystemTime::now()
            .duration_since(modified)
            .unwrap_or(Duration::from_secs(0));

        debug!("Found canary file {:?} with age {:?}", path, age);

        // If file is older than orphan timeout, clean it up
        if age > orphan_timeout {
            let jail_id = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");

            info!(
                "Found orphaned jail '{}' (age: {:?}), cleaning up",
                jail_id, age
            );

            // Call platform-specific cleanup
            #[cfg(target_os = "linux")]
            {
                <httpjail::jail::linux::LinuxJail as httpjail::jail::Jail>::cleanup_orphaned(
                    jail_id,
                )?;
            }

            #[cfg(target_os = "macos")]
            {
                // On macOS, we use WeakJail which doesn't have orphaned resources to clean up
                // Just log that we're skipping cleanup
                debug!("Skipping orphan cleanup on macOS (using weak jail)");
            }

            // Remove canary file after cleanup
            if let Err(e) = fs::remove_file(&path) {
                debug!("Failed to remove canary file {:?}: {}", path, e);
            } else {
                debug!("Removed canary file: {:?}", path);
            }
        } else {
            debug!(
                "Canary file {:?} is not old enough to be considered orphaned",
                path
            );
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    setup_logging(args.verbose);

    debug!("Starting httpjail with args: {:?}", args);

    // Handle cleanup flag
    if args.cleanup {
        info!("Running orphan cleanup and exiting...");

        // Directly call platform-specific orphan cleanup without creating jails
        cleanup_orphans()?;

        info!("Cleanup completed successfully");
        return Ok(());
    }

    // Handle server mode
    if args.server {
        info!("Starting httpjail in server mode");
    }

    // Build rules from command line arguments
    let rules = build_rules(&args)?;
    let rule_engine = RuleEngine::new(rules, args.dry_run, args.log_only);

    // Parse bind configuration from env vars
    // Supports both "port" and "ip:port" formats
    fn parse_bind_config(env_var: &str) -> (Option<u16>, Option<std::net::IpAddr>) {
        if let Ok(val) = std::env::var(env_var) {
            if let Some(colon_pos) = val.rfind(':') {
                // Try to parse as ip:port
                let ip_str = &val[..colon_pos];
                let port_str = &val[colon_pos + 1..];

                let port = port_str.parse::<u16>().ok();
                let ip = ip_str.parse::<std::net::IpAddr>().ok();

                if port.is_some() && ip.is_some() {
                    return (port, ip);
                }
            }

            // Try to parse as just a port number
            if let Ok(port) = val.parse::<u16>() {
                return (Some(port), None);
            }
        }
        (None, None)
    }

    let (http_port_env, http_bind_ip) = parse_bind_config("HTTPJAIL_HTTP_BIND");
    let (https_port_env, https_bind_ip) = parse_bind_config("HTTPJAIL_HTTPS_BIND");

    // Use env port or default to 8080/8443 in server mode
    let http_port = http_port_env.or_else(|| if args.server { Some(8080) } else { None });
    let https_port = https_port_env.or_else(|| if args.server { Some(8443) } else { None });

    // Determine bind address based on configuration and mode
    let bind_address = if let Some(ip) = http_bind_ip.or(https_bind_ip) {
        // If user explicitly specified an IP, use it
        match ip {
            std::net::IpAddr::V4(ipv4) => Some(ipv4.octets()),
            std::net::IpAddr::V6(_) => {
                warn!("IPv6 addresses are not currently supported, falling back to IPv4");
                None
            }
        }
    } else if args.weak || args.server {
        // In weak mode or server mode, bind to localhost only by default
        None
    } else {
        // For jailed mode on Linux, bind to all interfaces
        // The namespace isolation provides the security boundary
        #[cfg(target_os = "linux")]
        {
            Some([0, 0, 0, 0])
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    };

    // Start the proxy server
    let mut proxy = ProxyServer::new(http_port, https_port, rule_engine.clone(), bind_address);
    let (actual_http_port, actual_https_port) = proxy.start().await?;

    info!(
        "Proxy server started on ports {} (HTTP) and {} (HTTPS)",
        actual_http_port, actual_https_port
    );

    // In server mode, just run the proxy server
    if args.server {
        // Use tokio::sync::Notify for real-time shutdown signaling
        let shutdown_notify = Arc::new(tokio::sync::Notify::new());
        let shutdown_notify_clone = shutdown_notify.clone();

        ctrlc::set_handler(move || {
            info!("Received interrupt signal, shutting down server...");
            shutdown_notify_clone.notify_one();
        })
        .expect("Error setting signal handler");

        info!(
            "Server running on ports {} (HTTP) and {} (HTTPS). Press Ctrl+C to stop.",
            actual_http_port, actual_https_port
        );

        // Wait for shutdown signal
        shutdown_notify.notified().await;

        info!("Server shutdown complete");
        return Ok(());
    }

    // Normal mode: create jail and execute command
    // Create jail configuration with actual bound ports
    let mut jail_config = JailConfig::new();
    jail_config.http_proxy_port = actual_http_port;
    jail_config.https_proxy_port = actual_https_port;

    // Create and setup jail
    let mut jail = create_jail(jail_config.clone(), args.weak)?;

    // Setup jail (pass 0 as the port parameter is ignored)
    jail.setup(0)?;

    // Wrap jail in Arc for potential sharing with timeout task and signal handler
    let jail = std::sync::Arc::new(jail);

    // Set up signal handler for cleanup
    let shutdown = Arc::new(AtomicBool::new(false));
    let jail_for_signal = jail.clone();
    let shutdown_clone = shutdown.clone();
    let no_cleanup = args.no_jail_cleanup;

    // Set up signal handler for SIGINT and SIGTERM
    ctrlc::set_handler(move || {
        if !shutdown_clone.load(Ordering::SeqCst) {
            info!("Received interrupt signal, cleaning up...");
            shutdown_clone.store(true, Ordering::SeqCst);

            // Cleanup jail unless testing flag is set
            if !no_cleanup && let Err(e) = jail_for_signal.cleanup() {
                warn!("Failed to cleanup jail on signal: {}", e);
            }

            // Exit with signal termination status
            std::process::exit(130); // 128 + SIGINT(2)
        }
    })
    .expect("Error setting signal handler");

    // Set up CA certificate environment variables for common tools
    let mut extra_env = Vec::new();

    match httpjail::tls::CertificateManager::get_ca_env_vars() {
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

    // Execute command in jail with extra environment variables
    let status = if let Some(timeout_secs) = args.timeout {
        info!("Executing command with {}s timeout", timeout_secs);

        // Use tokio to handle timeout
        let command = args.command.clone();
        let extra_env_clone = extra_env.clone();
        let jail_clone = jail.clone();

        // We need to use spawn_blocking since jail.execute is blocking
        let handle =
            tokio::task::spawn_blocking(move || jail_clone.execute(&command, &extra_env_clone));

        // Apply timeout to the blocking task
        match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), handle).await {
            Ok(Ok(result)) => result?,
            Ok(Err(e)) => anyhow::bail!("Task execution failed: {}", e),
            Err(_) => {
                warn!("Command timed out after {}s", timeout_secs);
                // Note: We can't actually kill the process from here since it's in a separate
                // process/namespace. The process will continue running but we return timeout.
                // This matches the behavior of GNU timeout when it can't kill the process.
                std::process::ExitStatus::from_raw(124 << 8)
            }
        }
    } else {
        jail.execute(&args.command, &extra_env)?
    };

    // Cleanup jail (unless testing flag is set)
    if !args.no_jail_cleanup {
        jail.cleanup()?;
    } else {
        info!("Skipping jail cleanup (--no-jail-cleanup flag set)");
    }

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
    fn test_dry_run_mode() {
        let rules = vec![Rule::new(Action::Deny, r".*").unwrap()];

        let engine = RuleEngine::new(rules, true, false);

        // In dry-run mode, everything should be allowed
        assert!(matches!(
            engine.evaluate(Method::GET, "https://example.com"),
            Action::Allow
        ));
    }

    #[test]
    fn test_log_only_mode() {
        let rules = vec![Rule::new(Action::Deny, r".*").unwrap()];

        let engine = RuleEngine::new(rules, false, true);

        // In log-only mode, everything should be allowed
        assert!(matches!(
            engine.evaluate(Method::POST, "https://example.com"),
            Action::Allow
        ));
    }

    #[test]
    fn test_build_rules_from_config_file() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            "allow-get: google\\.com\n# comment\ndeny: yahoo.com\n\nallow: .*"
        )
        .unwrap();

        let args = Args {
            rules: vec![],
            config: Some(file.path().to_str().unwrap().to_string()),
            dry_run: false,
            log_only: false,
            interactive: false,
            weak: false,
            verbose: 0,
            timeout: None,
            no_jail_cleanup: false,
            cleanup: false,
            server: false,
            command: vec![],
        };

        let rules = build_rules(&args).unwrap();
        assert_eq!(rules.len(), 3);

        // First rule should be allow for GET method only
        assert!(matches!(rules[0].action, Action::Allow));
        assert!(rules[0].methods.as_ref().unwrap().contains(&Method::GET));

        // Second rule should be deny
        assert!(matches!(rules[1].action, Action::Deny));

        // Third rule allow all
        assert!(matches!(rules[2].action, Action::Allow));
    }
}
