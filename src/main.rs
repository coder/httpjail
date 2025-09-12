use anyhow::{Context, Result};
use clap::Parser;
use httpjail::jail::{JailConfig, create_jail};
use httpjail::proxy::ProxyServer;
use httpjail::rules::script::ScriptRuleEngine;
use httpjail::rules::v8_js::V8JsRuleEngine;
use httpjail::rules::{Action, RuleEngine};
use hyper::Method;
use std::fs::OpenOptions;
use std::os::unix::process::ExitStatusExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

#[derive(Parser, Debug)]
#[command(name = "httpjail")]
#[command(version = env!("VERSION_WITH_GIT_HASH"), about, long_about = None)]
#[command(about = "Monitor and restrict HTTP/HTTPS requests from processes")]
struct Args {
    /// Use script for evaluating requests
    /// The script receives environment variables:
    ///   HTTPJAIL_URL, HTTPJAIL_METHOD, HTTPJAIL_HOST, HTTPJAIL_SCHEME, HTTPJAIL_PATH
    /// Exit code 0 allows the request, non-zero blocks it
    /// stdout becomes additional context in the 403 response
    #[arg(short = 's', long = "script", value_name = "PROG")]
    script: Option<String>,

    /// Use JavaScript (V8) for evaluating requests
    /// The JavaScript code receives global variables:
    ///   url, method, host, scheme, path
    /// Should return true to allow the request, false to block it
    /// Example: --js "return host === 'github.com' && method === 'GET'"
    #[arg(
        long = "js",
        value_name = "CODE",
        conflicts_with = "script",
        conflicts_with = "js_file"
    )]
    js: Option<String>,

    /// Load JavaScript (V8) rule code from a file
    /// Conflicts with --js
    #[arg(
        long = "js-file",
        value_name = "FILE",
        conflicts_with = "script",
        conflicts_with = "js"
    )]
    js_file: Option<String>,

    /// Append requests to a log file
    #[arg(long = "request-log", value_name = "FILE")]
    request_log: Option<String>,

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

    /// Evaluate rule against a URL and exit (dry-run)
    #[arg(
        long = "test",
        value_name = "[METHOD] URL",
        conflicts_with = "server",
        conflicts_with = "cleanup"
    )]
    test: Option<String>,

    /// Command and arguments to execute
    #[arg(trailing_var_arg = true, required_unless_present_any = ["cleanup", "server", "test"])]
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

/// Direct orphan cleanup without creating jails
fn cleanup_orphans() -> Result<()> {
    use anyhow::Context;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};
    use tracing::{debug, info};

    let canary_dir = PathBuf::from("/tmp/httpjail");
    let orphan_timeout = Duration::from_secs(5); // Short timeout to catch recent orphans

    debug!("Starting direct orphan cleanup scan");

    // Track jail IDs we've cleaned up to avoid duplicates
    #[allow(unused_mut)] // mut is needed on Linux but not macOS
    let mut cleaned_jails = std::collections::HashSet::<String>::new();

    // First, scan for stale canary files
    if canary_dir.exists() {
        debug!("Scanning canary directory: {:?}", canary_dir);
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
                    "Found orphaned jail '{}' via canary file (age: {:?}), cleaning up",
                    jail_id, age
                );

                // Call platform-specific cleanup
                #[cfg(target_os = "linux")]
                {
                    <httpjail::jail::linux::LinuxJail as httpjail::jail::Jail>::cleanup_orphaned(
                        jail_id,
                    )?;
                    cleaned_jails.insert(jail_id.to_string());
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
    } else {
        debug!("Canary directory does not exist");
    }

    // On Linux, also scan for orphaned namespace configs directly
    // This handles cases where canary files were deleted (e.g., /tmp cleanup)
    #[cfg(target_os = "linux")]
    {
        let netns_dir = PathBuf::from("/etc/netns");
        if netns_dir.exists() {
            debug!("Scanning for orphaned namespace configs in {:?}", netns_dir);
            for entry in fs::read_dir(&netns_dir)? {
                let entry = entry?;
                let path = entry.path();
                let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

                // Only process httpjail namespace configs
                if name.starts_with("httpjail_") && !cleaned_jails.contains(name) {
                    info!(
                        "Found orphaned namespace config '{}' without canary file, cleaning up",
                        name
                    );

                    <httpjail::jail::linux::LinuxJail as httpjail::jail::Jail>::cleanup_orphaned(
                        name,
                    )?;
                    cleaned_jails.insert(name.to_string());
                }
            }
        }
    }

    if cleaned_jails.is_empty() {
        debug!("No orphaned jails found");
    } else {
        info!("Cleaned up {} orphaned jail(s)", cleaned_jails.len());
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

    // Build rule engine based on script or JS
    let request_log = if let Some(path) = &args.request_log {
        Some(Arc::new(Mutex::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("Failed to open request log file: {}", path))?,
        )))
    } else {
        None
    };

    let rule_engine = if let Some(script) = &args.script {
        info!("Using script-based rule evaluation: {}", script);
        let script_engine = Box::new(ScriptRuleEngine::new(script.clone()));
        RuleEngine::from_trait(script_engine, request_log)
    } else if let Some(js_code) = &args.js {
        info!("Using V8 JavaScript rule evaluation");
        let js_engine = match V8JsRuleEngine::new(js_code.clone()) {
            Ok(engine) => Box::new(engine),
            Err(e) => {
                eprintln!("Failed to create V8 JavaScript engine: {}", e);
                std::process::exit(1);
            }
        };
        RuleEngine::from_trait(js_engine, request_log)
    } else if let Some(js_file) = &args.js_file {
        info!("Using V8 JavaScript rule evaluation from file: {}", js_file);
        let code = std::fs::read_to_string(js_file)
            .with_context(|| format!("Failed to read JS file: {}", js_file))?;
        let js_engine = match V8JsRuleEngine::new(code) {
            Ok(engine) => Box::new(engine),
            Err(e) => {
                eprintln!("Failed to create V8 JavaScript engine: {}", e);
                std::process::exit(1);
            }
        };
        RuleEngine::from_trait(js_engine, request_log)
    } else {
        info!("No rule evaluation provided; defaulting to deny-all");
        let js_engine = match V8JsRuleEngine::new("false".to_string()) {
            Ok(engine) => Box::new(engine),
            Err(e) => {
                eprintln!("Failed to create default V8 JavaScript engine: {}", e);
                std::process::exit(1);
            }
        };
        RuleEngine::from_trait(js_engine, request_log)
    };

    // Handle test (dry-run) mode: evaluate the rule against a URL and exit
    if let Some(test_arg) = &args.test {
        // Parse the test argument: if it contains two words, the first is the method
        let (method, url) = if let Some(space_pos) = test_arg.find(' ') {
            let method_str = &test_arg[..space_pos];
            let url = &test_arg[space_pos + 1..].trim();

            // Parse the method string
            let method = match method_str.to_uppercase().as_str() {
                "GET" => Method::GET,
                "POST" => Method::POST,
                "PUT" => Method::PUT,
                "DELETE" => Method::DELETE,
                "HEAD" => Method::HEAD,
                "OPTIONS" => Method::OPTIONS,
                "CONNECT" => Method::CONNECT,
                "PATCH" => Method::PATCH,
                "TRACE" => Method::TRACE,
                _ => {
                    eprintln!("Invalid HTTP method: {}", method_str);
                    std::process::exit(1);
                }
            };
            (method, url.to_string())
        } else {
            // Single word: default to GET
            (Method::GET, test_arg.clone())
        };

        let eval = rule_engine
            .evaluate_with_context(method.clone(), &url)
            .await;
        match eval.action {
            Action::Allow => {
                println!("ALLOW {} {}", method, url);
                if let Some(ctx) = eval.context {
                    println!("{}", ctx);
                }
                std::process::exit(0);
            }
            Action::Deny => {
                println!("DENY {} {}", method, url);
                if let Some(ctx) = eval.context {
                    println!("{}", ctx);
                }
                std::process::exit(1);
            }
        }
    }

    // Parse bind configuration from env vars
    // Supports both "port" and "ip:port" formats
    fn parse_bind_config(env_var: &str) -> (Option<u16>, Option<std::net::IpAddr>) {
        if let Ok(val) = std::env::var(env_var) {
            if let Some(colon_pos) = val.rfind(':') {
                // Try to parse as ip:port
                let ip_str = &val[..colon_pos];
                let port_str = &val[colon_pos + 1..];
                match port_str.parse::<u16>() {
                    Ok(port) => match ip_str.parse::<std::net::IpAddr>() {
                        Ok(ip) => (Some(port), Some(ip)),
                        Err(_) => (Some(port), None),
                    },
                    Err(_) => (None, None),
                }
            } else {
                // Try to parse as port
                match val.parse::<u16>() {
                    Ok(port) => (Some(port), None),
                    Err(_) => (None, None),
                }
            }
        } else {
            (None, None)
        }
    }

    // Determine ports to bind
    let (http_port, _http_ip) = parse_bind_config("HTTPJAIL_HTTP_BIND");
    let (https_port, _https_ip) = parse_bind_config("HTTPJAIL_HTTPS_BIND");

    // For strong jail mode (not weak, not server), we need to bind to all interfaces (0.0.0.0)
    // so the proxy is accessible from the veth interface. For weak mode or server mode,
    // localhost is fine.
    // TODO: This has security implications - see GitHub issue #31
    let bind_address = if args.weak || args.server {
        None // defaults to 127.0.0.1
    } else {
        Some([0, 0, 0, 0]) // bind to all interfaces for strong jail
    };
    let mut proxy = ProxyServer::new(http_port, https_port, rule_engine, bind_address);

    // Start proxy in background if running as server; otherwise start with random ports
    let (actual_http_port, actual_https_port) = proxy.start().await?;

    if args.server {
        info!(
            "Proxy server running on http://localhost:{} and https://localhost:{}",
            actual_http_port, actual_https_port
        );
        std::future::pending::<()>().await;
        unreachable!();
    }

    // Create jail canary dir early to reduce race with cleanup
    std::fs::create_dir_all("/tmp/httpjail").ok();

    // Configure and execute the target command inside a jail
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
