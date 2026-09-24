use anyhow::{Context, Result};
use clap::Parser;
use httpjail::jail::{JailConfig, create_jail};
use httpjail::proxy::ProxyServer;
use httpjail::rules::proc::ProcRuleEngine;
use httpjail::rules::shell::ShellRuleEngine;
use httpjail::rules::v8_js::V8JsRuleEngine;
use httpjail::rules::{Action, RuleEngine};
use hyper::Method;
use std::fs::OpenOptions;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

#[derive(Parser, Debug)]
#[command(name = "httpjail")]
#[command(version = env!("VERSION_WITH_GIT_HASH"), about, long_about = None)]
#[command(about = "Monitor and restrict HTTP/HTTPS requests from processes")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    run_args: RunArgs,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    #[cfg(target_os = "macos")]
    /// Manage CA certificate trust
    Trust {
        /// Install the httpjail CA certificate to the system keychain
        #[arg(long)]
        install: bool,

        /// Remove the httpjail CA certificate from the system keychain
        #[arg(long, conflicts_with = "install")]
        remove: bool,
    },
}

#[derive(Parser, Debug)]
struct RunArgs {
    /// Use shell script for evaluating requests
    /// The script receives environment variables:
    ///   HTTPJAIL_URL, HTTPJAIL_METHOD, HTTPJAIL_HOST, HTTPJAIL_SCHEME, HTTPJAIL_PATH
    /// Exit code 0 allows the request, non-zero blocks it
    /// stdout becomes additional context in the 403 response
    #[arg(long = "sh", value_name = "SCRIPT")]
    sh: Option<String>,

    /// Use persistent program for evaluating requests (line processor)
    /// The program receives JSON on stdin (one request per line) and outputs per line.
    /// Output: "true"/"false" or JSON {"allow": bool, "deny_message": "..."}
    #[arg(long = "proc", value_name = "PATH", conflicts_with = "sh")]
    proc: Option<String>,

    /// Use JavaScript (V8) expression for evaluating requests
    /// The JavaScript expression receives an object 'r' with properties:
    ///   r.url, r.method, r.host, r.scheme, r.path
    /// Should evaluate to true to allow the request, false to block it
    /// Example: --js "r.host === 'github.com' && r.method === 'GET'"
    #[arg(
        long = "js",
        value_name = "CODE",
        conflicts_with = "sh",
        conflicts_with = "proc",
        conflicts_with = "js_file"
    )]
    js: Option<String>,

    /// Load JavaScript (V8) rule code from a file
    /// Conflicts with --js
    #[arg(
        long = "js-file",
        value_name = "FILE",
        conflicts_with = "sh",
        conflicts_with = "proc",
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
        num_args = 1..=2,
        conflicts_with = "server",
        conflicts_with = "cleanup"
    )]
    test: Option<Vec<String>>,

    /// Run a Docker container with httpjail network isolation
    /// All arguments after -- are passed to docker run
    #[arg(
        long = "docker-run",
        conflicts_with = "server",
        conflicts_with = "cleanup",
        conflicts_with = "test",
        conflicts_with = "weak"
    )]
    docker_run: bool,

    /// Command and arguments to execute  
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    exec_command: Vec<String>,
}

#[cfg(target_os = "linux")]
fn trusted_policy_path(path: &str, shell_rule: bool) -> Result<String> {
    use std::os::unix::fs::MetadataExt;

    anyhow::ensure!(
        !shell_rule || !path.chars().any(char::is_whitespace),
        "Linux strong mode requires --sh to name one trusted executable, not a shell command"
    );
    let resolved = std::fs::canonicalize(path)
        .with_context(|| format!("Failed to resolve rule executable: {path}"))?;
    for component in resolved.ancestors() {
        let metadata = std::fs::metadata(component)?;
        anyhow::ensure!(
            metadata.uid() == 0 && metadata.mode() & 0o022 == 0,
            "Linux strong mode requires root-owned, non-writable rule executable and ancestors: {}",
            component.display()
        );
    }
    Ok(resolved
        .to_str()
        .context("Rule executable path must be UTF-8")?
        .to_string())
}

#[cfg(target_os = "linux")]
fn open_request_log_as_invoker(path: &str) -> Result<std::fs::File> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;

    let uid = std::env::var("SUDO_UID")
        .context("Root request logs require an invoking sudo user")?
        .parse::<u32>()?;
    let gid = std::env::var("SUDO_GID")
        .context("Root request logs require an invoking sudo group")?
        .parse::<u32>()?;
    anyhow::ensure!(
        uid != 0,
        "Root request logs require a non-root invoking user"
    );

    let path = Path::new(path);
    let name = path.file_name().context("Request log needs a filename")?;
    anyhow::ensure!(name != "." && name != "..", "Invalid request log name");
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    // Pin a directory the invoking user owns. Even if a parent pathname is
    // swapped afterward, openat stays anchored to this checked directory.
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)
        .context("Failed to open request-log directory")?;
    anyhow::ensure!(
        dir.metadata()?.uid() == uid,
        "Request-log directory must be owned by invoking user"
    );
    let name = CString::new(name.as_bytes())?;
    let flags =
        libc::O_WRONLY | libc::O_APPEND | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    let (fd, created) = unsafe {
        let fd = libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CREAT | libc::O_EXCL,
            0o600,
        );
        if fd >= 0 {
            (fd, true)
        } else if std::io::Error::last_os_error().kind() == std::io::ErrorKind::AlreadyExists {
            (libc::openat(dir.as_raw_fd(), name.as_ptr(), flags), false)
        } else {
            return Err(std::io::Error::last_os_error().into());
        }
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    anyhow::ensure!(metadata.is_file(), "Request log must be a regular file");
    if created {
        let result = unsafe { libc::fchown(fd, uid, gid) };
        anyhow::ensure!(result == 0, "Failed to assign request log to invoking user");
    } else {
        anyhow::ensure!(
            metadata.uid() == uid,
            "Existing request log must be owned by invoking user"
        );
    }
    Ok(file)
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
        // Default (0) shows warn and error, -v shows info, -vv shows debug, -vvv shows trace
        let level = match verbosity {
            0 => "warn",
            1 => "info",
            2 => "debug",
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
    use std::time::{Duration, SystemTime};
    use tracing::{debug, info};

    let canary_dir = httpjail::jail::get_canary_dir();
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
                if !httpjail::jail::valid_jail_id(jail_id)
                    || httpjail::jail::canary_owner_alive(&path)
                {
                    debug!("Skipping live or invalid jail canary: {:?}", path);
                    continue;
                }

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

    // A namespace without a trusted canary may still belong to a live older
    // jail (possibly under another user's legacy HOME). Never infer it is dead
    // just from a missing canary. Orphaned canaryless namespaces need manual
    // administrator inspection instead of automatic destructive cleanup.

    if cleaned_jails.is_empty() {
        debug!("No orphaned jails found");
    } else {
        info!("Cleaned up {} orphaned jail(s)", cleaned_jails.len());
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Note: The internal DNS server functionality has been removed in favor of
    // mounting a custom /etc/resolv.conf. All DNS queries now go directly to the
    // host-side DNS server bound to host_ip.

    let args = Args::parse();

    // Handle trust subcommand (takes precedence)
    #[cfg(target_os = "macos")]
    if let Some(Command::Trust { install, remove }) = &args.command {
        setup_logging(0); // Minimal logging for trust commands

        use httpjail::macos_keychain::KeychainManager;
        let keychain_manager = KeychainManager::new();

        if !*install && !*remove {
            // Default to status if no flags provided
            match keychain_manager.is_ca_trusted() {
                Ok(true) => {
                    println!("✓ httpjail CA certificate is trusted in keychain");
                    return Ok(());
                }
                Ok(false) => {
                    println!("✗ httpjail CA certificate is NOT trusted in keychain");
                    println!("Run 'httpjail trust --install' to enable HTTPS interception");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Error checking trust status: {}", e);
                    std::process::exit(1);
                }
            }
        }

        if *install {
            // Repair incomplete credentials before trusting the public certificate.
            let _ = httpjail::tls::CertificateManager::new()?;
            let ca_cert_path = httpjail::tls::CertificateManager::get_ca_cert_path()?;
            keychain_manager.install_ca(ca_cert_path.as_std_path())?;
            println!("✓ httpjail CA certificate installed successfully");
            return Ok(());
        }

        if *remove {
            keychain_manager.uninstall_ca()?;
            return Ok(());
        }
    }

    // Server mode defaults to INFO level logging for visibility
    let verbosity = args
        .run_args
        .verbose
        .max(if args.run_args.server { 1 } else { 0 });
    setup_logging(verbosity);

    // Log the version at startup for easier diagnostics
    debug!("httpjail version: {}", env!("VERSION_WITH_GIT_HASH"));

    debug!("Starting httpjail with args: {:?}", args.run_args);

    // Handle cleanup flag
    if args.run_args.cleanup {
        info!("Running orphan cleanup and exiting...");

        // Directly call platform-specific orphan cleanup without creating jails
        cleanup_orphans()?;

        info!("Cleanup completed successfully");
        return Ok(());
    }

    // Handle server mode
    if args.run_args.server {
        info!("Starting httpjail in server mode");
    }

    // Initialize jail configuration early to allow computing the host IP
    let mut jail_config = JailConfig::new();

    // Build rule engine based on script or JS
    let request_log = if let Some(path) = &args.run_args.request_log {
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        #[cfg(target_os = "linux")]
        let file = if unsafe { libc::geteuid() == 0 } {
            open_request_log_as_invoker(path)
        } else {
            options.open(path).map_err(Into::into)
        };
        #[cfg(not(target_os = "linux"))]
        let file: Result<std::fs::File> = options.open(path).map_err(Into::into);
        Some(Arc::new(Mutex::new(file.with_context(|| {
            format!("Failed to open request log file: {}", path)
        })?)))
    } else {
        None
    };

    #[cfg(target_os = "linux")]
    // Dry-run evaluates rules too; it must not bypass root rule-engine restrictions.
    let strong_rule = unsafe { libc::geteuid() == 0 };

    let rule_engine = if let Some(script) = &args.run_args.sh {
        #[cfg(target_os = "linux")]
        let script = if strong_rule {
            trusted_policy_path(script, true)?
        } else {
            script.clone()
        };
        #[cfg(not(target_os = "linux"))]
        let script = script.clone();
        info!("Using shell script rule evaluation: {}", script);
        let shell_engine = ShellRuleEngine::new(script);
        #[cfg(target_os = "linux")]
        let shell_engine = if strong_rule {
            shell_engine.restricted()
        } else {
            shell_engine
        };
        RuleEngine::from_trait(Box::new(shell_engine), request_log)
    } else if let Some(proc) = &args.run_args.proc {
        #[cfg(target_os = "linux")]
        let proc = if strong_rule {
            trusted_policy_path(proc, false)?
        } else {
            proc.clone()
        };
        #[cfg(not(target_os = "linux"))]
        let proc = proc.clone();
        info!("Using line processor rule evaluation: {}", proc);
        let proc_engine = ProcRuleEngine::new(proc);
        #[cfg(target_os = "linux")]
        let proc_engine = if strong_rule {
            proc_engine.restricted()
        } else {
            proc_engine
        };
        RuleEngine::from_trait(Box::new(proc_engine), request_log)
    } else if let Some(js_code) = &args.run_args.js {
        info!("Using V8 JavaScript rule evaluation");
        let js_engine = match V8JsRuleEngine::new(js_code.clone()) {
            Ok(engine) => Box::new(engine),
            Err(e) => {
                eprintln!("Failed to create V8 JavaScript engine: {}", e);
                std::process::exit(1);
            }
        };
        RuleEngine::from_trait(js_engine, request_log)
    } else if let Some(js_file) = &args.run_args.js_file {
        info!("Using V8 JavaScript rule evaluation from file: {}", js_file);
        let code = std::fs::read_to_string(js_file)
            .with_context(|| format!("Failed to read JS file: {}", js_file))?;
        // A jailed command may share write access to this file. Freeze the
        // policy while it executes; hot reload is safe only in server mode,
        // where no untrusted command is launched by this process.
        let reload_path = args
            .run_args
            .server
            .then(|| std::path::PathBuf::from(js_file));
        let js_engine = match V8JsRuleEngine::new_with_file(code, reload_path) {
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
    if let Some(test_vals) = &args.run_args.test {
        let (method, url) = if test_vals.len() == 1 {
            let s = &test_vals[0];
            let mut parts = s.split_whitespace();
            match (parts.next(), parts.next()) {
                (Some(maybe_method), Some(url_rest)) => {
                    let method_str = maybe_method.to_ascii_uppercase();
                    let method = method_str.parse::<Method>().unwrap_or(Method::GET);
                    (method, url_rest.to_string())
                }
                _ => (Method::GET, s.clone()),
            }
        } else {
            let maybe_method = &test_vals[0];
            let url = &test_vals[1];
            let method_str = maybe_method.to_ascii_uppercase();
            let method = method_str.parse::<Method>().unwrap_or(Method::GET);
            (method, url.clone())
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
    // Returns Some(addr) for "port", ":port", or "ip:port" formats (including explicit :0)
    // Returns None for "ip" only or missing config
    fn parse_bind_config(env_var: &str) -> Option<std::net::SocketAddr> {
        if let Ok(val) = std::env::var(env_var) {
            let val = val.trim();

            // First try parsing as "ip:port" (respects explicit :0)
            if let Ok(addr) = val.parse::<std::net::SocketAddr>() {
                return Some(addr);
            }

            // Try parsing as ":port" (Go-style) - bind to all interfaces (0.0.0.0)
            if let Some(port_str) = val.strip_prefix(':')
                && let Ok(port) = port_str.parse::<u16>()
            {
                return Some(std::net::SocketAddr::from(([0, 0, 0, 0], port)));
            }

            // Try parsing as just a port number - bind to all interfaces (0.0.0.0)
            if let Ok(port) = val.parse::<u16>() {
                return Some(std::net::SocketAddr::from(([0, 0, 0, 0], port)));
            }
        }
        None
    }

    // Parse IP-only from env var (for default port handling)
    fn parse_ip_from_env(env_var: &str) -> Option<std::net::IpAddr> {
        std::env::var(env_var).ok()?.parse().ok()
    }

    // Resolve bind address with optional default port for IP-only configs
    fn resolve_bind_with_default(
        parsed: Option<std::net::SocketAddr>,
        env_var: &str,
        default_ip: std::net::IpAddr,
        default_port: u16,
    ) -> Option<std::net::SocketAddr> {
        match parsed {
            Some(addr) => Some(addr), // Respect explicit config including :0
            None => {
                // Check if user provided just IP without port
                if let Some(ip) = parse_ip_from_env(env_var) {
                    Some(std::net::SocketAddr::new(ip, default_port))
                } else {
                    Some(std::net::SocketAddr::new(default_ip, default_port))
                }
            }
        }
    }

    // Determine bind addresses
    let http_bind = parse_bind_config("HTTPJAIL_HTTP_BIND");
    let https_bind = parse_bind_config("HTTPJAIL_HTTPS_BIND");

    // For strong jail mode (not weak, not server), we need to bind to a specific IP
    // so the proxy is accessible from the veth interface. For weak mode or server mode,
    // use the configured address or defaults.
    // TODO: This has security implications - see GitHub issue #31
    let (http_bind, https_bind) = if args.run_args.server {
        // Server mode: default to localhost:8080/8443, respect explicit ports including :0
        let localhost = std::net::IpAddr::from([127, 0, 0, 1]);
        let http = resolve_bind_with_default(http_bind, "HTTPJAIL_HTTP_BIND", localhost, 8080);
        let https = resolve_bind_with_default(https_bind, "HTTPJAIL_HTTPS_BIND", localhost, 8443);
        (http, https)
    } else if args.run_args.weak {
        // Weak mode: If IP-only provided, use port 0 (OS auto-select), else None
        let http = http_bind.or_else(|| {
            parse_ip_from_env("HTTPJAIL_HTTP_BIND").map(|ip| std::net::SocketAddr::new(ip, 0))
        });
        let https = https_bind.or_else(|| {
            parse_ip_from_env("HTTPJAIL_HTTPS_BIND").map(|ip| std::net::SocketAddr::new(ip, 0))
        });
        (http, https)
    } else {
        #[cfg(target_os = "linux")]
        {
            let jail_ip =
                httpjail::jail::linux::LinuxJail::compute_host_ip_for_jail_id(&jail_config.jail_id);
            // For strong jail mode, we need to bind to the jail IP.
            // Use env var port if provided, otherwise use port 0 (auto-select) on jail IP.
            let http_addr = match http_bind {
                Some(addr) => std::net::SocketAddr::from((jail_ip, addr.port())),
                None => std::net::SocketAddr::from((jail_ip, 0)), // Port 0 = auto-select
            };
            let https_addr = match https_bind {
                Some(addr) => std::net::SocketAddr::from((jail_ip, addr.port())),
                None => std::net::SocketAddr::from((jail_ip, 0)),
            };
            (Some(http_addr), Some(https_addr))
        }
        #[cfg(not(target_os = "linux"))]
        {
            (http_bind, https_bind)
        }
    };

    let mut proxy = ProxyServer::new(http_bind, https_bind, rule_engine);

    // Start proxy in background if running as server; otherwise start with random ports
    let (actual_http_port, actual_https_port) = proxy.start().await?;

    if args.run_args.server {
        let bind_str = |addr: Option<std::net::SocketAddr>| {
            addr.map(|a| a.ip().to_string())
                .unwrap_or_else(|| "localhost".to_string())
        };
        info!(
            "Proxy server running on http://{}:{} and https://{}:{}",
            bind_str(http_bind),
            actual_http_port,
            bind_str(https_bind),
            actual_https_port
        );
        std::future::pending::<()>().await;
        unreachable!();
    }

    // Create jail canary dir early to reduce race with cleanup
    let canary_dir = httpjail::jail::get_canary_dir();
    std::fs::create_dir_all(&canary_dir).ok();

    // Configure and execute the target command inside a jail
    jail_config.http_proxy_port = actual_http_port;
    jail_config.https_proxy_port = actual_https_port;

    // Create and setup jail
    let mut jail = create_jail(
        jail_config.clone(),
        args.run_args.weak,
        args.run_args.docker_run,
    )?;

    // Setup jail (pass 0 as the port parameter is ignored)
    jail.setup(0)?;

    // Wrap jail in Arc for potential sharing with timeout task and signal handler
    let jail = std::sync::Arc::new(jail);

    // Set up signal handler for cleanup
    let shutdown = Arc::new(AtomicBool::new(false));
    let jail_for_signal = jail.clone();
    let shutdown_clone = shutdown.clone();
    let no_cleanup = args.run_args.no_jail_cleanup;

    // Set up signal handler for SIGINT and SIGTERM
    ctrlc::set_handler(move || {
        if !shutdown_clone.load(Ordering::SeqCst) {
            info!("Received interrupt signal, cleaning up...");
            shutdown_clone.store(true, Ordering::SeqCst);

            // Attempt cleanup only if no_cleanup is false
            if !no_cleanup && let Err(e) = jail_for_signal.cleanup() {
                warn!("Failed to cleanup jail on signal: {}", e);
            }

            // Always exit with signal termination status
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

    // Inject glibc resolver timeouts to avoid long DNS hangs if not already set
    if std::env::var("RES_OPTIONS").is_err() && !extra_env.iter().any(|(k, _)| k == "RES_OPTIONS") {
        debug!("Setting glibc resolver timeouts via RES_OPTIONS=timeout:2 attempts:1");
        extra_env.push((
            "RES_OPTIONS".to_string(),
            "timeout:2 attempts:1".to_string(),
        ));
    } else {
        debug!("RES_OPTIONS already present; not overriding existing setting");
    }

    // Execute command in jail with extra environment variables
    let status = if let Some(timeout_secs) = args.run_args.timeout {
        info!("Executing command with {}s timeout", timeout_secs);

        let command = args.run_args.exec_command.clone();
        let jail_clone = jail.clone();
        let duration = std::time::Duration::from_secs(timeout_secs);
        // Keep the blocking task alive until it has killed and reaped the child.
        // Detaching a timed-out spawn_blocking task would let it run after jail cleanup.
        let status = tokio::task::spawn_blocking(move || {
            jail_clone.execute_with_timeout(&command, &extra_env, duration)
        })
        .await
        .context("Command execution task failed")??;
        if status.code() == Some(124) {
            warn!("Command timed out after {}s", timeout_secs);
        }
        status
    } else {
        jail.execute(&args.run_args.exec_command, &extra_env)?
    };

    // Cleanup jail (unless testing flag is set)
    if !args.run_args.no_jail_cleanup {
        jail.cleanup()?;
    } else {
        info!("Skipping jail cleanup (--no-jail-cleanup flag set)");
    }

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }

    Ok(())
}
