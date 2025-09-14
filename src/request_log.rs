use crate::body_logger::BodyLogConfig;
use crate::rules::{Action, EvaluationResult, RuleEngineTrait};
use async_trait::async_trait;
use chrono::{SecondsFormat, Utc};
use hyper::Method;
use std::fs::File;
use std::io::Write;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

/// Trait for logging HTTP requests
pub trait RequestLogger: Send + Sync {
    /// Log a request with its evaluation result
    fn log_request(
        &self,
        method: &Method,
        url: &str,
        request_id: &str,
        action: &Action,
        context: Option<&str>,
    );

    /// Get body logging configuration if enabled
    fn get_body_log_config(&self, request_id: String) -> Option<BodyLogConfig>;

    /// Check if body logging is enabled
    fn is_body_logging_enabled(&self) -> bool;
}

/// No-op logger that doesn't log anything
pub struct NoopLogger;

impl RequestLogger for NoopLogger {
    fn log_request(
        &self,
        _method: &Method,
        _url: &str,
        _request_id: &str,
        _action: &Action,
        _context: Option<&str>,
    ) {
        // Do nothing
    }

    fn get_body_log_config(&self, _request_id: String) -> Option<BodyLogConfig> {
        None
    }

    fn is_body_logging_enabled(&self) -> bool {
        false
    }
}

/// File-based request logger
pub struct FileRequestLogger {
    log_file: Arc<Mutex<File>>,
    log_bodies: bool,
}

impl FileRequestLogger {
    pub fn new(log_file: Arc<Mutex<File>>, log_bodies: bool) -> Self {
        if log_bodies {
            info!("Request/response body logging enabled");
        }
        Self {
            log_file,
            log_bodies,
        }
    }
}

impl RequestLogger for FileRequestLogger {
    fn log_request(
        &self,
        method: &Method,
        url: &str,
        request_id: &str,
        action: &Action,
        context: Option<&str>,
    ) {
        if let Ok(mut file) = self.log_file.lock() {
            let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
            let status = match action {
                Action::Allow => '+',
                Action::Deny => '-',
            };
            // Include request ID in log line with arrow notation
            let log_line = format!(
                "{} --> {} {} {} {}",
                timestamp, request_id, status, method, url
            );
            if let Err(e) = writeln!(file, "{}", log_line) {
                warn!("Failed to write to request log: {}", e);
            }

            // Log denial reason if present
            if let Action::Deny = action {
                if let Some(context) = context {
                    let denied_line =
                        format!("{} --> {}:DENIED {}", timestamp, request_id, context);
                    if let Err(e) = writeln!(file, "{}", denied_line) {
                        warn!("Failed to write denial context to request log: {}", e);
                    }
                }
            }
        }
    }

    fn get_body_log_config(&self, request_id: String) -> Option<BodyLogConfig> {
        if self.log_bodies {
            Some(BodyLogConfig {
                log_file: Arc::clone(&self.log_file),
                request_id,
                enabled: true,
            })
        } else {
            None
        }
    }

    fn is_body_logging_enabled(&self) -> bool {
        self.log_bodies
    }
}

/// A rule engine wrapper that logs requests and responses
pub struct LoggingRuleEngine {
    engine: Box<dyn RuleEngineTrait>,
    logger: Arc<dyn RequestLogger>,
    request_counter: Arc<AtomicU32>,
}

impl LoggingRuleEngine {
    pub fn new(engine: Box<dyn RuleEngineTrait>, logger: Arc<dyn RequestLogger>) -> Self {
        Self {
            engine,
            logger,
            request_counter: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Generate a unique request ID
    fn generate_request_id(&self) -> String {
        let counter = self.request_counter.fetch_add(1, Ordering::SeqCst);
        format!("{:04x}", counter % 0x10000)
    }

    /// Get the log file handle if body logging is enabled
    pub fn get_body_log_config(&self, request_id: String) -> Option<BodyLogConfig> {
        self.logger.get_body_log_config(request_id)
    }
}

#[async_trait]
impl RuleEngineTrait for LoggingRuleEngine {
    async fn evaluate(&self, method: Method, url: &str, requester_ip: &str) -> EvaluationResult {
        let mut result = self
            .engine
            .evaluate(method.clone(), url, requester_ip)
            .await;

        // Generate request ID for this evaluation
        let request_id = self.generate_request_id();
        result.request_id = request_id.clone();

        // Log the request
        self.logger.log_request(
            &method,
            url,
            &request_id,
            &result.action,
            result.context.as_deref(),
        );

        result
    }

    fn name(&self) -> &str {
        self.engine.name()
    }
}
