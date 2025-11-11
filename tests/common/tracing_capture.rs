use std::sync::{Arc, Mutex};
use tracing::{Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, SubscriberExt};

/// Captured log record
#[derive(Debug, Clone)]
pub struct CapturedLog {
    pub level: Level,
    pub target: String,
    pub message: String,
}

/// Layer that captures log messages for testing
struct CaptureLayer {
    logs: Arc<Mutex<Vec<CapturedLog>>>,
}

impl<S: Subscriber> Layer<S> for CaptureLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let mut visitor = MessageVisitor::new();
        event.record(&mut visitor);

        if let Some(message) = visitor.message {
            let log = CapturedLog {
                level: *metadata.level(),
                target: metadata.target().to_string(),
                message,
            };
            self.logs.lock().unwrap().push(log);
        }
    }
}

/// Visitor to extract message from tracing events
struct MessageVisitor {
    message: Option<String>,
}

impl MessageVisitor {
    fn new() -> Self {
        Self { message: None }
    }
}

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{:?}", value));
            // Remove surrounding quotes from debug output
            if let Some(ref mut msg) = self.message
                && msg.starts_with('"')
                && msg.ends_with('"')
                && msg.len() >= 2
            {
                *msg = msg[1..msg.len() - 1].to_string();
            }
        }
    }
}

/// Set up tracing subscriber that captures logs for testing
pub fn setup_capture() -> Arc<Mutex<Vec<CapturedLog>>> {
    let logs = Arc::new(Mutex::new(Vec::new()));
    let layer = CaptureLayer { logs: logs.clone() };

    let subscriber = tracing_subscriber::registry().with(layer);
    let _ = tracing::subscriber::set_global_default(subscriber);

    logs
}

/// Find logs matching a predicate
pub fn find_logs<F>(logs: &[CapturedLog], predicate: F) -> Vec<CapturedLog>
where
    F: Fn(&CapturedLog) -> bool,
{
    logs.iter().filter(|log| predicate(log)).cloned().collect()
}

/// Find logs with specific target and level
pub fn find_logs_by_target_level(
    logs: &[CapturedLog],
    target: &str,
    level: Level,
) -> Vec<CapturedLog> {
    find_logs(logs, |log| log.target == target && log.level == level)
}

/// Find logs containing specific text
pub fn find_logs_containing(logs: &[CapturedLog], text: &str) -> Vec<CapturedLog> {
    find_logs(logs, |log| log.message.contains(text))
}
