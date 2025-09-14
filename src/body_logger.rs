use bytes::Buf;
use http_body::{Body, Frame, SizeHint};
use hyper::body::Incoming;
use std::fs::File;
use std::io::Write;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

/// Maximum size of body to log before truncation (default: 1MB)
const DEFAULT_MAX_BODY_LOG_SIZE: usize = 1024 * 1024;

/// Get the maximum body log size from environment or use default
fn get_max_body_log_size() -> usize {
    std::env::var("HTTPJAIL_REQUEST_LOG_BODY_MAX")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_BODY_LOG_SIZE)
}

/// Configuration for body logging
#[derive(Clone)]
pub struct BodyLogConfig {
    pub log_file: Arc<Mutex<File>>,
    pub request_id: String,
    pub enabled: bool,
}

/// A wrapper around request bodies that logs data as it streams through
pub struct LoggingRequestBody {
    inner: Incoming,
    config: BodyLogConfig,
    bytes_logged: usize,
    chunk_index: usize,
    max_size: usize,
    truncated: bool,
}

impl LoggingRequestBody {
    pub fn new(inner: Incoming, config: BodyLogConfig) -> Self {
        Self {
            inner,
            config,
            bytes_logged: 0,
            chunk_index: 0,
            max_size: get_max_body_log_size(),
            truncated: false,
        }
    }

    fn log_chunk(&mut self, data: &[u8]) {
        if self.truncated {
            return;
        }

        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        // Check if we should truncate
        if self.bytes_logged + data.len() > self.max_size {
            if let Ok(mut file) = self.config.log_file.lock() {
                let _ = writeln!(
                    file,
                    "{} --> {}:BODY:TRUNCATED at {} bytes",
                    timestamp, self.config.request_id, self.max_size
                );
            }
            self.truncated = true;
            return;
        }

        // Try to log as UTF-8 text, fall back to base64 for binary
        if let Ok(text) = std::str::from_utf8(data) {
            if let Ok(mut file) = self.config.log_file.lock() {
                if self.chunk_index == 0 {
                    let _ = writeln!(
                        file,
                        "{} --> {}:BODY {}",
                        timestamp, self.config.request_id, text
                    );
                } else {
                    let _ = writeln!(
                        file,
                        "{} --> {}:BODY:CHUNK:{} {}",
                        timestamp, self.config.request_id, self.chunk_index, text
                    );
                }
            }
        } else {
            // Binary data - log as base64
            use base64::{Engine, engine::general_purpose::STANDARD};
            let encoded = STANDARD.encode(data);
            if let Ok(mut file) = self.config.log_file.lock() {
                let _ = writeln!(
                    file,
                    "{} --> {}:BODY:BINARY [base64] {}",
                    timestamp, self.config.request_id, encoded
                );
            }
        }

        self.bytes_logged += data.len();
        self.chunk_index += 1;
    }

    fn log_end(&mut self) {
        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        if let Ok(mut file) = self.config.log_file.lock() {
            if self.bytes_logged == 0 {
                let _ = writeln!(
                    file,
                    "{} --> {}:BODY:EMPTY",
                    timestamp, self.config.request_id
                );
            } else if self.chunk_index > 1 {
                let _ = writeln!(
                    file,
                    "{} --> {}:BODY:END {} chunks, {} bytes",
                    timestamp, self.config.request_id, self.chunk_index, self.bytes_logged
                );
            } else {
                let _ = writeln!(
                    file,
                    "{} --> {}:BODY:END {} bytes",
                    timestamp, self.config.request_id, self.bytes_logged
                );
            }
        }
    }
}

impl Body for LoggingRequestBody {
    type Data = <Incoming as Body>::Data;
    type Error = <Incoming as Body>::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let inner = Pin::new(&mut self.inner);
        match inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                // Log data frames
                if let Some(data) = frame.data_ref() {
                    let bytes = data.chunk();
                    self.log_chunk(bytes);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                // End of body
                self.log_end();
                Poll::Ready(None)
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// A wrapper around response bodies that logs data as it streams through
pub struct LoggingResponseBody<B> {
    inner: B,
    config: BodyLogConfig,
    bytes_logged: usize,
    chunk_index: usize,
    max_size: usize,
    truncated: bool,
}

impl<B> LoggingResponseBody<B> {
    pub fn new(inner: B, config: BodyLogConfig) -> Self {
        Self {
            inner,
            config,
            bytes_logged: 0,
            chunk_index: 0,
            max_size: get_max_body_log_size(),
            truncated: false,
        }
    }

    fn log_chunk(&mut self, data: &[u8]) {
        if self.truncated {
            return;
        }

        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

        // Check if we should truncate
        if self.bytes_logged + data.len() > self.max_size {
            if let Ok(mut file) = self.config.log_file.lock() {
                let _ = writeln!(
                    file,
                    "{} <-- {}:BODY:TRUNCATED at {} bytes",
                    timestamp, self.config.request_id, self.max_size
                );
            }
            self.truncated = true;
            return;
        }

        // Try to log as UTF-8 text, fall back to base64 for binary
        if let Ok(text) = std::str::from_utf8(data) {
            if let Ok(mut file) = self.config.log_file.lock() {
                if self.chunk_index == 0 {
                    let _ = writeln!(
                        file,
                        "{} <-- {}:BODY {}",
                        timestamp, self.config.request_id, text
                    );
                } else {
                    let _ = writeln!(
                        file,
                        "{} <-- {}:BODY:CHUNK:{} {}",
                        timestamp, self.config.request_id, self.chunk_index, text
                    );
                }
            }
        } else {
            // Binary data - log as base64
            use base64::{Engine, engine::general_purpose::STANDARD};
            let encoded = STANDARD.encode(data);
            if let Ok(mut file) = self.config.log_file.lock() {
                let _ = writeln!(
                    file,
                    "{} <-- {}:BODY:BINARY [base64] {}",
                    timestamp, self.config.request_id, encoded
                );
            }
        }

        self.bytes_logged += data.len();
        self.chunk_index += 1;
    }

    fn log_end(&mut self) {
        let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        if let Ok(mut file) = self.config.log_file.lock() {
            if self.bytes_logged == 0 {
                let _ = writeln!(
                    file,
                    "{} <-- {}:BODY:EMPTY",
                    timestamp, self.config.request_id
                );
            } else if self.chunk_index > 1 {
                let _ = writeln!(
                    file,
                    "{} <-- {}:BODY:END {} chunks, {} bytes",
                    timestamp, self.config.request_id, self.chunk_index, self.bytes_logged
                );
            } else {
                let _ = writeln!(
                    file,
                    "{} <-- {}:BODY:END {} bytes",
                    timestamp, self.config.request_id, self.bytes_logged
                );
            }
        }
    }
}

impl<B> Body for LoggingResponseBody<B>
where
    B: Body + Unpin,
    B::Data: Buf,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // Get mutable reference to self through projection
        let this = self.get_mut();

        // Poll the inner body
        let inner = Pin::new(&mut this.inner);
        match inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                // Log data frames
                if let Some(data) = frame.data_ref() {
                    let bytes = data.chunk();
                    this.log_chunk(bytes);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(None) => {
                // End of body
                this.log_end();
                Poll::Ready(None)
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use std::fs::OpenOptions;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_request_body_logging() {
        let log_file = NamedTempFile::new().unwrap();
        let file = OpenOptions::new()
            .append(true)
            .open(log_file.path())
            .unwrap();

        let _config = BodyLogConfig {
            log_file: Arc::new(Mutex::new(file)),
            request_id: "test1".to_string(),
            enabled: true,
        };

        // Create a simple body
        let body_data = "Hello, World!";
        let _inner = Full::new(Bytes::from(body_data)).into_data_stream();

        // Note: This test would need a proper Incoming body to work fully
        // For now, it demonstrates the structure
    }

    #[tokio::test]
    async fn test_response_body_logging() {
        let log_file = NamedTempFile::new().unwrap();
        let file = OpenOptions::new()
            .append(true)
            .open(log_file.path())
            .unwrap();

        let config = BodyLogConfig {
            log_file: Arc::new(Mutex::new(file)),
            request_id: "test2".to_string(),
            enabled: true,
        };

        // Create a simple body
        let body_data = "Response data";
        let inner = Full::new(Bytes::from(body_data));
        let logging_body = LoggingResponseBody::new(inner, config);

        // Collect the body to trigger logging
        let _collected = logging_body.collect().await;

        // Check log file contains expected output
        let contents = std::fs::read_to_string(log_file.path()).unwrap();
        assert!(contents.contains("test2:BODY"));
    }
}
