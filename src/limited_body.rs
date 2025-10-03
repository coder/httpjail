//! Limited request body wrapper for enforcing byte transmission limits.
//!
//! This module provides `LimitedBody`, a wrapper around Hyper's body types that
//! enforces a maximum byte limit on data transmitted to upstream servers. This is
//! used to implement the `max_tx_bytes` feature in rule responses.
//!
//! # How It Works
//!
//! `LimitedBody` wraps any Hyper `Body` and tracks bytes as frames are polled:
//!
//! 1. **Initialization**: Created with a `max_bytes` limit representing the total
//!    bytes allowed for the request body (headers are counted separately by the caller)
//!
//! 2. **Frame Polling**: As frames are polled from the inner body:
//!    - Frames within the limit are passed through unchanged
//!    - Frames that would exceed the limit are truncated to fit
//!    - Once the limit is reached, the stream terminates (returns `None`)
//!
//! 3. **Partial Frames**: If a frame would partially exceed the limit, only the
//!    bytes up to the limit are transmitted. For example, with 10 bytes remaining
//!    and a 100-byte frame, only the first 10 bytes are sent.
//!
//! # Example Usage
//!
//! ```rust,ignore
//! use httpjail::limited_body::LimitedBody;
//! use http_body_util::BodyExt;
//!
//! // Create a limited body with 1KB limit
//! let limited = LimitedBody::new(original_body, 1024);
//! let boxed = BodyExt::boxed(limited);
//! ```

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::Error as HyperError;
use hyper::body::{Body, Frame, SizeHint};
use std::pin::Pin;
use std::task::{Context, Poll};
use tracing::debug;

/// A body wrapper that enforces a maximum byte transmission limit.
///
/// `LimitedBody` wraps another body and tracks the total bytes transmitted,
/// terminating the stream once the limit is reached. This ensures that
/// no more than `max_bytes` are sent to the upstream server.
///
/// # Behavior
///
/// - **Within Limit**: Frames are passed through unchanged
/// - **At Limit**: Stream terminates immediately (returns `None`)
/// - **Exceeding Limit**: Frame is truncated to fit remaining bytes
/// - **Non-Data Frames**: Trailers and other non-data frames pass through unchanged
///
/// # Example
///
/// ```rust,ignore
/// let body = LimitedBody::new(inner_body, 1024); // Limit to 1KB
/// ```
pub struct LimitedBody {
    /// The wrapped body being limited
    inner: BoxBody<Bytes, HyperError>,
    /// Total bytes transmitted so far
    bytes_transmitted: u64,
    /// Maximum bytes allowed
    max_bytes: u64,
}

impl LimitedBody {
    /// Creates a new `LimitedBody` that limits transmission to `max_bytes`.
    ///
    /// # Arguments
    ///
    /// * `inner` - The body to wrap
    /// * `max_bytes` - Maximum number of bytes to transmit
    ///
    /// # Note
    ///
    /// The caller is responsible for accounting for HTTP header size separately.
    /// This wrapper only limits the request body bytes.
    pub fn new(inner: BoxBody<Bytes, HyperError>, max_bytes: u64) -> Self {
        Self {
            inner,
            bytes_transmitted: 0,
            max_bytes,
        }
    }
}

impl Body for LimitedBody {
    type Data = Bytes;
    type Error = HyperError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // Check if we've already reached the limit
        if self.bytes_transmitted >= self.max_bytes {
            debug!(
                bytes_transmitted = self.bytes_transmitted,
                max_bytes = self.max_bytes,
                "Byte limit reached, terminating stream"
            );
            return Poll::Ready(None);
        }

        // Poll the inner body for the next frame
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                // Check if this is a data frame (vs trailers, etc.)
                if let Some(data) = frame.data_ref() {
                    let frame_size = data.len() as u64;
                    let new_total = self.bytes_transmitted + frame_size;

                    if new_total > self.max_bytes {
                        // This frame would exceed the limit - truncate it
                        let bytes_remaining = self.max_bytes - self.bytes_transmitted;
                        debug!(
                            bytes_transmitted = self.bytes_transmitted,
                            frame_size = frame_size,
                            max_bytes = self.max_bytes,
                            bytes_remaining = bytes_remaining,
                            "Frame would exceed limit, truncating"
                        );

                        if bytes_remaining > 0 {
                            // Send the partial frame that fits
                            self.bytes_transmitted = self.max_bytes;
                            let truncated = data.slice(0..bytes_remaining as usize);
                            Poll::Ready(Some(Ok(Frame::data(truncated))))
                        } else {
                            // No bytes remaining, terminate immediately
                            Poll::Ready(None)
                        }
                    } else {
                        // Frame fits entirely within the limit
                        self.bytes_transmitted = new_total;
                        debug!(
                            bytes_transmitted = self.bytes_transmitted,
                            frame_size = frame_size,
                            "Frame within limit, passing through"
                        );
                        Poll::Ready(Some(Ok(frame)))
                    }
                } else {
                    // Non-data frame (like trailers), pass through unchanged
                    Poll::Ready(Some(Ok(frame)))
                }
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        // Stream ends if we've hit the limit OR the inner body is done
        self.bytes_transmitted >= self.max_bytes || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        let bytes_remaining = self.max_bytes.saturating_sub(self.bytes_transmitted);
        let inner_hint = self.inner.size_hint();

        // Our upper bound is the minimum of:
        // 1. The inner body's upper bound
        // 2. Our remaining byte allowance
        let mut hint = SizeHint::new();
        if let Some(inner_upper) = inner_hint.upper() {
            hint.set_upper(std::cmp::min(inner_upper, bytes_remaining));
        } else {
            hint.set_upper(bytes_remaining);
        }
        hint
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};

    /// Helper to convert body to bytes vector
    async fn body_to_bytes(body: impl Body<Data = Bytes, Error = HyperError>) -> Vec<u8> {
        let collected = body.collect().await.unwrap();
        collected.to_bytes().to_vec()
    }

    /// Helper to convert Full<Bytes> (Infallible error) to BoxBody with HyperError
    fn wrap_body(body: Full<Bytes>) -> BoxBody<Bytes, HyperError> {
        body.map_err(|_e: std::convert::Infallible| {
            // This can never happen since Full never errors, but we need the type conversion
            unreachable!("Full body never produces errors")
        })
        .boxed()
    }

    #[tokio::test]
    async fn test_limited_body_within_limit() {
        // Test: Body smaller than limit passes through unchanged
        let data = Bytes::from("Hello, World!");
        let body = Full::new(data.clone());
        let limited = LimitedBody::new(wrap_body(body), 100);

        let result = body_to_bytes(limited).await;
        assert_eq!(result, data.to_vec());
    }

    #[tokio::test]
    async fn test_limited_body_exact_limit() {
        // Test: Body exactly at limit passes through completely
        let data = Bytes::from("1234567890");
        let body = Full::new(data.clone());
        let limited = LimitedBody::new(wrap_body(body), 10);

        let result = body_to_bytes(limited).await;
        assert_eq!(result, data.to_vec());
    }

    #[tokio::test]
    async fn test_limited_body_exceeds_limit() {
        // Test: Body larger than limit is truncated
        let data = Bytes::from("Hello, World! This is a long message.");
        let body = Full::new(data.clone());
        let limited = LimitedBody::new(wrap_body(body), 13);

        let result = body_to_bytes(limited).await;
        assert_eq!(result, b"Hello, World!".to_vec());
        assert_eq!(result.len(), 13);
    }

    #[tokio::test]
    async fn test_limited_body_zero_limit() {
        // Test: Zero limit produces empty body
        let data = Bytes::from("Hello, World!");
        let body = Full::new(data);
        let limited = LimitedBody::new(wrap_body(body), 0);

        let result = body_to_bytes(limited).await;
        assert_eq!(result, b"".to_vec());
    }

    #[tokio::test]
    async fn test_limited_body_empty_body() {
        // Test: Empty body remains empty
        let body = Full::new(Bytes::new());
        let limited = LimitedBody::new(wrap_body(body), 100);

        let result = body_to_bytes(limited).await;
        assert_eq!(result, b"".to_vec());
    }

    #[tokio::test]
    async fn test_limited_body_size_hint() {
        // Test: size_hint reflects the limit
        let data = Bytes::from("Hello, World! This is a very long message.");
        let body = Full::new(data);
        let limited = LimitedBody::new(wrap_body(body), 10);

        let hint = limited.size_hint();
        // Upper bound should be 10 (our limit)
        assert_eq!(hint.upper(), Some(10));
    }

    #[tokio::test]
    async fn test_limited_body_large_to_small() {
        // Test: Large body is properly truncated to small limit
        let data = Bytes::from("A".repeat(10000));
        let body = Full::new(data);
        let limited = LimitedBody::new(wrap_body(body), 50);

        let result = body_to_bytes(limited).await;
        assert_eq!(result.len(), 50);
        assert_eq!(result, "A".repeat(50).as_bytes());
    }

    #[tokio::test]
    async fn test_limited_body_one_byte_limit() {
        // Test: One byte limit
        let data = Bytes::from("Hello");
        let body = Full::new(data);
        let limited = LimitedBody::new(wrap_body(body), 1);

        let result = body_to_bytes(limited).await;
        assert_eq!(result, b"H".to_vec());
        assert_eq!(result.len(), 1);
    }
}
