/// Automatic test logging setup using ctor
/// This module ensures all tests have tracing enabled when RUST_LOG is set
use tracing_subscriber;

#[ctor::ctor]
fn init() {
    // Set up tracing subscriber that outputs to stdout
    // This allows debugging with RUST_LOG=debug cargo test
    // Using try_init() to avoid panics if already initialized
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("httpjail=debug".parse().unwrap()),
        )
        .with_test_writer()
        .try_init();
}
