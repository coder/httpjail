# Contributing to httpjail

Thank you for your interest in contributing to httpjail! This document provides guidelines and instructions for contributing to the project.

## Development Setup

### Prerequisites

- Rust 1.70+ (install via [rustup](https://rustup.rs/))
- On macOS: Xcode Command Line Tools
- On Linux: build-essential, libssl-dev

### Building from Source

```bash
# Clone the repository
git clone https://github.com/yourusername/httpjail
cd httpjail

# Build the project
cargo build

# Run in debug mode
cargo run -- --allow ".*" -- echo "test"
```

## Testing

### Unit Tests

Run the standard unit tests:

```bash
cargo test
```

### Integration Tests (macOS)

The integration tests require sudo access to set up PF rules and groups:

```bash
# Run all integration tests (requires sudo)
sudo -E cargo test -- --ignored

# Run a specific integration test suite
sudo -E cargo test --test jail_integration -- --ignored

# Run with output for debugging
sudo -E cargo test -- --ignored --nocapture
```

### Manual Testing

Test basic functionality:

```bash
# Build the binary
cargo build --release

# Test with allow rule (requires sudo on macOS)
sudo ./target/release/httpjail --allow "httpbin\.org" -- curl http://httpbin.org/get

# Test with method-specific rules
sudo ./target/release/httpjail --allow-get ".*" -- curl -X POST http://httpbin.org/post

# Test log-only mode
sudo ./target/release/httpjail --log-only -- curl http://example.com
```

### Test Organization

- `tests/smoke_test.rs` - Basic CLI tests that don't require network or sudo
- `tests/jail_integration.rs` - Comprehensive integration tests for jail functionality
- `tests/macos_integration.rs` - macOS-specific integration tests using assert_cmd

## Code Style

We use standard Rust formatting and linting:

```bash
# Format code
cargo fmt

# Run clippy for linting
cargo clippy -- -D warnings

# Check for common mistakes
cargo check
```

## Project Structure

```
httpjail/
├── src/
│   ├── main.rs           # CLI entry point and argument parsing
│   ├── rules.rs          # Rule engine for allow/deny logic
│   ├── proxy.rs          # HTTP/HTTPS proxy implementation
│   └── jail/             # Platform-specific jail implementations
│       ├── mod.rs        # Jail trait and common code
│       ├── macos.rs      # macOS implementation (PF + groups)
│       └── linux.rs      # Linux implementation (namespaces)
├── tests/                # Integration tests
└── Cargo.toml           # Project dependencies
```

## Making Changes

1. **Fork the repository** and create a feature branch
2. **Write tests** for your changes
3. **Ensure all tests pass** with `cargo test`
4. **Format your code** with `cargo fmt`
5. **Update documentation** if needed
6. **Submit a pull request** with a clear description

## Platform-Specific Development

### macOS Development

The macOS implementation uses:

- PF (Packet Filter) for traffic redirection
- Supplemental groups for process isolation
- `divert-to` rules to redirect traffic to the proxy

Key files:

- `src/jail/macos.rs` - PF rule management and group creation

### Linux Development

The Linux implementation (currently a stub) will use:

- Network namespaces for isolation
- iptables for traffic redirection
- veth pairs for namespace networking

Key files:

- `src/jail/linux.rs` - Namespace and iptables management

## Debugging

### Enable Debug Logging

```bash
# Set RUST_LOG environment variable
RUST_LOG=httpjail=debug cargo run -- --allow ".*" -- curl http://example.com

# Maximum verbosity
cargo run -- -vvv --allow ".*" -- curl http://example.com
```

### Check PF Rules (macOS)

```bash
# View current PF rules
sudo pfctl -sa

# Check httpjail anchor
sudo pfctl -a httpjail -sr

# Clean up PF rules manually if needed
sudo pfctl -a httpjail -F all
```

## License

By contributing to httpjail, you agree that your contributions will be licensed under the same license as the project.
