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

### Integration Tests

#### macOS

On macOS, httpjail runs in weak mode (environment variable-based):

```bash
# Run weak mode tests
cargo test --test weak_integration

# Run with output for debugging
cargo test --test weak_integration -- --nocapture
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
- `tests/weak_integration.rs` - Weak mode (environment-based) integration tests

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

## Release Process

### Publishing a New Version

Releases are automated through GitHub Actions when a version tag is pushed. The process:

1. **Update version in Cargo.toml**
   ```bash
   # Edit Cargo.toml and update the version field
   # Example: version = "0.2.0"
   ```

2. **Commit the version change**
   ```bash
   git add Cargo.toml
   git commit -m "Bump version to 0.2.0"
   git push
   ```

3. **Create and push a version tag**
   ```bash
   # Tag format must be v<version> matching Cargo.toml version
   git tag v0.2.0
   git push origin v0.2.0
   ```

4. **Automated publish workflow**
   - The GitHub Actions workflow will automatically:
     - Verify the tag version matches Cargo.toml
     - Run all tests
     - Run clippy and format checks
     - Build the release binary
     - Publish to crates.io

### Prerequisites for Publishing

- **GitHub Environment**: The `publish` environment must be configured in the repository settings
- **Cargo Token**: The `CARGO_REGISTRY_TOKEN` secret must be set in the `publish` environment
- **Version Match**: The git tag (without `v` prefix) must exactly match the version in Cargo.toml

### Manual Publishing (if needed)

If automated publishing fails, you can publish manually:

```bash
cargo publish --token <your-token>
```

## License

By contributing to httpjail, you agree that your contributions will be licensed under the same license as the project.
