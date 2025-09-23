# Installation

httpjail can be installed in several ways depending on your needs and platform.

## Pre-built Binaries

The easiest way to install httpjail is to download a pre-built binary from the [releases page](https://github.com/coder/httpjail/releases).

### Linux
```bash
# Download the latest release (example for Linux x86_64)
curl -L https://github.com/coder/httpjail/releases/latest/download/httpjail-linux-amd64 -o httpjail
chmod +x httpjail
sudo mv httpjail /usr/local/bin/
```

### macOS
```bash
# Download the latest release (example for macOS arm64)
curl -L https://github.com/coder/httpjail/releases/latest/download/httpjail-darwin-arm64 -o httpjail
chmod +x httpjail
sudo mv httpjail /usr/local/bin/
```

## Install via Cargo

If you have Rust installed, you can install httpjail using Cargo:

```bash
cargo install httpjail
```

This will compile httpjail from source and install it to your Cargo bin directory (usually `~/.cargo/bin/`).

## Build from Source

For development or to get the latest unreleased features:

```bash
# Clone the repository
git clone https://github.com/coder/httpjail.git
cd httpjail

# Build in release mode
cargo build --release

# The binary will be at target/release/httpjail
sudo cp target/release/httpjail /usr/local/bin/
```

### Fast Development Builds

For faster builds during development:

```bash
cargo build --profile fast
```

This profile provides reasonable performance with significantly faster build times.

## System Requirements

### Linux
- Linux kernel 3.8+ (for network namespaces)
- Root privileges (for network namespace creation)
- iptables (for traffic redirection)

### macOS  
- macOS 10.15+ (Catalina or later)
- No special privileges required (uses weak mode)

## Verify Installation

After installation, verify httpjail is working:

```bash
# Check version
httpjail --version

# Test with a simple command
httpjail --js "false" -- curl https://example.com
# Should block the request
```

## Trust the CA Certificate (Optional)

For HTTPS interception to work smoothly, you may want to trust httpjail's CA certificate:

```bash
# Install the CA certificate to system trust store
httpjail trust --install

# Remove the CA certificate
httpjail trust --uninstall
```

This is especially important on macOS for applications that use the system keychain (like Go programs).

## Next Steps

Now that you have httpjail installed, check out the [Quick Start](./quick-start.md) guide to learn how to use it.