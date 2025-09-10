# httpjail

[![Crates.io](https://img.shields.io/crates/v/httpjail.svg)](https://crates.io/crates/httpjail)
[![CI](https://github.com/coder/httpjail/actions/workflows/tests.yml/badge.svg)](https://github.com/coder/httpjail/actions/workflows/tests.yml)

A cross-platform tool for monitoring and restricting HTTP/HTTPS requests from processes using network isolation and transparent proxy interception.

## Installation

### Install via Cargo

```bash
cargo install httpjail
```

### Install from source

```bash
# Clone the repository
git clone https://github.com/coder/httpjail
cd httpjail

# Build with Cargo
cargo build --release

# Install to PATH
sudo cp target/release/httpjail /usr/local/bin/
```

## Features

- 🔒 **Process-level network isolation** - Isolate processes in restricted network environments
- 🌐 **HTTP/HTTPS interception** - Transparent proxy with TLS certificate injection
- 🎯 **Regex-based filtering** - Flexible allow/deny rules with regex patterns
- 📝 **Request logging** - Monitor and log all HTTP/HTTPS requests
- 🖥️ **Cross-platform** - Native support for Linux and macOS
- ⚡ **Zero configuration** - Works out of the box with sensible defaults

## MVP TODO

- [ ] Update README to be more reflective of AI agent restrictions
- [ ] Block all other TCP/UDP traffic when in jail mode. Exception for UDP to 53. DNS is pretty darn safe.
- [ ] Add a `--server` mode that runs the proxy server but doesn't execute the command
- [ ] Expand test cases to include WebSockets
- [x] Add Linux support with parity with macOS
- [x] Add robust firewall cleanup mechanism for Linux and macOS
- [x] Support/test concurrent jailing across macOS and Linux

## Quick Start

```bash
# Allow only requests to github.com
httpjail -r "allow: github\.com" -r "deny: .*" -- claude

# Monitor all requests without blocking
httpjail --log-only -- npm install

# Block specific domains
httpjail -r "deny: telemetry\..*" -r "allow: .*" -- ./my-app

# Method-specific rules
httpjail -r "allow-get: api\.github\.com" -r "deny: .*" -- git pull

# Use config file for complex rules
httpjail --config rules.yaml -- python script.py
```

## Architecture Overview

httpjail creates an isolated network environment for the target process, intercepting all HTTP/HTTPS traffic through a transparent proxy that enforces user-defined rules.

### Linux Implementation

```
┌─────────────────────────────────────────────────┐
│                 httpjail Process                │
├─────────────────────────────────────────────────┤
│  1. Create network namespace                    │
│  2. Setup nftables rules                        │
│  3. Start embedded proxy                        │
│  4. Inject CA certificate                       │
│  5. Execute target process in namespace         │
└─────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────┐
│              Target Process                     │
│  • Isolated in network namespace                │
│  • All HTTP/HTTPS → local proxy                 │
│  • CA cert in trust store                       │
└─────────────────────────────────────────────────┘
```

### macOS Implementation

```
┌─────────────────────────────────────────────────┐
│                 httpjail Process                │
├─────────────────────────────────────────────────┤
│  1. Start HTTP/HTTPS proxy servers              │
│  2. Set HTTP_PROXY/HTTPS_PROXY env vars         │
│  3. Generate/load CA certificate                │
│  4. Execute target with proxy environment       │
└─────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────┐
│              Target Process                     │
│  • HTTP_PROXY/HTTPS_PROXY environment vars      │
│  • Applications must respect proxy settings     │
│  • CA cert via environment variables            │
└─────────────────────────────────────────────────┘
```

**Note**: Due to macOS PF (Packet Filter) limitations, httpjail uses environment-based proxy configuration on macOS. PF translation rules (such as `rdr` and `route-to`) cannot match on user or group, making transparent traffic interception impossible. As a result, httpjail operates in "weak mode" on macOS, relying on applications to respect the `HTTP_PROXY` and `HTTPS_PROXY` environment variables. Most command-line tools and modern applications respect these settings, but some may bypass them. See also https://github.com/coder/httpjail/issues/7.

## Platform Support

| Feature           | Linux                    | macOS                       | Windows       |
| ----------------- | ------------------------ | --------------------------- | ------------- |
| Traffic isolation | ✅ Namespaces + nftables | ⚠️ Env vars only            | 🚧 Planned    |
| TLS interception  | ✅ CA injection          | ✅ Env variables            | 🚧 Cert store |
| Sudo required     | ⚠️ Yes                   | ✅ No                       | 🚧            |
| Force all traffic | ✅ Yes                   | ❌ No (apps must cooperate) | 🚧            |

## Prerequisites

### Linux

- Linux kernel 3.8+ (network namespace support)
- nftables (nft command)
- libssl-dev (for TLS)
- sudo access (for namespace creation)

### macOS

- macOS 10.15+ (Catalina or later)
- No special permissions required (runs in weak mode)

## Usage Examples

### Basic Usage

```bash
# Simple allow/deny rules
httpjail -r "allow: api\.github\.com" -r "deny: .*" -- git pull

# Multiple allow patterns (order matters!)
httpjail \
  -r "allow: github\.com" \
  -r "allow: githubusercontent\.com" \
  -r "deny: .*" \
  -- npm install

# Deny telemetry while allowing everything else
httpjail \
  -r "deny: telemetry\." \
  -r "deny: analytics\." \
  -r "deny: sentry\." \
  -r "allow: .*" \
  -- ./application

# Method-specific rules
httpjail \
  -r "allow-get: api\..*\.com" \
  -r "deny-post: telemetry\..*" \
  -r "allow: .*" \
  -- ./application
```

### Configuration File

Create a `rules.yaml`:

```yaml
# rules.yaml
rules:
  - action: allow
    pattern: "github\.com"
    methods: ["GET", "POST"]

  - action: allow
    pattern: "api\..*\.com"
    methods: ["GET"]

  - action: deny
    pattern: "telemetry"

  - action: deny
    pattern: ".*"

logging:
  level: info
  file: /var/log/httpjail.log
```

Use the config:

```bash
httpjail --config rules.yaml -- ./my-application
```

### Advanced Options

```bash
# Dry run - log what would be blocked without blocking
httpjail --dry-run --config rules.yaml -- ./app

# Verbose logging
httpjail -vvv --allow ".*" -- curl https://example.com

# Interactive mode - approve/deny requests in real-time
httpjail --interactive -- ./app
```

## TLS Interception

httpjail uses a locally-generated Certificate Authority (CA) to intercept HTTPS traffic:

1. **Automatic CA Generation**: On first run, httpjail generates a unique CA certificate
2. **Persistent CA Storage**: The CA is cached in the user's config directory:
   - macOS: `~/Library/Application Support/httpjail/`
   - Linux: `~/.config/httpjail/`
   - Windows: `%APPDATA%\httpjail\`
3. **Trust Store Injection**: The CA is temporarily added to the system trust store
4. **Certificate Generation**: Dynamic certificate generation for intercepted domains
5. **Cleanup**: CA is removed from trust store after process termination

### Security Considerations

- CA private key is stored with 600 permissions (Unix) in the config directory
- CA is only trusted for the duration of the jailed process
- Each httpjail installation has a unique CA
- The same CA is reused across runs for consistency
- Certificates are generated on-the-fly and not persisted

### Disable TLS Interception

```bash
# Only monitor/block HTTP traffic
httpjail --no-tls-intercept --allow ".*" -- ./app
```

## Command-Line Options

```
httpjail [OPTIONS] -- <COMMAND> [ARGS]

OPTIONS:
    -r, --rule <RULE>            Add a rule (format: "action[-method]: pattern")
                                 Actions: allow, deny
                                 Methods: get, post, put, delete, head, options, connect, trace, patch
    -c, --config <FILE>          Use configuration file
    --dry-run                    Log actions without blocking
    --log-only                   Monitor without filtering
    --no-tls-intercept          Disable HTTPS interception
    --interactive               Interactive approval mode
    --weak                      Use weak mode (env vars only, no system isolation)
    --timeout <SECONDS>         Timeout for command execution
    -v, --verbose               Increase verbosity (-vvv for max)
    -h, --help                  Print help
    -V, --version               Print version

RULE FORMAT:
    Rules are specified with -r/--rule and use the format:
    "action[-method]: pattern"

    Examples:
    -r "allow: github\.com"              # Allow all methods to github.com
    -r "allow-get: api\..*"              # Allow only GET requests to api.*
    -r "deny-post: telemetry\..*"        # Deny POST requests to telemetry.*
    -r "deny: .*"                        # Deny everything (usually last rule)

    Rules are evaluated in the order specified.

EXAMPLES:
    httpjail -r "allow: github\.com" -r "deny: .*" -- git clone https://github.com/user/repo
    httpjail --config rules.yaml -- npm install
    httpjail --dry-run -r "deny: telemetry" -r "allow: .*" -- ./application
    httpjail --weak -r "allow: .*" -- npm test  # Use environment variables only
```

## License

This project is released into the public domain under the CC0 1.0 Universal license. See [LICENSE](LICENSE) for details.
