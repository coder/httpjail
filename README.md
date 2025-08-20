# httpjail

A cross-platform tool for monitoring and restricting HTTP/HTTPS requests from processes using network isolation and transparent proxy interception.

## Features

- 🔒 **Process-level network isolation** - Isolate processes in restricted network environments
- 🌐 **HTTP/HTTPS interception** - Transparent proxy with TLS certificate injection
- 🎯 **Regex-based filtering** - Flexible allow/deny rules with regex patterns
- 📝 **Request logging** - Monitor and log all HTTP/HTTPS requests
- 🖥️ **Cross-platform** - Native support for Linux and macOS
- ⚡ **Zero configuration** - Works out of the box with sensible defaults

## MVP TODO

- [ ] Update README to be more reflective of AI agent restrictions
- [ ] Block all other TCP traffic by default (disabled via flag) (perhaps should be a rule?)
- [ ] When ran under sudo should drop into original user before executing the command
- [ ] Add a `--server` mode that runs the proxy server but doesn't execute the command
- [ ] Requests occasionally take a very long time to complete.

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
│  2. Setup iptables rules                        │
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
│                 httpjail Process                 │
├─────────────────────────────────────────────────┤
│  1. Start HTTP/HTTPS proxy servers              │
│  2. Configure PF (Packet Filter) rules          │
│  3. Create httpjail group (GID-based isolation) │
│  4. Generate/load CA certificate                │
│  5. Execute target with group membership        │
└─────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────┐
│              Target Process                     │
│  • Running with httpjail GID                    │
│  • TCP traffic redirected via PF rules          │
│  • HTTP → port 8xxx, HTTPS → port 8xxx          │
│  • CA cert via environment variables            │
└─────────────────────────────────────────────────┘
```

The macOS implementation uses PF (Packet Filter) for transparent TCP redirection:

- Creates a dedicated `httpjail` group for process isolation
- Uses PF rules to redirect TCP traffic from processes with the httpjail GID
- HTTP traffic (port 80) → local proxy (port 8xxx)
- HTTPS traffic (port 443) → local proxy (port 8xxx)
- Supports both CONNECT tunneling and transparent TLS interception
- CA certificate distributed via environment variables

## Platform Support

| Feature           | Linux                    | macOS               | Windows       | Weak Mode (All) |
| ----------------- | ------------------------ | ------------------- | ------------- | --------------- |
| Traffic isolation | ✅ Namespaces + iptables | ✅ GID + PF (pfctl) | 🚧 Planned    | ✅ Env vars     |
| TLS interception  | ✅ CA injection          | ✅ Env variables    | 🚧 Cert store | ✅ Env vars     |
| Sudo required     | ⚠️ Yes                   | ⚠️ Yes              | 🚧            | ✅ No           |

## Installation

### Prerequisites

#### Linux

- Linux kernel 3.8+ (network namespace support)
- iptables
- libssl-dev (for TLS)
- sudo access (for namespace creation)

#### macOS

- macOS 10.15+ (Catalina or later)
- pfctl (included in macOS)
- sudo access (for PF rules and group creation)
- coreutils (optional, for gtimeout support)

### Install from source

```bash
# Clone the repository
git clone https://github.com/yourusername/httpjail
cd httpjail

# Build with Cargo
cargo build --release

# Install to PATH
sudo cp target/release/httpjail /usr/local/bin/

# CA certificate is auto-generated on first run
```

### Install via Cargo

```bash
cargo install httpjail
```

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
