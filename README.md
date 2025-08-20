# httpjail

A cross-platform tool for monitoring and restricting HTTP/HTTPS requests from processes using network isolation and transparent proxy interception.

## Features

- 🔒 **Process-level network isolation** - Isolate processes in restricted network environments
- 🌐 **HTTP/HTTPS interception** - Transparent proxy with TLS certificate injection
- 🎯 **Regex-based filtering** - Flexible allow/deny rules with regex patterns
- 📝 **Request logging** - Monitor and log all HTTP/HTTPS requests
- 🖥️ **Cross-platform** - Native support for Linux and macOS
- ⚡ **Zero configuration** - Works out of the box with sensible defaults

## Quick Start

```bash
# Allow only requests to github.com
httpjail --allow "github\.com" --deny ".*" -- curl https://github.com

# Monitor all requests without blocking
httpjail --log-only -- npm install

# Block specific domains
httpjail --deny "telemetry\..*" --allow ".*" -- ./my-app

# Use config file for complex rules
httpjail --config rules.yaml -- python script.py
```

## Architecture Overview

httpjail creates an isolated network environment for the target process, intercepting all HTTP/HTTPS traffic through a transparent proxy that enforces user-defined rules.

### Linux Implementation

```
┌─────────────────────────────────────────────────┐
│                 httpjail Process                 │
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
│  1. Configure pfctl packet filter               │
│  2. Create sandbox-exec profile                 │
│  3. Start embedded proxy                        │
│  4. Add CA cert to Keychain                     │
│  5. Execute target in sandbox                   │
└─────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────┐
│              Target Process                     │
│  • Running in sandbox-exec                      │
│  • Traffic redirected via pfctl                 │
│  • CA cert trusted in Keychain                  │
└─────────────────────────────────────────────────┘
```

## Platform Support

| Feature             | Linux                 | macOS             | Windows       |
| ------------------- | --------------------- | ----------------- | ------------- |
| Process isolation   | ✅ Network namespaces | ✅ sandbox-exec   | 🚧 Planned    |
| Traffic redirection | ✅ iptables           | ✅ pfctl          | 🚧 WFP        |
| TLS interception    | ✅ CA injection       | ✅ Keychain       | 🚧 Cert store |
| No-sudo mode        | ❌                    | ⚠️ Limited (DYLD) | 🚧            |
| Performance         | ✅ Kernel-level       | ✅ Kernel-level   | -             |

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
- sudo access (for pfctl rules)

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
httpjail --allow "api\.github\.com" --deny ".*" -- git pull

# Multiple allow patterns
httpjail \
  --allow "github\.com" \
  --allow "githubusercontent\.com" \
  --deny ".*" \
  -- npm install

# Deny telemetry while allowing everything else
httpjail \
  --deny "telemetry\." \
  --deny "analytics\." \
  --deny "sentry\." \
  --allow ".*" \
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

1. **Automatic CA Generation**: On first run, httpjail generates a unique CA certificate and caches it in `~/.httpjail/`
2. **Trust Store Injection**: The CA is temporarily added to the system trust store
3. **Certificate Generation**: Dynamic certificate generation for intercepted domains
4. **Cleanup**: CA is removed from trust store after process termination

### Security Considerations

- CA private key is stored with 600 permissions in `~/.httpjail/`
- CA is only trusted for the duration of the jailed process
- Each httpjail installation has a unique CA
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
    -a, --allow <PATTERN>         Allow requests matching regex pattern
    -d, --deny <PATTERN>          Deny requests matching regex pattern
    -c, --config <FILE>           Use configuration file
    --dry-run                     Log actions without blocking
    --log-only                    Monitor without filtering
    --no-tls-intercept           Disable HTTPS interception
    --interactive                Interactive approval mode
    -v, --verbose                Increase verbosity (-vvv for max)
    -h, --help                   Print help
    -V, --version                Print version

EXAMPLES:
    httpjail --allow "github\.com" --deny ".*" -- git clone https://github.com/user/repo
    httpjail --config rules.yaml -- npm install
    httpjail --dry-run --deny "telemetry" --allow ".*" -- ./application
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development setup instructions
- Testing guidelines
- Code style requirements
- Pull request process

## License

MIT License - see LICENSE file for details

