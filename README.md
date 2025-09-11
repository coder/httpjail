# httpjail

[![Crates.io](https://img.shields.io/crates/v/httpjail.svg)](https://crates.io/crates/httpjail)
[![CI](https://github.com/coder/httpjail/actions/workflows/tests.yml/badge.svg)](https://github.com/coder/httpjail/actions/workflows/tests.yml)

A cross-platform tool for monitoring and restricting HTTP/HTTPS requests from processes using network isolation and transparent proxy interception.

Install:

```bash
cargo install httpjail
```

## Features

> [!WARNING]
> httpjail is experimental and offers no API or CLI compatibility guarantees.

- 🔒 **Process-level network isolation** - Isolate processes in restricted network environments
- 🌐 **HTTP/HTTPS interception** - Transparent proxy with TLS certificate injection
- 🎯 **Regex-based filtering** - Flexible allow/deny rules with regex patterns
- 🔧 **Script-based evaluation** - Custom request evaluation logic via external scripts
- 🚀 **JavaScript evaluation** - Fast, secure request filtering using V8 JavaScript engine (experimental)
- 📝 **Request logging** - Monitor and log all HTTP/HTTPS requests
- ⛔ **Default deny** - Requests are blocked unless explicitly allowed
- 🖥️ **Cross-platform** - Native support for Linux and macOS
- ⚡ **Zero configuration** - Works out of the box with sensible defaults

## Quick Start

> By default, httpjail denies all network requests. Add `allow:` rules to permit traffic.

```bash
# Allow only requests to github.com
httpjail -r "allow: github\.com" -r "deny: .*" -- claude

# Log requests to a file
httpjail --request-log requests.log -r "allow: .*" -- npm install
# Log format: "<timestamp> <+/-> <METHOD> <URL>" (+ = allowed, - = blocked)

# Block specific domains
httpjail -r "deny: telemetry\..*" -r "allow: .*" -- ./my-app

# Method-specific rules
httpjail -r "allow-get: api\.github\.com" -r "deny: .*" -- git pull

# Use config file for complex rules
httpjail --config rules.txt -- python script.py

# Use custom script for request evaluation
httpjail --script /path/to/check.sh -- ./my-app
# Script receives: HTTPJAIL_URL, HTTPJAIL_METHOD, HTTPJAIL_HOST, HTTPJAIL_SCHEME, HTTPJAIL_PATH
# Exit 0 to allow, non-zero to block. stdout becomes additional context in 403 response.

# Use JavaScript for request evaluation (experimental)
httpjail --js "return host === 'github.com'" -- git pull
# JavaScript receives: url, method, host, scheme, path as global variables
# Should return true to allow, false to block

# Run as standalone proxy server (no command execution)
httpjail --server -r "allow: .*"
# Server defaults to ports 8080 (HTTP) and 8443 (HTTPS)
# Configure your application:
# HTTP_PROXY=http://localhost:8080 HTTPS_PROXY=http://localhost:8443
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
│  4. Export CA trust env vars                    │
│  5. Execute target process in namespace         │
└─────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────┐
│              Target Process                     │
│  • Isolated in network namespace                │
│  • All HTTP/HTTPS → local proxy                 │
│  • CA cert trusted via env vars                 │
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

| Feature           | Linux                        | macOS                       | Windows       |
| ----------------- | ---------------------------- | --------------------------- | ------------- |
| Traffic isolation | ✅ Namespaces + nftables     | ⚠️ Env vars only            | 🚧 Planned    |
| TLS interception  | ✅ Transparent MITM + env CA | ✅ Env variables            | 🚧 Cert store |
| Sudo required     | ⚠️ Yes                       | ✅ No                       | 🚧            |
| Force all traffic | ✅ Yes                       | ❌ No (apps must cooperate) | 🚧            |

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

Create a `rules.txt` (one rule per line, `#` comments and blank lines are ignored):

```text
# rules.txt
allow-get: github\.com
deny: telemetry
allow: .*
```

Use the config:

```bash
httpjail --config rules.txt -- ./my-application
```

### Script-Based Evaluation

Instead of regex rules, you can use a custom script to evaluate each request. The script receives environment variables for each request and returns an exit code to allow (0) or block (non-zero) the request. Any output to stdout becomes additional context in the 403 response.

```bash
# Simple script example
cat > check_request.sh << 'EOF'
#!/bin/bash
# Allow only GitHub and reject everything else
if [[ "$HTTPJAIL_HOST" == "github.com" ]]; then
    exit 0
else
    echo "Access denied: $HTTPJAIL_HOST is not on the allowlist"
    exit 1
fi
EOF
chmod +x check_request.sh

# Use the script
httpjail --script ./check_request.sh -- curl https://github.com

# Inline script (with spaces, executed via shell)
httpjail --script '[ "$HTTPJAIL_HOST" = "github.com" ] && exit 0 || exit 1' -- git pull
```

**Environment variables provided to the script:**

- `HTTPJAIL_URL` - Full URL being requested
- `HTTPJAIL_METHOD` - HTTP method (GET, POST, etc.)
- `HTTPJAIL_HOST` - Hostname from the URL
- `HTTPJAIL_SCHEME` - URL scheme (http or https)
- `HTTPJAIL_PATH` - Path component of the URL

**Script requirements:**

- Exit code 0 allows the request
- Any non-zero exit code blocks the request
- stdout is captured and included in 403 responses as additional context
- stderr is logged for debugging but not sent to the client

> [!TIP]
> Script-based evaluation can also be used for custom logging! Your script can log requests to a database, send metrics to a monitoring service, or implement complex audit trails before returning the allow/deny decision.

### JavaScript (V8) Evaluation (Experimental)

httpjail includes experimental support for JavaScript-based request evaluation using Google's V8 engine. This provides more flexible and powerful rule logic compared to regex patterns or shell scripts.

```bash
# Simple JavaScript rule - allow only GitHub requests
httpjail --js "return host === 'github.com'" -- curl https://github.com

# Method-specific filtering
httpjail --js "return method === 'GET' && host === 'api.github.com'" -- git pull

# Complex logic with multiple conditions
httpjail --js "
// Allow GitHub and safe domains
if (host.endsWith('github.com') || host === 'api.github.com') {
    return true;
}

// Block social media
if (host.includes('facebook.com') || host.includes('twitter.com')) {
    return false;
}

// Allow HTTPS API calls
if (scheme === 'https' && path.startsWith('/api/')) {
    return true;
}

// Default deny
return false;
" -- ./my-app

# Path-based filtering
httpjail --js "return path.startsWith('/api/') && scheme === 'https'" -- npm install
```

**Global variables available in JavaScript:**

- `url` - Full URL being requested (string)
- `method` - HTTP method (GET, POST, etc.)
- `host` - Hostname from the URL
- `scheme` - URL scheme (http or https)
- `path` - Path portion of the URL

**JavaScript evaluation rules:**

- JavaScript code should return `true` to allow the request, `false` to block it
- Code is executed in a sandboxed V8 isolate for security
- Syntax errors are caught during startup and cause httpjail to exit
- Runtime errors result in the request being blocked
- Each request evaluation runs in a fresh context for thread safety

**Performance considerations:**

- V8 engine provides fast JavaScript execution
- Fresh isolate creation per request ensures thread safety but adds some overhead
- For maximum performance with complex logic, consider using compiled rules instead
- JavaScript evaluation is generally faster than external script execution

> [!WARNING]
> JavaScript evaluation is experimental and may change in future versions. Use the `--script` option for production environments requiring stability.

> [!NOTE]
> The `--js` flag conflicts with `--script`, `--rule`, and `--config` flags. Only one evaluation method can be used at a time.

### Advanced Options

```bash
# Verbose logging
httpjail -vvv -r "allow: .*" -- curl https://example.com

# Server mode - run as standalone proxy without executing commands
httpjail --server -r "allow: github\.com" -r "deny: .*"
# Server defaults to ports 8080 (HTTP) and 8443 (HTTPS)

# Server mode with custom ports (format: port or ip:port)
HTTPJAIL_HTTP_BIND=3128 HTTPJAIL_HTTPS_BIND=3129 httpjail --server -r "allow: .*"
# Configure applications: HTTP_PROXY=http://localhost:3128 HTTPS_PROXY=http://localhost:3129

# Bind to specific interface
HTTPJAIL_HTTP_BIND=192.168.1.100:8080 httpjail --server -r "allow: .*"

```

### Server Mode

httpjail can run as a standalone proxy server without executing any commands. This is useful when you want to proxy multiple applications through the same httpjail instance. The server binds to localhost (127.0.0.1) only for security.

```bash
# Start server with default ports (8080 for HTTP, 8443 for HTTPS) on localhost
httpjail --server -r "allow: github\.com" -r "deny: .*"
# Output: Server running on ports 8080 (HTTP) and 8443 (HTTPS). Press Ctrl+C to stop.

# Start server with custom ports using environment variables
HTTPJAIL_HTTP_BIND=3128 HTTPJAIL_HTTPS_BIND=3129 httpjail --server -r "allow: .*"
# Output: Server running on ports 3128 (HTTP) and 3129 (HTTPS). Press Ctrl+C to stop.

# Bind to all interfaces (use with caution - exposes proxy to network)
HTTPJAIL_HTTP_BIND=0.0.0.0:8080 HTTPJAIL_HTTPS_BIND=0.0.0.0:8443 httpjail --server -r "allow: .*"
# Output: Server running on ports 8080 (HTTP) and 8443 (HTTPS). Press Ctrl+C to stop.

# Configure your applications to use the proxy:
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8443
curl https://github.com  # This request will go through httpjail
```

**Note**: In server mode, httpjail does not create network isolation. Applications must be configured to use the proxy via environment variables or application-specific proxy settings.

## TLS Interception

httpjail performs HTTPS interception using a locally-generated Certificate Authority (CA). The tool does not modify your system trust store. Instead, it configures the jailed process to trust the httpjail CA via environment variables.

How it works:

1. **CA generation (first run)**: A unique CA keypair is created and persisted.
2. **Persistent storage** (via `dirs::config_dir()`):
   - macOS: `~/Library/Application Support/httpjail/`
   - Linux: `~/.config/httpjail/`
   - Windows: `%APPDATA%\httpjail\`
     Files: `ca-cert.pem`, `ca-key.pem` (key is chmod 600 on Unix).
3. **Per‑process trust via env vars**: For the jailed command, httpjail sets common variables so clients trust the CA without touching system stores:
   - `SSL_CERT_FILE` and `SSL_CERT_DIR`
   - `CURL_CA_BUNDLE`
   - `GIT_SSL_CAINFO`
   - `REQUESTS_CA_BUNDLE`
   - `NODE_EXTRA_CA_CERTS`
     These apply on both Linux (strong/transparent mode) and macOS (`--weak` env‑only mode).
4. **Transparent MITM**:
   - Linux strong mode redirects TCP 80/443 to the local proxy. HTTPS is intercepted transparently by extracting SNI from ClientHello and presenting a per‑host certificate signed by the httpjail CA.
   - macOS uses explicit proxying via `HTTP_PROXY`/`HTTPS_PROXY` and typically negotiates HTTPS via CONNECT; interception occurs after CONNECT.
5. **No system trust changes**: httpjail never installs the CA into OS trust stores; there is no global modification and thus no trust cleanup step. The CA files remain in the config dir for reuse across runs.

Notes and limits:

- Tools that ignore the above env vars will fail TLS verification when intercepted. For those, add tool‑specific flags to point at `ca-cert.pem`.
- Long‑lived connections are supported: timeouts are applied only to protocol detection, CONNECT header reads, and TLS handshakes — not to proxied streams (e.g., gRPC/WebSocket).

## License

This project is released into the public domain under the CC0 1.0 Universal license. See [LICENSE](LICENSE) for details.
