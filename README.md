# httpjail

[![Documentation](https://img.shields.io/badge/docs-coder.github.io%2Fhttpjail-blue?logo=readthedocs&style=flat-square)](https://coder.github.io/httpjail/)
[![Crates.io](https://img.shields.io/crates/v/httpjail.svg)](https://crates.io/crates/httpjail)
[![CI](https://github.com/coder/httpjail/actions/workflows/tests.yml/badge.svg)](https://github.com/coder/httpjail/actions/workflows/tests.yml)

A cross-platform tool for monitoring and restricting HTTP/HTTPS requests from processes using network isolation and transparent proxy interception.

Install:

```bash
cargo install httpjail
```

Or download a pre-built binary from the [releases page](https://github.com/coder/httpjail/releases).

## Features

> [!WARNING]
> httpjail is experimental and offers no API or CLI compatibility guarantees.

- 🔒 **Process-level network isolation** - Isolate processes in restricted network environments
- 🌐 **HTTP/HTTPS interception** - Transparent proxy with TLS certificate injection
- 🛡️ **DNS exfiltration protection** - Prevents data leakage through DNS queries
- 🔧 **Multiple evaluation approaches** - JS expressions or custom programs
- 🖥️ **Cross-platform** - Native support for Linux and macOS

## Quick Start

> By default, httpjail denies all network requests. Provide a JS rule or script to allow traffic.

```bash
# Allow only requests to github.com (JS)
httpjail --js "r.host === 'github.com'" -- your-app

# Load JS from a file (auto-reloads on file changes)
echo "/^api\\.example\\.com$/.test(r.host) && r.method === 'GET'" > rules.js
httpjail --js-file rules.js -- curl https://api.example.com/health
# File changes are detected and reloaded automatically on each request

# Log requests to a file
httpjail --request-log requests.log --js "true" -- npm install
# Log format: "<timestamp> <+/-> <METHOD> <URL>" (+ = allowed, - = blocked)

# Use shell script for request evaluation (process per request)
httpjail --sh "/path/to/script.sh" -- ./my-app
# Script receives env vars: HTTPJAIL_URL, HTTPJAIL_METHOD, HTTPJAIL_HOST, etc.
# Exit code 0 allows, non-zero blocks

# Use line processor for request evaluation (efficient persistent process)
httpjail --proc /path/to/filter.py -- ./my-app
# Program receives JSON on stdin (one per line) and outputs allow/deny decisions
# stdin  -> {"method": "GET", "url": "https://api.github.com", "host": "api.github.com", ...}
# stdout -> true

# Run as standalone proxy server (no command execution) and allow all
httpjail --server --js "true"
# Server defaults to ports 8080 (HTTP) and 8443 (HTTPS)
# Configure your application:
# HTTP_PROXY=http://localhost:8080 HTTPS_PROXY=http://localhost:8443

# Run Docker containers with network isolation (Linux only)
httpjail --js "r.host === 'api.github.com'" --docker-run -- --rm alpine:latest wget -qO- https://api.github.com
```

## Docker

httpjail can run as a standalone proxy server in a Docker container, perfect for team-wide policy enforcement or testing.

### Building the Image

```bash
docker build -t httpjail:latest .
```

The Dockerfile downloads httpjail v0.5.1 from GitHub releases and runs as a non-root user (UID 1000).

### Running the Container

**Basic usage with default allow all rule:**

```bash
docker run -d --name httpjail \
  -p 8080:8080 -p 8443:8443 \
  httpjail:latest
```

**With persistent certificates:**

```bash
mkdir -p ./httpjail-certs
docker run -d --name httpjail \
  -p 8080:8080 -p 8443:8443 \
  -v ./httpjail-certs:/home/httpjail/.config/httpjail \
  httpjail:latest
```

**With custom rules:**

```bash
# Create your custom rule file
cat > my-rules.js <<'EOF'
// Allow only specific domains
const allowed = ['github.com', 'api.github.com', 'npmjs.org'];
allowed.includes(r.host)
EOF

# Run with custom rules (overrides default rules.js)
docker run -d --name httpjail \
  -p 8080:8080 -p 8443:8443 \
  -v ./httpjail-certs:/home/httpjail/.config/httpjail \
  -v ./my-rules.js:/rules/rules.js:ro \
  httpjail:latest
```

**With additional verbosity:**

```bash
docker run -d --name httpjail \
  -p 8080:8080 -p 8443:8443 \
  httpjail:latest --server --js-file /rules/rules.js -vv --request-log /dev/stderr
```

### Configuring Clients

After starting the container, configure your applications to use the proxy:

```bash
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8443
```

For HTTPS to work, clients need to trust the CA certificate. Extract it from the container:

```bash
# Extract CA certificate
docker cp httpjail:/home/httpjail/.config/httpjail/ca-cert.pem ./ca-cert.pem

# Configure client
export SSL_CERT_FILE=$PWD/ca-cert.pem

# Test
curl https://github.com
```

Alternatively, install the certificate system-wide:

```bash
# Linux
sudo cp ca-cert.pem /usr/local/share/ca-certificates/httpjail.crt
sudo update-ca-certificates

# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca-cert.pem
```

### Viewing Logs

Request logs are sent to stderr (visible in `docker logs`):

```bash
docker logs -f httpjail
```

Log format: `<timestamp> <+/-> <METHOD> <URL>` where `+` means allowed and `-` means blocked.

### JavaScript Rule Examples

The default rule (`true`) allows all traffic. Here are more useful examples:

**Allowlist specific domains:**

```javascript
const allowed = ['github.com', 'api.github.com', 'npmjs.org'];
allowed.includes(r.host)
```

**Block specific paths:**

```javascript
// Allow all except admin paths
!r.path.startsWith('/admin')
```

**Size limits:**

```javascript
// Allow GET requests under 10MB
if (r.method === 'GET') {
  ({allow: {max_tx_bytes: 10 * 1024 * 1024}})
} else {
  false  // Block non-GET
}
```

**Custom deny messages:**

```javascript
if (r.host === 'malicious.com') {
  ({allow: false, deny_message: 'Blocked: Known malicious domain'})
} else {
  true
}
```

**Complex policies:**

```javascript
// Allow GitHub and NPM GET requests, deny everything else
const trustedDomains = ['github.com', 'api.github.com', 'npmjs.org', 'registry.npmjs.org'];
const isTrusted = trustedDomains.includes(r.host);
const isSafeMethod = ['GET', 'HEAD'].includes(r.method);

isTrusted && isSafeMethod
```

See the [JavaScript rule engine docs](https://coder.github.io/httpjail/guide/rule-engines/javascript.html) for complete reference.

### Security Notes

- The container runs as non-root user (UID 1000)
- Server mode does NOT provide network isolation (no namespaces)
- Applications must be configured to use the proxy (HTTP_PROXY/HTTPS_PROXY)
- The Docker image is built for x86_64 architecture only
- Certificates are auto-generated on first run if not provided via volume mount

## Documentation

Docs are stored in the `docs/` directory and served
at [coder.github.io/httpjail](https://coder.github.io/httpjail).

Table of Contents:

- [Installation](https://coder.github.io/httpjail/guide/installation.html)
- [Quick Start](https://coder.github.io/httpjail/guide/quick-start.html)
- [Configuration](https://coder.github.io/httpjail/guide/configuration.html)
- [Rule Engines](https://coder.github.io/httpjail/guide/rule-engines/index.html)
  - [JavaScript](https://coder.github.io/httpjail/guide/rule-engines/javascript.html)
  - [Shell](https://coder.github.io/httpjail/guide/rule-engines/shell.html)
  - [Line Processor](https://coder.github.io/httpjail/guide/rule-engines/line-processor.html)
- [Platform Support](https://coder.github.io/httpjail/guide/platform-support.html)
- [Request Logging](https://coder.github.io/httpjail/guide/request-logging.html)
- [TLS Interception](https://coder.github.io/httpjail/advanced/tls-interception.html)
- [DNS Exfiltration](https://coder.github.io/httpjail/advanced/dns-exfiltration.html)
- [Server Mode](https://coder.github.io/httpjail/advanced/server-mode.html)

## License

This project is released into the public domain under the CC0 1.0 Universal license. See [LICENSE](LICENSE) for details.
