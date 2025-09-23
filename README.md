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
- 🔧 **Script-based evaluation** - Custom request evaluation logic via external scripts
- 🚀 **JavaScript evaluation** - Fast, secure request filtering using V8 JavaScript engine
- 📝 **Request logging** - Monitor and log all HTTP/HTTPS requests
- ⛔ **Default deny** - Requests are blocked unless explicitly allowed
- 🖥️ **Cross-platform** - Native support for Linux and macOS
- ⚡ **Zero configuration** - Works out of the box with sensible defaults

## Quick Start

> By default, httpjail denies all network requests. Provide a JS rule or script to allow traffic.

```bash
# Allow only requests to github.com (JS)
httpjail --js "r.host === 'github.com'" -- your-app

# Load JS from a file
echo "/^api\\.example\\.com$/.test(r.host) && r.method === 'GET'" > rules.js
httpjail --js-file rules.js -- curl https://api.example.com/health

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

## Documentation

See the [documentation](https://coder.github.io/httpjail/) for more details.

## License

This project is released into the public domain under the CC0 1.0 Universal license. See [LICENSE](LICENSE) for details.
