# httpjail

[![Crates.io](https://img.shields.io/crates/v/httpjail.svg)](https://crates.io/crates/httpjail)
[![CI](https://github.com/coder/httpjail/actions/workflows/tests.yml/badge.svg)](https://github.com/coder/httpjail/actions/workflows/tests.yml)

A cross-platform tool for monitoring and restricting HTTP/HTTPS requests from processes using network isolation and transparent proxy interception.

> **Warning**: httpjail is experimental and offers no API or CLI compatibility guarantees.

## What is httpjail?

httpjail provides process-level network isolation and HTTP request control for applications. It acts as a transparent proxy that intercepts all HTTP/HTTPS traffic from a process and its children, allowing you to:

- Monitor all outgoing HTTP/HTTPS requests
- Block requests based on customizable rules
- Log network activity for auditing
- Prevent data exfiltration through DNS
- Isolate processes in restricted network environments

## Key Features

- 🔒 **Process-level network isolation** - Isolate processes in restricted network environments
- 🌐 **HTTP/HTTPS interception** - Transparent proxy with TLS certificate injection
- 🛡️ **DNS exfiltration protection** - Prevents data leakage through DNS queries
- 🔧 **Script-based evaluation** - Custom request evaluation logic via external scripts
- 🚀 **JavaScript evaluation** - Fast, secure request filtering using V8 JavaScript engine
- 📝 **Request logging** - Monitor and log all HTTP/HTTPS requests
- ⛔ **Default deny** - Requests are blocked unless explicitly allowed
- 🖥️ **Cross-platform** - Native support for Linux and macOS
- ⚡ **Zero configuration** - Works out of the box with sensible defaults

## Use Cases

- **Security auditing** - Monitor what network resources an application accesses
- **Compliance** - Ensure applications only communicate with approved endpoints
- **Development** - Test applications with restricted network access
- **CI/CD** - Control and log network access during builds and tests
- **Privacy** - Prevent applications from phoning home or leaking data

## How It Works

httpjail creates an isolated network environment for your process:

1. **Network Isolation**: On Linux, creates a network namespace; on macOS, uses environment variables
2. **Transparent Proxy**: All HTTP/HTTPS traffic is redirected through httpjail's proxy
3. **Rule Evaluation**: Each request is evaluated against your configured rules
4. **Action**: Requests are either allowed through or blocked based on the evaluation

## Getting Started

The simplest way to use httpjail is with JavaScript rules:

```bash
# Allow only requests to github.com
httpjail --js "r.host === 'github.com'" -- curl https://github.com

# Block everything (default behavior)
httpjail -- curl https://example.com
```

For more examples and detailed usage, see the [Quick Start](./guide/quick-start.md) guide.