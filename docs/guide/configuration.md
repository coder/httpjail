# Configuration

httpjail's behavior can be configured through command-line options, environment variables, and configuration files. This page provides an overview of how these work together.

## Configuration Hierarchy

httpjail follows a simple configuration hierarchy:

1. **Command-line options** - Highest priority, override everything
2. **Environment variables** - Set by httpjail for the jailed process

## Key Configuration Areas

### Rule Engine Selection

Choose how requests are evaluated:

- **JavaScript** (`--js` or `--js-file`) - Fast, sandboxed evaluation
  - Files specified with `--js-file` are automatically reloaded when changed
- **Shell Script** (`--sh`) - System integration, external tools
- **Line Processor** (`--proc`) - Stateful, streaming evaluation

Only one rule engine can be active at a time. See [Rule Engines](./rule-engines/index.md) for detailed comparison.

### Network Mode

Control the isolation level:

- **Strong mode** (default on Linux) - Full network namespace isolation
- **Weak mode** (`--weak`) - Environment variables only, no isolation
- **Server mode** (`--server`) - Run as standalone proxy server

### Logging and Monitoring

Track what's happening:

- **Request logging** (`--request-log`) - Log all HTTP requests
- **Debug output** (`RUST_LOG=debug`) - Detailed operational logs
- **Process output** - Captured from the jailed command

See [Request Logging](./request-logging.md) for details.

## Common Configurations

### Development Environment

```bash
# Allow localhost and common dev services
httpjail --js "['localhost', '127.0.0.1'].includes(r.host)" \
         --request-log /dev/stdout \
         -- npm run dev
```

### CI/CD Pipeline

```bash
# Strict allow-list for builds
httpjail --js-file ci-rules.js \
         --request-log build-network.log \
         --timeout 600 \
         -- make build
```

### Production Service

```bash
# Stateful filtering with monitoring
httpjail --proc ./rate-limiter.py \
         --request-log /var/log/httpjail/requests.log \
         -- ./api-server
```

## Environment Variables

### Set by httpjail

These are automatically set in the jailed process:

| Variable        | Description                  | Example                  |
| --------------- | ---------------------------- | ------------------------ |
| `HTTP_PROXY`    | HTTP proxy address           | `http://127.0.0.1:34567` |
| `HTTPS_PROXY`   | HTTPS proxy address          | `http://127.0.0.1:34567` |
| `SSL_CERT_FILE` | CA certificate path          | `/tmp/httpjail-ca.pem`   |
| `SSL_CERT_DIR`  | CA certificate directory     | `/tmp/httpjail-certs/`   |
| `NO_PROXY`      | Bypass proxy for these hosts | `localhost,127.0.0.1`    |

### Controlling httpjail

These affect httpjail's behavior:

| Variable           | Description                | Example                          |
| ------------------ | -------------------------- | -------------------------------- |
| `RUST_LOG`         | Logging level              | `debug`, `info`, `warn`, `error` |
| `HTTPJAIL_CA_CERT` | Custom CA certificate path | `/etc/pki/custom-ca.pem`         |

## Platform-Specific Configuration

### Linux

- Uses network namespaces for strong isolation
- Requires root/sudo for namespace operations
- iptables rules for traffic redirection
- Supports all network modes

### macOS

- Limited to weak mode (environment variables)
- No root required for standard operation
- Certificate trust via Keychain Access
- Some apps may ignore proxy variables

See [Platform Support](./platform-support.md) for detailed information.

## Troubleshooting Configuration

### Rules not matching

```bash
# Debug rule evaluation
RUST_LOG=debug httpjail --js "r.host === 'example.com'" -- curl https://example.com

# Log all requests to see what's being evaluated
httpjail --request-log /dev/stderr --js "false" -- your-app
```

### Environment variables not working

```bash
# Check what's set in the jail
httpjail --js "true" -- env | grep -E "(HTTP|PROXY|SSL)"

# Verify proxy is listening
httpjail --js "true" -- curl -I http://127.0.0.1:$PROXY_PORT
```

### Certificate issues

```bash
# Trust the CA certificate
httpjail trust --install

# Check certificate details
openssl x509 -in ~/.config/httpjail/ca-cert.pem -text -noout
```

## Next Steps

- [Rule Engines](./rule-engines/index.md) - Choose the right evaluation method
- [Request Logging](./request-logging.md) - Monitor and audit requests
- [Platform Support](./platform-support.md) - Platform-specific details
