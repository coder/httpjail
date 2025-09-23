# Configuration

httpjail can be configured through command-line options and environment variables.

## Command Line Options

### Core Options

- `--js <EXPR>` - JavaScript expression to evaluate requests
- `--js-file <PATH>` - JavaScript file to evaluate requests  
- `--sh <PATH>` - Shell script to evaluate requests
- `--request-log <PATH>` - Log all requests to file
- `--weak` - Use weak mode (environment variables only, no network isolation)

### Advanced Options

- `--timeout <SECONDS>` - Command timeout (default: no timeout)
- `--server` - Run in server mode
- `--address <ADDR>` - Proxy address (default: 127.0.0.1:0)
- `--no-jail-cleanup` - Don't clean up jail on exit (for debugging)

## Rule Evaluation

Rules are evaluated in the following order:
1. JavaScript expression (`--js`)
2. JavaScript file (`--js-file`)
3. Shell script (`--sh`)
4. Default: deny all

Only one rule type can be active at a time.

## Logging

Request logs follow the format:
```
<timestamp> <+|-> <METHOD> <URL>
```

Where:
- `+` indicates allowed request
- `-` indicates blocked request

## Environment Variables

httpjail sets the following environment variables in the jailed process:

- `HTTP_PROXY` - Proxy address for HTTP requests
- `HTTPS_PROXY` - Proxy address for HTTPS requests  
- `SSL_CERT_FILE` - Path to CA certificate for HTTPS interception
- `SSL_CERT_DIR` - Directory containing CA certificate

These ensure most applications automatically use httpjail's proxy.