# Command Line Options

Complete reference for httpjail command line options.

## Synopsis

```
httpjail [OPTIONS] [-- <COMMAND> [ARGS...]]
```

## Options

### Rule Evaluation

#### `--js <EXPRESSION>`
JavaScript expression to evaluate each request. The expression has access to a request object `r` with properties: `url`, `method`, `host`, `scheme`, `path`.

Example:
```bash
httpjail --js "r.host === 'github.com'" -- git pull
```

#### `--js-file <PATH>`
Path to JavaScript file containing request evaluation logic. The file should contain a JavaScript expression that evaluates to a boolean.

Example:
```bash
httpjail --js-file ./rules.js -- npm install
```

#### `--sh <PATH>`
Path to shell script for request evaluation. The script receives request details via environment variables and should exit with 0 to allow, non-zero to block.

Environment variables passed to script:
- `HTTPJAIL_URL` - Full URL
- `HTTPJAIL_METHOD` - HTTP method
- `HTTPJAIL_HOST` - Hostname
- `HTTPJAIL_SCHEME` - URL scheme (http/https)
- `HTTPJAIL_PATH` - URL path

Example:
```bash
httpjail --sh ./check.sh -- curl https://example.com
```

### Logging

#### `--request-log <PATH>`
Log all HTTP requests to specified file. Use `/dev/stdout` or `/dev/stderr` for console output.

Format: `<timestamp> <+|-> <METHOD> <URL>`

Example:
```bash
httpjail --request-log requests.log --js "true" -- npm install
```

### Network Mode

#### `--weak`
Use weak mode (environment variables only) instead of strong network isolation. This mode doesn't require root privileges but provides less isolation.

Example:
```bash
httpjail --weak --js "true" -- curl https://example.com
```

### Execution Control

#### `--timeout <SECONDS>`
Set timeout for command execution in seconds.

Example:
```bash
httpjail --timeout 30 --js "true" -- npm install
```

### Server Mode

#### `--server`
Run httpjail as a standalone proxy server instead of executing a command.

Example:
```bash
httpjail --server --js "true"
```

#### `--address <ADDR>`
Set proxy listening address (default: 127.0.0.1:0). Format: `<ip>:<port>`.

Example:
```bash
httpjail --server --address 0.0.0.0:8080 --js "true"
```

### Trust Management

#### `trust --install`
Install httpjail's CA certificate to system trust store.

Example:
```bash
httpjail trust --install
```

#### `trust --uninstall`
Remove httpjail's CA certificate from system trust store.

Example:
```bash
httpjail trust --uninstall
```

### Debugging

#### `--no-jail-cleanup`
Don't clean up network namespace and iptables rules on exit (Linux only). Useful for debugging.

Example:
```bash
httpjail --no-jail-cleanup --js "true" -- curl https://example.com
```

### Information

#### `--help`
Display help information.

#### `--version`
Display version information.

## Examples

### Basic Usage

```bash
# Block all requests (default)
httpjail -- curl https://example.com

# Allow all requests
httpjail --js "true" -- curl https://example.com

# Allow specific host
httpjail --js "r.host === 'github.com'" -- git clone https://github.com/user/repo
```

### Complex Filtering

```bash
# Multiple conditions
httpjail --js "r.host === 'api.example.com' && r.method === 'GET'" -- app

# Using a rules file
echo "r.host.endsWith('.example.com')" > rules.js
httpjail --js-file rules.js -- app
```

### Monitoring

```bash
# Log to console
httpjail --request-log /dev/stdout --js "true" -- npm install

# Log to file with timeout
httpjail --request-log build.log --timeout 300 --js "true" -- make build
```

### Development

```bash
# Weak mode for development
httpjail --weak --js "r.host === 'localhost'" -- npm run dev

# Server mode for testing
httpjail --server --address 127.0.0.1:8888 --js "true"
```

## Exit Codes

- `0` - Success
- `1` - General error
- `124` - Command timeout (when using `--timeout`)
- `125` - httpjail internal error
- `126` - Command found but not executable
- `127` - Command not found
- Other - Exit code from the executed command