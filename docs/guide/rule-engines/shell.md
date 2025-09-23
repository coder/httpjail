# Shell Script Rule Engine

Execute external scripts or programs to evaluate HTTP requests. Use any language or integrate with external systems.

## How It Works

With `--sh`, httpjail executes your script for each request, passing details through environment variables. Exit code 0 allows the request, non-zero denies it.

## Basic Usage

```bash
# Use a shell script for evaluation
httpjail --sh "./policy.sh" -- curl https://api.example.com

# Use an inline command
httpjail --sh "exit 0" -- curl https://example.com  # Allow all

# Use any executable
httpjail --sh "/usr/local/bin/my-policy-checker" -- ./my-app
```

## Environment Variables

Your script receives the following environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `HTTPJAIL_URL` | Complete request URL | `https://api.github.com/repos` |
| `HTTPJAIL_METHOD` | HTTP method | `GET`, `POST`, `PUT`, etc. |
| `HTTPJAIL_SCHEME` | URL scheme | `http` or `https` |
| `HTTPJAIL_HOST` | Hostname from URL | `api.github.com` |
| `HTTPJAIL_PATH` | URL path | `/repos` |
| `HTTPJAIL_REQUESTER_IP` | IP of the requesting process | `127.0.0.1` |

## Exit Codes and Output

- **Exit code 0**: Request is **allowed**
- **Any non-zero exit code**: Request is **denied**
- **stdout**: Becomes the response body for denied requests (useful for custom error messages)
- **stderr**: Logged for debugging (use `RUST_LOG=debug` to see)

## Examples

### Simple Allow/Deny Script

```bash
#!/bin/sh
# allow-github.sh - Only allow GitHub API requests

case "$HTTPJAIL_HOST" in
    api.github.com|github.com)
        exit 0  # Allow
        ;;
    *)
        echo "Only GitHub requests allowed"
        exit 1  # Deny
        ;;
esac
```

### Domain Allowlist

Command:
```bash
httpjail --sh "./rules.sh" -- curl https://api.github.com/repos
```

In `whitelist.txt`:
```
api.github.com
github.com
raw.githubusercontent.com
api.gitlab.com
gitlab.com
```

In `rules.sh`:
```bash
#!/bin/sh
# Check if host is in whitelist file

# Read whitelist file (one domain per line)
WHITELIST_FILE="./whitelist.txt"

# Check if whitelist file exists
if [ ! -f "$WHITELIST_FILE" ]; then
    echo "Whitelist file not found: $WHITELIST_FILE"
    exit 1
fi

# Check if current host is in the whitelist (exact match)
if grep -Fxq "$HTTPJAIL_HOST" "$WHITELIST_FILE"; then
    exit 0  # Allow
else
    echo "Host $HTTPJAIL_HOST not in whitelist"
    exit 1  # Deny
fi
```

### Method-Based Restrictions

```bash
#!/bin/sh
# read-only.sh - Only allow safe HTTP methods

case "$HTTPJAIL_METHOD" in
    GET|HEAD|OPTIONS)
        exit 0
        ;;
    *)
        echo "Method $HTTPJAIL_METHOD not allowed (read-only mode)"
        exit 1
        ;;
esac
```

### Using Other Languages

```python
#!/usr/bin/env python3
import os, sys

if os.environ.get('HTTPJAIL_HOST') == 'api.github.com':
    sys.exit(0)  # Allow
else:
    print("Only GitHub API allowed")
    sys.exit(1)  # Deny
```

## Script vs Command

httpjail determines how to execute your script:

- **Contains spaces**: Executed as `sh -c "your command"`
- **No spaces**: Executed directly as a binary/script

```bash
# These are equivalent:
httpjail --sh "exit 0" -- curl example.com
httpjail --sh "./my-script.sh" -- curl example.com

# But this runs the binary directly (more efficient):
httpjail --sh "/usr/local/bin/policy-check" -- curl example.com
```

## Error Handling

### Script Not Found

```bash
$ httpjail --sh "./nonexistent.sh" -- curl example.com
# Error: Script execution failed: No such file or directory
```

### Script Not Executable

```bash
$ httpjail --sh "./policy.sh" -- curl example.com
# Error: Script execution failed: Permission denied
# Fix: chmod +x ./policy.sh
```

### Script Timeout

Scripts that run longer than 30 seconds are automatically terminated:

```bash
#!/bin/sh
# This will timeout
sleep 60
exit 0
```

## When to Use Shell Scripts

Best for:
- External integrations (databases, APIs)
- Reusing existing scripts/tools
- Any programming language

Avoid for:
- High-throughput scenarios (use line processor mode)
- Simple logic (use JavaScript)

For high-throughput scenarios, consider the [Line Processor](./line-processor.md) mode which maintains a single process.
