# Line Processor

Stream requests to a long-running process for stateful, high-performance filtering.

## How It Works

1. httpjail spawns your processor once at startup
2. For each HTTP request, httpjail sends a JSON line to the processor's stdin
3. The processor evaluates and responds with "true" or "false"
4. The process continues running until httpjail exits

## Protocol

### Request Format

Each request is sent as a single JSON line:

```json
{
  "url": "https://example.com/api",
  "method": "GET",
  "host": "example.com",
  "scheme": "https",
  "path": "/api"
}
```

### Response Format

Your processor must respond with one line per request:

- **Boolean strings**: `"true"` (allow) or `"false"` (deny)
- **JSON object**: `{"allow": false, "deny_message": "Blocked by policy"}`
- **JSON with message only**: `{"deny_message": "Blocked"}` (implies deny)
- **JSON with byte limit**: `{"allow": {"max_tx_bytes": 1024}}` (allow but limit request upload to N bytes)
- **Any other text**: Treated as deny with that text as the message (e.g., `"Access denied"` becomes a deny with message "Access denied")

## Command Line Usage

```bash
# Use a Python script as processor
httpjail --proc ./filter.py -- your-command

# Use any executable
httpjail --proc "/usr/bin/python3 -u filter.py" -- your-command

# Pass arguments to the processor
httpjail --proc "./filter.sh --strict" -- your-command
```

## Examples

### Python Example

```python
#!/usr/bin/env python3
import sys, json

allowed_hosts = {'github.com', 'api.github.com'}
upload_hosts = {'uploads.example.com'}

for line in sys.stdin:
    try:
        req = json.loads(line)
        if req['host'] in allowed_hosts:
            print("true")
        elif req['host'] in upload_hosts:
            # Limit upload endpoints to 1KB requests
            response = {"allow": {"max_tx_bytes": 1024}}
            print(json.dumps(response))
        else:
            # Can return JSON for custom messages
            response = {"allow": False, "deny_message": f"{req['host']} not allowed"}
            print(json.dumps(response))
    except:
        print("Invalid request")  # Any non-boolean text becomes deny message
    sys.stdout.flush()  # Ensure immediate response
```

### Bash Example

```bash
#!/bin/bash

while IFS= read -r line; do
    host=$(echo "$line" | jq -r .host)

    if [[ "$host" == *.github.com ]]; then
        echo "true"
    else
        echo "false"
    fi
done
```

## Important Notes

- **Flush output after each response** (`sys.stdout.flush()` in Python, automatic in bash)
- **Handle errors gracefully** - always respond with allow or deny
- **Use stderr for debugging** - stdout is reserved for responses

## Best for

- High-throughput scenarios
- Stateful processing (caching, rate limiting)
- Complex logic requiring external libraries
