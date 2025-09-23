# Line Processor

The Line Processor mode (`--proc`) enables streaming evaluation of requests through a long-running process. This provides stateful filtering with better performance than shell scripts for high-volume scenarios.

## How It Works

1. httpjail spawns your processor once at startup
2. For each HTTP request, httpjail sends a JSON line to the processor's stdin
3. The processor evaluates and responds with "allow" or "deny"
4. The process continues running until httpjail exits

## Protocol

### Request Format

Each request is sent as a single JSON line:

```json
{"url":"https://example.com/api","method":"GET","host":"example.com","scheme":"https","path":"/api"}
```

### Response Format

Your processor must respond with exactly one line per request:
- `allow` - Allow the request
- `deny` - Block the request
- `deny: <reason>` - Block with custom error message

## Command Line Usage

```bash
# Use a Python script as processor
httpjail --proc ./filter.py -- your-command

# Use any executable
httpjail --proc "/usr/bin/python3 -u filter.py" -- your-command

# Pass arguments to the processor
httpjail --proc "./filter.sh --strict" -- your-command
```

## Implementation Examples

### Python Rate Limiter

```python
#!/usr/bin/env python3
import sys
import json
import time
from collections import defaultdict

# Rate limit: 100 requests per minute per host
rate_limits = defaultdict(lambda: {"count": 0, "reset": time.time() + 60})

# Ensure unbuffered output
sys.stdout = sys.stdout.reconfigure(line_buffering=True)

for line in sys.stdin:
    try:
        req = json.loads(line.strip())
        host = req["host"]
        
        # Reset counter if minute has passed
        if time.time() > rate_limits[host]["reset"]:
            rate_limits[host] = {"count": 1, "reset": time.time() + 60}
        else:
            rate_limits[host]["count"] += 1
        
        # Check rate limit
        if rate_limits[host]["count"] <= 100:
            print("allow")
        else:
            print(f"deny: Rate limit exceeded for {host}")
            
    except Exception as e:
        # On error, deny the request
        print(f"deny: Processing error: {e}")
        
    # Ensure output is flushed immediately
    sys.stdout.flush()
```

### Ruby Domain Allowlist

```ruby
#!/usr/bin/env ruby
require 'json'

# Configure allowed domains
ALLOWED_DOMAINS = [
  'github.com',
  'api.github.com',
  'registry.npmjs.org'
]

# Disable output buffering
STDOUT.sync = true

STDIN.each_line do |line|
  begin
    req = JSON.parse(line)
    
    if ALLOWED_DOMAINS.include?(req['host'])
      puts "allow"
    else
      puts "deny: #{req['host']} not in allowlist"
    end
    
  rescue => e
    puts "deny: #{e.message}"
  end
end
```

### Node.js Pattern Matcher

```javascript
#!/usr/bin/env node
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false
});

// Define patterns
const patterns = [
  { host: /^.*\.example\.com$/, method: 'GET' },
  { host: 'api.service.com', path: /^\/v1\// }
];

rl.on('line', (line) => {
  try {
    const req = JSON.parse(line);
    
    const allowed = patterns.some(pattern => {
      let hostMatch = pattern.host instanceof RegExp 
        ? pattern.host.test(req.host)
        : pattern.host === req.host;
        
      let methodMatch = !pattern.method || pattern.method === req.method;
      
      let pathMatch = !pattern.path || (
        pattern.path instanceof RegExp 
          ? pattern.path.test(req.path)
          : pattern.path === req.path
      );
      
      return hostMatch && methodMatch && pathMatch;
    });
    
    console.log(allowed ? 'allow' : 'deny');
  } catch (e) {
    console.log(`deny: ${e.message}`);
  }
});
```

### Bash Simple Filter

```bash
#!/bin/bash

# Read JSON and make decisions
while IFS= read -r line; do
    # Extract host using jq
    host=$(echo "$line" | jq -r .host)
    
    # Simple domain check
    case "$host" in
        *.internal.com|localhost|127.0.0.1)
            echo "allow"
            ;;
        *)
            echo "deny: External host $host not allowed"
            ;;
    esac
done
```

## Advanced Features

### Stateful Filtering

Track requests across time:

```python
#!/usr/bin/env python3
import sys, json
from datetime import datetime

# Track first request time per host
first_seen = {}

for line in sys.stdin:
    req = json.loads(line)
    host = req["host"]
    
    # Record first time we see each host
    if host not in first_seen:
        first_seen[host] = datetime.now()
        print(f"allow")  # Allow first request
    else:
        # Block if host was first seen over an hour ago
        age = (datetime.now() - first_seen[host]).seconds
        if age > 3600:
            print(f"deny: Session expired for {host}")
        else:
            print("allow")
    
    sys.stdout.flush()
```

### Machine Learning Integration

```python
#!/usr/bin/env python3
import sys, json
import joblib

# Load pre-trained model
model = joblib.load('request_classifier.pkl')

for line in sys.stdin:
    req = json.loads(line)
    
    # Extract features
    features = [
        len(req['path']),
        req['method'] == 'POST',
        'api' in req['host'],
        req['path'].count('/'),
        # ... more features
    ]
    
    # Predict: 0 = malicious, 1 = benign
    prediction = model.predict([features])[0]
    
    print("allow" if prediction == 1 else "deny: Suspicious request pattern")
    sys.stdout.flush()
```

## Best Practices

### 1. Always Flush Output
Ensure your processor flushes output after each response:

- **Python**: `sys.stdout.flush()` or use `-u` flag
- **Ruby**: `STDOUT.sync = true`
- **Node.js**: Automatic with `console.log`
- **Bash**: Automatic with `echo`

### 2. Handle Errors Gracefully
Always wrap processing in try-catch blocks:

```python
for line in sys.stdin:
    try:
        req = json.loads(line)
        # ... process request
    except:
        print("deny: Processing error")
    finally:
        sys.stdout.flush()
```

### 3. Validate Input
Don't assume the JSON structure:

```python
req = json.loads(line)
host = req.get('host', '')
method = req.get('method', 'GET')
```

### 4. Log for Debugging
Write debug logs to stderr, not stdout:

```python
import sys
print(f"Debug: Processing {host}", file=sys.stderr)
print("allow")  # This goes to stdout
```

## Performance Tips

1. **Minimize startup time**: Do heavy initialization once at startup
2. **Use efficient data structures**: Dictionaries for lookups, sets for membership
3. **Avoid blocking operations**: Don't make synchronous network calls per request
4. **Cache when possible**: Store frequently accessed data in memory
5. **Profile your code**: Identify bottlenecks in high-volume scenarios

## Debugging

Test your processor standalone:

```bash
# Test with sample input
echo '{"url":"https://example.com","method":"GET","host":"example.com","scheme":"https","path":"/"}' | ./filter.py

# Test with httpjail in verbose mode
RUST_LOG=debug httpjail --proc ./filter.py -- curl https://example.com
```

Monitor processor health:

```bash
# Check if processor is running
ps aux | grep filter.py

# Monitor CPU/memory usage
top -p $(pgrep -f filter.py)
```

## Common Pitfalls

1. **Buffered output**: Always disable output buffering
2. **Slow startup**: Avoid heavy initialization that delays first request
3. **Memory leaks**: Clean up state periodically in long-running processes
4. **Deadlocks**: Ensure you always respond to each request
5. **Encoding issues**: Handle UTF-8 properly in URLs and paths

## Comparison with Other Modes

| Aspect | Line Processor | JavaScript | Shell Script |
|--------|---------------|------------|--------------|
| Performance | Good | Excellent | Poor |
| Startup time | Slow | Fast | None |
| Stateful | Yes | No | No |
| Language | Any | JavaScript | Bash/Shell |
| Complexity | Medium | Low | Low |
| External tools | Yes | No | Yes |

## When to Use Line Processor

✅ **Good for:**
- High-volume request filtering
- Stateful decision making
- Complex business logic
- Integration with ML models
- Custom protocols

❌ **Not ideal for:**
- Simple host/path filtering (use JavaScript)
- One-off scripts (use shell mode)
- Untrusted rule sources (use JavaScript)
