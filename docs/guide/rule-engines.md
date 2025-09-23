# Rule Engines

httpjail provides three different rule engines for evaluating HTTP requests. Each has different trade-offs in terms of performance, flexibility, and ease of use.

## Available Engines

### JavaScript (V8)

Fast, secure JavaScript evaluation using the V8 engine. Best for most use cases.

**Pros:**

- ⚡ Fastest performance (compiled and cached)
- 🔒 Sandboxed execution environment
- 📝 Familiar JavaScript syntax
- 🎯 Direct access to request properties

**Cons:**

- Limited to JavaScript expressions
- No external tool integration
- No stateful operations between requests

**Use when:** You need high-performance filtering with simple to moderate logic.

### Shell Scripts

Execute shell scripts for each request with full system access.

**Pros:**

- 🔧 Full system access and tool integration
- 📊 Can maintain state between requests
- 🔗 Integrate with existing scripts and tools
- 💾 Can query databases or external services

**Cons:**

- Slow (process spawn per request)
- Security considerations with shell execution
- Platform-specific behavior

**Use when:** You need to integrate with existing tools or require complex system interactions.

### Line Processor

Stream-based processing with line-by-line evaluation.

**Pros:**

- 🚀 Long-running process (no spawn overhead)
- 📈 Can maintain state across requests
- 🐍 Language agnostic (Python, Ruby, etc.)
- 🔄 Bi-directional communication

**Cons:**

- More complex to implement
- Requires handling the protocol correctly
- Process management considerations

**Use when:** You have high request volume and need stateful processing or want to use a specific language.

## Performance Comparison

| Engine         | Startup Time | Per-Request Overhead | Memory Usage | Stateful |
| -------------- | ------------ | -------------------- | ------------ | -------- |
| JavaScript     | Fast         | ~0.1ms               | Low          | No       |
| Shell Script   | None         | ~10-50ms             | Variable     | No\*     |
| Line Processor | Slow         | ~0.5ms               | Variable     | Yes      |

\*Shell scripts can use files for state but each invocation is independent

## Choosing a Rule Engine

### For Production Use

**JavaScript** is recommended for production environments due to:

- Excellent performance
- Predictable resource usage
- Security isolation
- Simple deployment

### For Development/Testing

**Shell scripts** work well for:

- Rapid prototyping
- Integration testing
- Debugging complex scenarios

### For Complex Filtering

**Line Processor** excels at:

- Machine learning models
- Statistical analysis
- Complex stateful logic
- Custom protocols

## Examples

### Simple Host Filtering

All three engines can handle basic filtering:

**JavaScript:**

```bash
httpjail --js "r.host === 'github.com'" -- command
```

**Shell Script:**

```bash
#!/bin/bash
[[ "$HTTPJAIL_HOST" == "github.com" ]] && exit 0 || exit 1
```

**Line Processor:**

```python
#!/usr/bin/env python3
import sys, json
for line in sys.stdin:
    req = json.loads(line)
    print("allow" if req["host"] == "github.com" else "deny")
```

### Complex Logic

For complex scenarios, consider the implementation complexity:

**JavaScript** - Limited to expression evaluation:

```javascript
// Complex but still performant
const allowed = ["api.example.com", "cdn.example.com"];
allowed.includes(r.host) && r.method === "GET" && r.path.startsWith("/v1/");
```

**Shell Script** - Can use any tool but slow:

```bash
#!/bin/bash
# Check against database, but spawns process per request
psql -c "SELECT allowed FROM rules WHERE host='$HTTPJAIL_HOST'" | grep -q true
```

**Line Processor** - Best for complex stateful logic:

```python
#!/usr/bin/env python3
# Maintains state, handles thousands of requests efficiently
import sys, json, time
from collections import defaultdict

rate_limits = defaultdict(lambda: {"count": 0, "reset": time.time() + 60})

for line in sys.stdin:
    req = json.loads(line)
    host_limit = rate_limits[req["host"]]

    if time.time() > host_limit["reset"]:
        host_limit["count"] = 0
        host_limit["reset"] = time.time() + 60

    if host_limit["count"] < 100:  # 100 requests per minute
        host_limit["count"] += 1
        print("allow")
    else:
        print("deny")
    sys.stdout.flush()
```

## Next Steps

- [JavaScript Rules](./javascript-rules.md) - Learn the JavaScript API
- [Shell Scripts](./shell-scripts.md) - Integrate with system tools
- [Line Processor](./line-processor.md) - Build stateful filters
