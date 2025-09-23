# Rule Engines

httpjail provides three different rule engines for evaluating HTTP requests. Each has different trade-offs in terms of performance, flexibility, and ease of use.

## Engine Comparison

| Feature | JavaScript (V8) | Shell Script | Line Processor |
|---------|----------------|--------------|----------------|
| **Performance** | | | |
| Per-Jail Overhead | None* | None | Process spawn (~2ms) |
| Per-Request Overhead | ~1-2ms** | ~2-5ms*** | <1ms**** |
| **Capabilities** | | | |
| Stateful Processing | ❌ | ✅ | ✅ |
| External Tool Access | ❌ | ✅ | ✅ |
| Language Choice | JS only | Any | Any |
| Sandboxed Execution | ✅ | ❌ | Depends |
| Development Complexity | Easy | Easy | Moderate |

\* V8 engine is created per-request, not per-jail (no persistent context)  
\*\* Creates new V8 isolate + compiles JS for each request  
\*\*\* Process spawn + script execution (similar to line processor startup)  
\*\*\*\* Simple IPC: write JSON line, read response line

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

- [JavaScript Rules](./javascript.md) - Learn the JavaScript API
- [Shell Scripts](./shell.md) - Integrate with system tools
- [Line Processor](./line-processor.md) - Build stateful filters
