# JavaScript Rules

Fast, sandboxed request evaluation using the V8 JavaScript engine.

## The Request Object

Your JavaScript code receives a `r` object with these properties:

- `r.url` - Full URL
- `r.method` - HTTP method (GET, POST, etc.)
- `r.host` - Hostname
- `r.scheme` - URL scheme (http/https)
- `r.path` - URL path

## Basic Usage

### Inline Rules

```bash
# Allow specific host
httpjail --js "r.host === 'github.com'" -- command

# Multiple conditions
httpjail --js "r.host === 'api.example.com' && r.method === 'GET'" -- command

# Using arrays
httpjail --js "['GET', 'POST'].includes(r.method)" -- command
```

### File-based Rules

```javascript
// rules.js
const allowedHosts = ['github.com', 'api.github.com'];

// The last expression is the result
allowedHosts.includes(r.host);
```

```bash
httpjail --js-file rules.js -- command
```

#### Automatic File Reloading

When using `--js-file`, httpjail automatically detects and reloads the file when it changes. This is especially useful during development and debugging:

```bash
# Start with initial rules
echo "r.host === 'example.com'" > rules.js
httpjail --js-file rules.js -- your-app

# In another terminal, update the rules (reloads automatically on next request)
echo "r.host === 'github.com'" > rules.js
```

**How it works:**
- File modification time (mtime) is checked on each request
- If the file has changed, it's reloaded and validated
- Invalid JavaScript is rejected and existing rules are kept
- Reload happens atomically without interrupting request processing
- Zero overhead when the file hasn't changed

**Note:** File watching is only active when using `--js-file`. Inline rules (`--js`) do not reload.

## Response Format

{{#include ../../includes/response-format-table.md}}

**Examples:**

```javascript
// Simple boolean
true  // Allow
false // Deny

// With custom deny message (needs parentheses in inline expressions)
({allow: false, deny_message: "Social media blocked"})

// Conditional with message
r.host === 'facebook.com' ? {deny_message: 'Social media blocked'} : true

// Limit request upload size to 1KB (headers + body)
({allow: {max_tx_bytes: 1024}})
```

## Using Return Statements

JavaScript rules don't allow naked `return` statements. To use returns, wrap your code in an IIFE:

```javascript
(function() {
  if (r.host === 'github.com') {
    return true;
  }
  
  if (r.host.match(/facebook|twitter/)) {
    return {deny_message: "Blocked"};
  }
  
  return false;
})();
```

## Common Patterns

### Domain Allowlisting

```javascript
const allowed = ['example.com', 'api.example.com'];
allowed.includes(r.host)
```

### Subdomain Matching

```javascript
r.host === 'example.com' || r.host.endsWith('.example.com')
```

### Path-based Rules

```javascript
r.host === 'api.example.com' && r.path.startsWith('/v1/public/')
```

### Method Restrictions

```javascript
['GET', 'HEAD', 'OPTIONS'].includes(r.method)
```

### Host Whitelist

```javascript
// Simple host whitelist
const allowedHosts = [
  'github.com',
  'api.github.com',
  'raw.githubusercontent.com',
  'codeload.github.com'
];

allowedHosts.includes(r.host)
```

### Host + Method Whitelist

```javascript
// Allow specific methods only for certain hosts
const rules = [
  {host: 'api.github.com', methods: ['GET', 'POST']},
  {host: 'github.com', methods: ['GET']},
  {host: 'uploads.github.com', methods: ['POST', 'PUT']}
];

rules.some(rule => 
  rule.host === r.host && rule.methods.includes(r.method)
)
```

### Regexp Matching on Method + URL

```javascript
// Whitelist patterns for METHOD + URL combinations
const patterns = [
  /^GET api\.github\.com\/repos\/.+/,
  /^POST api\.example\.com\/v[12]\/.*/,
  /^(GET|HEAD) .*\.cdn\.example\.com\/.*\.(jpg|png|gif)/
];

// Build request string using host and path for simpler patterns
const requestString = `${r.method} ${r.host}${r.path}`;
patterns.some(pattern => pattern.test(requestString))
```

## Debugging with Console API

JavaScript rules support the full console API for debugging. Each method maps to a corresponding tracing level:

| Console Method | Tracing Level | Use Case |
|----------------|---------------|----------|
| `console.debug()` | DEBUG | Detailed troubleshooting information |
| `console.log()` | INFO | General informational messages |
| `console.info()` | INFO | Informational messages (e.g., allowed requests) |
| `console.warn()` | WARN | Warning messages (e.g., suspicious patterns) |
| `console.error()` | ERROR | Error messages (e.g., blocked threats) |

### Example

```javascript
// Debug: detailed information
console.debug("Evaluating request:", r.method, r.url);
console.debug("Full request:", r);

// Info: general messages
console.info("Allowing trusted domain:", r.host);

// Warn: suspicious patterns
console.warn("Suspicious path detected:", r.path);

// Error: security issues
console.error("Blocked malicious request:", r.url);
```

### Viewing Console Output

Set `RUST_LOG` to control which messages appear:

```bash
# Show debug and above (debug, info, warn, error) - all console output
RUST_LOG=debug httpjail --js-file rules.js -- command

# Show info and above (info, warn, error) - recommended for production
# Includes console.log(), console.info(), console.warn(), console.error()
RUST_LOG=info httpjail --js-file rules.js -- command

# Show only warnings and errors
RUST_LOG=warn httpjail --js-file rules.js -- command
```

Example output with color coding:

```
DEBUG httpjail::rules::js: Evaluating request: GET https://api.github.com/users
INFO  httpjail::rules::js: Allowing trusted domain: api.github.com
WARN  httpjail::rules::js: Suspicious path detected: /admin
ERROR httpjail::rules::js: Blocked malicious request: https://evil.com/exploit
```

### Objects and Arrays

Objects and arrays are automatically JSON-stringified:

```javascript
console.log("Request:", r);
// Output: Request: {"url":"https://...","method":"GET",...}

console.log("Complex:", {hosts: ["a.com", "b.com"], count: 42});
// Output: Complex: {"hosts":["a.com","b.com"],"count":42}
```

## When to Use

Best for:
- Simple host/path filtering
- Quick prototyping
- Untrusted rule sources (sandboxed)

Avoid for:
- Stateful processing (use line processor)
- External integrations (use shell or line processor)
