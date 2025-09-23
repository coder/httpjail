# JavaScript Rules

httpjail uses the V8 JavaScript engine to evaluate requests efficiently and securely.

## The Request Object

Each request is exposed to your JavaScript code as the `r` object with the following properties:

- `r.url` - Full URL (string)
- `r.method` - HTTP method (string, e.g., "GET", "POST")
- `r.host` - Hostname (string, e.g., "example.com")
- `r.scheme` - URL scheme (string, "http" or "https")
- `r.path` - URL path (string, e.g., "/api/users")

## Rule Syntax

### Inline Rules

Simple expressions can be passed directly via `--js`:

```bash
# Single condition
httpjail --js "r.host === 'github.com'" -- command

# Multiple conditions
httpjail --js "r.host === 'api.example.com' && r.method === 'GET'" -- command

# Using arrays
httpjail --js "['GET', 'POST'].includes(r.method)" -- command
```

### File-based Rules

For complex logic, use a JavaScript file:

```javascript
// rules.js
// Define your logic
const allowedHosts = ['github.com', 'api.github.com'];
const isProduction = process.env.NODE_ENV === 'production';

// The last expression is the result
allowedHosts.includes(r.host) && (!isProduction || r.method !== 'DELETE');
```

```bash
httpjail --js-file rules.js -- command
```

## Common Patterns

### Domain Allowlisting

```javascript
// Allow specific domains
const allowed = ['example.com', 'api.example.com'];
allowed.includes(r.host)
```

### Subdomain Matching

```javascript
// Allow all subdomains of example.com
r.host === 'example.com' || r.host.endsWith('.example.com')
```

### Path-based Rules

```javascript
// Allow only specific API endpoints
r.host === 'api.example.com' && 
r.path.startsWith('/v1/public/')
```

### Method Restrictions

```javascript
// Read-only access
['GET', 'HEAD', 'OPTIONS'].includes(r.method)
```

### Regular Expressions

```javascript
// Match patterns
/^api\d+\.example\.com$/.test(r.host)
```

## Advanced Examples

### Environment-based Rules

```javascript
// Different rules for different environments
const isDev = r.host === 'localhost' || r.host === '127.0.0.1';
const isProd = r.host.endsWith('.production.example.com');

if (isDev) {
  true; // Allow all in development
} else if (isProd) {
  r.method === 'GET'; // Read-only in production
} else {
  false; // Deny everything else
}
```

### Service-specific Rules

```javascript
// Package manager rules
const npmHosts = ['registry.npmjs.org', 'registry.yarnpkg.com'];
const pypiHosts = ['pypi.org', 'files.pythonhosted.org'];
const cargoHosts = ['crates.io', 'static.crates.io'];

const isPackageManager = 
  npmHosts.includes(r.host) ||
  pypiHosts.includes(r.host) ||
  cargoHosts.includes(r.host);

isPackageManager
```

### API Rate Limiting Preparation

```javascript
// Log specific endpoints for rate limiting analysis
if (r.host === 'api.example.com' && r.path.startsWith('/v1/')) {
  console.log(`API call: ${r.method} ${r.path}`);
  true;
} else {
  false;
}
```

## Security Considerations

- JavaScript evaluation is sandboxed using V8 isolates
- No access to file system, network, or other system resources  
- Limited execution time to prevent infinite loops
- The `r` object is read-only

## Performance

JavaScript rules are compiled once and cached, making them very fast for repeated evaluations. For best performance:

1. Keep expressions simple
2. Avoid complex regular expressions
3. Use early returns in conditional logic
4. Prefer simple property checks over method calls

## Debugging

Test your rules before deployment:

```bash
# Test with verbose output
httpjail --js-file rules.js --request-log /dev/stdout -- curl https://example.com
```

Look for blocked requests in the log to understand what's being filtered.