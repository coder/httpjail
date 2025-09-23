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

## Response Types

Your JavaScript can return:

- **Boolean**: `true` to allow, `false` to deny
- **Object with message**: `{allow: false, deny_message: "Custom error"}`
- **Just a message**: `{deny_message: "Blocked"}` (implies deny)

```javascript
// Simple boolean
true  // Allow
false // Deny

// With custom deny message (needs parentheses in inline expressions)
({allow: false, deny_message: "Social media blocked"})

// Conditional with message
r.host === 'facebook.com' ? {deny_message: 'Social media blocked'} : true
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

## When to Use

Best for:
- Simple host/path filtering
- Quick prototyping
- Untrusted rule sources (sandboxed)

Avoid for:
- Stateful processing (use line processor)
- External integrations (use shell or line processor)
