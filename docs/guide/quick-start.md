# Quick Start

This guide will help you get started with httpjail quickly.

> **Note**: By default, httpjail denies all network requests. You must provide rules to allow traffic.

## Basic Usage

The basic syntax for httpjail is:

```bash
httpjail [OPTIONS] -- <COMMAND> [ARGS...]
```

## Examples

### Allow All Requests

```bash
# Allow all HTTP/HTTPS requests (not recommended for production)
httpjail --js "true" -- curl https://example.com
```

### Allow Specific Hosts

```bash
# Allow only requests to github.com
httpjail --js "r.host === 'github.com'" -- git clone https://github.com/user/repo.git

# Allow multiple hosts
httpjail --js "['github.com', 'api.github.com'].includes(r.host)" -- your-app

# Allow using regex
httpjail --js "/^.*\\.example\\.com$/.test(r.host)" -- npm install
```

### Filter by Method

```bash
# Only allow GET requests
httpjail --js "r.method === 'GET'" -- curl https://api.example.com

# Allow GET and POST
httpjail --js "['GET', 'POST'].includes(r.method)" -- your-app
```

### Complex Rules

```bash
# Allow only GET requests to api.example.com
httpjail --js "r.host === 'api.example.com' && r.method === 'GET'" -- curl https://api.example.com/data

# Allow specific path patterns
httpjail --js "r.host === 'api.github.com' && r.path.startsWith('/repos/')" -- gh repo list
```

### Using Rule Files

For complex rules, use a JavaScript file:

```javascript
// rules.js
// Allow GitHub API and npmjs.org
const allowedHosts = [
  'api.github.com',
  'github.com',
  'registry.npmjs.org',
  'registry.yarnpkg.com'
];

const isAllowed = allowedHosts.some(host => 
  r.host === host || r.host.endsWith('.' + host)
);

// Result (must be a boolean expression)
isAllowed && r.method !== 'DELETE';
```

```bash
httpjail --js-file rules.js -- npm install
```

> **Tip:** Rules files are automatically reloaded when they change - perfect for development and debugging! Just edit `rules.js` and the changes take effect on the next request.

### Request Logging

Monitor what requests are being made:

```bash
# Log to stdout
httpjail --request-log /dev/stdout --js "true" -- your-app

# Log to file
httpjail --request-log requests.log --js "true" -- npm install

# Log format: <timestamp> <+/-> <METHOD> <URL>
# + means allowed, - means blocked
```

### Shell Script Rules

Use a shell script for complex logic:

```bash
#!/bin/bash
# check.sh
if [[ "$HTTPJAIL_HOST" == "github.com" ]]; then
  exit 0  # Allow
else
  echo "Blocked: $HTTPJAIL_HOST is not allowed"
  exit 1  # Block
fi
```

```bash
chmod +x check.sh
httpjail --sh ./check.sh -- git clone https://github.com/user/repo.git
```

## Common Patterns

### Development Environment

```bash
# Allow common development services
httpjail --js "
  ['localhost', '127.0.0.1', '::1'].includes(r.host) ||
  r.host.endsWith('.local') ||
  r.host === 'registry.npmjs.org'
" -- npm run dev
```

### CI/CD Pipeline

```bash
# Strict rules for CI
httpjail --js-file ci-rules.js --request-log build-requests.log -- make build
```

### Package Installation

```bash
# Allow package registries only
httpjail --js "
  ['registry.npmjs.org', 'registry.yarnpkg.com', 'pypi.org', 'crates.io']
    .some(h => r.host === h || r.host.endsWith('.' + h))
" -- npm install
```

## Debugging

When requests are blocked, httpjail returns a 403 Forbidden response with details:

```
HTTP/1.1 403 Forbidden
Content-Type: text/plain

httpjail: Blocked GET https://blocked.example.com/
```

Use `--request-log` to see all requests and understand what's being blocked:

```bash
httpjail --request-log /dev/stderr --js "false" -- curl https://example.com
# Will show: 2024-01-01 12:00:00 - GET https://example.com/
```

## Next Steps

- Learn about [JavaScript Rules](./rule-engines/javascript.md) for more complex filtering
- Explore [Configuration](./configuration.md) options
- Understand [Platform Support](./platform-support.md) differences