# Docker

httpjail can run as a standalone proxy server in a Docker container, perfect for team-wide policy enforcement or testing. An example Dockerfile is provided in the [`examples/`](https://github.com/coder/httpjail/tree/main/examples) directory.

## Building the Image

The example Dockerfile downloads httpjail from GitHub releases and runs as a non-root user (UID 1000). Multi-arch builds are supported for `linux/amd64` and `linux/arm64`.

**Build for your current platform:**

```bash
cd examples/
docker build -t httpjail:latest .
```

**Build for a specific platform:**

```bash
# For amd64 (x86_64)
docker build --platform linux/amd64 -t httpjail:amd64 .

# For arm64 (aarch64)
docker build --platform linux/arm64 -t httpjail:arm64 .
```

**Build and push multi-arch image to a registry:**

```bash
# Create and use a new buildx builder (one-time setup)
docker buildx create --name multiarch --use

# Build and push for both architectures
docker buildx build --platform linux/amd64,linux/arm64 \
  -t your-registry/httpjail:latest \
  --push .

# Or build and load locally (single platform only)
docker buildx build --platform linux/amd64 \
  -t httpjail:latest \
  --load .
```

> **Note:** Multi-arch builds require [Docker Buildx](https://docs.docker.com/build/buildx/). The `--load` flag only works with single-platform builds; use `--push` for multi-platform images.

## Running the Container

**Basic usage with default allow-all rule:**

```bash
docker run -d --name httpjail \
  -p 8080:8080 -p 8443:8443 \
  httpjail:latest
```

**With persistent certificates:**

```bash
mkdir -p ./httpjail-certs
docker run -d --name httpjail \
  -p 8080:8080 -p 8443:8443 \
  -v ./httpjail-certs:/home/httpjail/.config/httpjail \
  httpjail:latest
```

**With custom rules:**

```bash
# Create your custom rule file
cat > my-rules.js <<'EOF'
// Allow only specific domains
const allowed = ['github.com', 'api.github.com', 'npmjs.org'];
allowed.includes(r.host)
EOF

# Run with custom rules (overrides default rules.js)
docker run -d --name httpjail \
  -p 8080:8080 -p 8443:8443 \
  -v ./httpjail-certs:/home/httpjail/.config/httpjail \
  -v ./my-rules.js:/rules/rules.js:ro \
  httpjail:latest
```

**With additional verbosity:**

```bash
docker run -d --name httpjail \
  -p 8080:8080 -p 8443:8443 \
  httpjail:latest --server --js-file /rules/rules.js -vv --request-log /dev/stderr
```

## Configuring Clients

After starting the container, configure your applications to use the proxy:

```bash
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8443
```

For HTTPS to work, clients need to trust the CA certificate. Extract it from the container:

```bash
# Extract CA certificate
docker cp httpjail:/home/httpjail/.config/httpjail/ca-cert.pem ./ca-cert.pem

# Configure client
export SSL_CERT_FILE=$PWD/ca-cert.pem

# Test
curl https://github.com
```

Alternatively, install the certificate system-wide:

```bash
# Linux
sudo cp ca-cert.pem /usr/local/share/ca-certificates/httpjail.crt
sudo update-ca-certificates

# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca-cert.pem
```

## Viewing Logs

Request logs are sent to stdout by default (visible in `docker logs`):

```bash
docker logs -f httpjail
```

Log format: `<timestamp> <+/-> <METHOD> <URL>` where `+` means allowed and `-` means blocked.

## JavaScript Rule Examples

The default rule (`true`) allows all traffic. Here are more useful examples:

**Allowlist specific domains:**

```javascript
const allowed = ['github.com', 'api.github.com', 'npmjs.org'];
allowed.includes(r.host)
```

**Block specific paths:**

```javascript
// Allow all except admin paths
!r.path.startsWith('/admin')
```

**Size limits:**

```javascript
// Allow GET requests under 10MB
if (r.method === 'GET') {
  ({allow: {max_tx_bytes: 10 * 1024 * 1024}})
} else {
  false  // Block non-GET
}
```

**Custom deny messages:**

```javascript
if (r.host === 'malicious.com') {
  ({allow: false, deny_message: 'Blocked: Known malicious domain'})
} else {
  true
}
```

**Complex policies:**

```javascript
// Allow GitHub and NPM GET requests, deny everything else
const trustedDomains = ['github.com', 'api.github.com', 'npmjs.org', 'registry.npmjs.org'];
const isTrusted = trustedDomains.includes(r.host);
const isSafeMethod = ['GET', 'HEAD'].includes(r.method);

isTrusted && isSafeMethod
```

See the [JavaScript rule engine](../guide/rule-engines/javascript.md) documentation for complete reference.

## Security Notes

- The container runs as non-root user (UID 1000)
- Server mode does NOT provide network isolation (no namespaces)
- Applications must be configured to use the proxy (HTTP_PROXY/HTTPS_PROXY)
- The Docker image supports both `linux/amd64` (x86_64) and `linux/arm64` (aarch64) architectures
- Certificates are auto-generated on first run if not provided via volume mount
