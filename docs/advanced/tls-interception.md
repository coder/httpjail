# TLS Interception

httpjail intercepts HTTPS traffic using a locally-generated Certificate Authority (CA) to inspect and filter encrypted requests.

## How It Works

1. **CA Generation**: On first run, httpjail creates a unique CA keypair
2. **Certificate Storage**: CA files are stored in your config directory:
   - Linux: `~/.config/httpjail/`
   - macOS: `~/Library/Application Support/httpjail/`
   - Windows: `%APPDATA%\httpjail\` (planned)
3. **Process Trust**: The jailed process trusts the CA via environment variables
4. **Per-Host Certificates**: Each HTTPS connection gets a certificate signed by the httpjail CA
5. **No System Changes**: Your system trust store is never modified

## Certificate Trust

httpjail sets these environment variables for the child process:

- `SSL_CERT_FILE` / `SSL_CERT_DIR` - OpenSSL and most tools
- `CURL_CA_BUNDLE` - curl
- `REQUESTS_CA_BUNDLE` - Python requests
- `NODE_EXTRA_CA_CERTS` - Node.js
- `DENO_CERT` - Deno
- `CARGO_HTTP_CAINFO` - Cargo
- `GIT_SSL_CAINFO` - Git

## Platform Differences

### Linux (Strong Mode)

- Transparently redirects TCP port 443 to the proxy
- Extracts SNI from TLS ClientHello
- No application cooperation needed

### macOS (Weak Mode)

- Uses `HTTP_PROXY`/`HTTPS_PROXY` environment variables
- HTTPS negotiated via CONNECT method
- Applications must respect proxy settings

## Application Support

| Platform | Environment Variables | System Trust Store |
| -------- | --------------------- | ------------------ |
| Linux    | 🟢 Vast majority      | N/A                |
| macOS    | 🟠 Some               | 🟢 Vast majority   |

Most CLI tools and libraries respect the CA environment variables that httpjail sets. On macOS, some tools (e.g. those built with Go) ignore these variables and require system trust. As
Linux doesn't have a concept of a "system trust store" the environment variables are
well supported.

On macOS, you can install the CA certificate to the keychain using `httpjail trust --install`.
