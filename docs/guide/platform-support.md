# Platform Support

httpjail works differently on each platform due to OS-specific networking capabilities.

## Platform Comparison

| Feature           | Linux                    | macOS                  | Windows    |
| ----------------- | ------------------------ | ---------------------- | ---------- |
| Traffic isolation | ✅ Namespaces + nftables | ⚠️ Env vars only       | 🚧 Planned |
| TLS interception  | ✅ Transparent           | ✅ Via proxy settings  | 🚧 Planned |
| Sudo required     | ⚠️ Yes                   | ✅ No                  | 🚧         |
| Force all traffic | ✅ Yes                   | ❌ Apps must cooperate | 🚧         |

## Linux

Full network isolation using namespaces and nftables.

```
┌─────────────────────────────────────────────────┐
│                 httpjail Process                │
├─────────────────────────────────────────────────┤
│  1. Create network namespace                    │
│  2. Setup nftables rules                        │
│  3. Start embedded proxy + DNS server           │
│  4. Export CA trust env vars                    │
│  5. Execute target process in namespace         │
└─────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────┐
│              Target Process                     │
│  • Isolated in network namespace                │
│  • All HTTP/HTTPS → local proxy                 │
│  • All DNS queries → dummy resolver (6.6.6.6)   │
│  • CA cert trusted via env vars                 │
└─────────────────────────────────────────────────┘
```

### Prerequisites

- Linux kernel 3.8+ (network namespace support)
- nftables (`nft` command)
- libssl-dev (for TLS)
- sudo access (for namespace creation)

### How It Works

- Creates isolated network namespace
- Uses nftables to redirect all HTTP/HTTPS traffic
- Intercepts DNS queries (returns 6.6.6.6 to prevent exfiltration)
- Transparent TLS interception with per-host certificates

### Usage

```bash
# Strong mode (default) - full isolation
sudo httpjail --js "r.host === 'github.com'" -- curl https://api.github.com

# Weak mode - environment variables only (no sudo)
httpjail --weak --js "r.host === 'github.com'" -- curl https://api.github.com
```

## macOS

```
┌─────────────────────────────────────────────────┐
│                 httpjail Process                │
├─────────────────────────────────────────────────┤
│  1. Start HTTP/HTTPS proxy servers              │
│  2. Set HTTP_PROXY/HTTPS_PROXY env vars         │
│  3. Generate/load CA certificate                │
│  4. Execute target with proxy environment       │
└─────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────┐
│              Target Process                     │
│  • HTTP_PROXY/HTTPS_PROXY environment vars      │
│  • Applications must respect proxy settings     │
│  • CA cert via environment variables            │
└─────────────────────────────────────────────────┘
```

**Note**: Due to macOS PF (Packet Filter) limitations, httpjail uses environment-based proxy configuration on macOS. PF translation rules (such as `rdr` and `route-to`) cannot match on user or group, making transparent traffic interception impossible. As a result, httpjail operates in "weak mode" on macOS, relying on applications to respect the `HTTP_PROXY` and `HTTPS_PROXY` environment variables. Most command-line tools and modern applications respect these settings, but some may bypass them. See also https://github.com/coder/httpjail/issues/7.

### Prerequisites

- No special permissions required
- Applications must respect proxy environment variables

### Certificate Trust

httpjail generates a unique CA certificate for TLS interception:

```bash
# Check if CA is trusted
httpjail trust

# Install CA to user keychain (prompts for password)
httpjail trust --install

# Remove CA from keychain
httpjail trust --remove
```

**Note:** Most CLI tools respect the `SSL_CERT_FILE` environment variable that httpjail sets automatically. Go programs require the CA in the keychain.

### How It Works

- Sets `HTTP_PROXY` and `HTTPS_PROXY` environment variables
- Applications must voluntarily use these proxy settings
- Cannot force traffic from non-cooperating applications
- DNS queries are not intercepted

### Usage

```bash
# Always runs in weak mode on macOS (no sudo needed)
httpjail --js "r.host === 'github.com'" -- curl https://api.github.com
```

## Windows

Support is planned but not yet implemented.

## Mode Selection

httpjail automatically selects the appropriate mode:

- **Linux**: Strong mode by default, use `--weak` to force environment-only mode
- **macOS**: Always weak mode (environment variables)
- **Windows**: Not yet supported

## Environment Variables

httpjail sets these variables for the child process to trust the CA certificate:

- `SSL_CERT_FILE` / `SSL_CERT_DIR` - OpenSSL and most tools
- `CURL_CA_BUNDLE` - curl
- `REQUESTS_CA_BUNDLE` - Python requests
- `NODE_EXTRA_CA_CERTS` - Node.js
- `CARGO_HTTP_CAINFO` - Cargo
- `GIT_SSL_CAINFO` - Git
