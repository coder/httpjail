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
│  • User dropped to $SUDO_USER                   │
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
- CAP_SYS_ADMIN and CAP_NET_ADMIN capabilities (automatically available with sudo, or in privileged containers)

**Note:** httpjail no longer requires the `ip` command from `iproute2`. It uses direct syscalls and netlink for all network namespace operations. This allows it to work in minimal container images (like Alpine) or container runtimes like sysbox that provide the necessary capabilities but don't include the `iproute2` package.

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

### Running Inside Containers

httpjail works inside container environments (Docker, sysbox-runc, etc.) with proper capabilities:

```bash
# Docker with privileged mode (full capabilities)
docker run --privileged --rm -it alpine:latest sh -c '
  wget https://github.com/coder/httpjail/releases/latest/download/httpjail-linux-amd64 -O /usr/local/bin/httpjail
  chmod +x /usr/local/bin/httpjail
  apk add --no-cache nftables
  httpjail --js "r.host === \"example.com\"" -- wget -qO- https://example.com
'

# sysbox-runc (provides CAP_SYS_ADMIN automatically)
docker run --runtime=sysbox-runc --rm -it alpine:latest sh -c '
  wget https://github.com/coder/httpjail/releases/latest/download/httpjail-linux-amd64 -O /usr/local/bin/httpjail
  chmod +x /usr/local/bin/httpjail
  apk add --no-cache nftables
  httpjail --js "r.host === \"example.com\"" -- wget -qO- https://example.com
'

# Or use weak mode if you don't have the necessary capabilities
httpjail --weak --js "r.host === \"example.com\"" -- wget -qO- https://example.com
```

**Requirements for strong mode in containers:**
- CAP_SYS_ADMIN capability (for network namespace operations)
- CAP_NET_ADMIN capability (for network configuration)
- `nft` binary available (nftables)
- NO need for `iproute2` package

**Note:** Weak mode (`--weak`) works in any container but only sets HTTP_PROXY/HTTPS_PROXY environment variables, so applications must respect proxy settings.

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

## Weak Mode

Weak mode is available on all platforms and uses environment variables only:

```bash
httpjail --weak --js "r.host === 'allowed.com'" -- your-app
```

**Characteristics:**
- ✅ No root/sudo required
- ✅ Works on all platforms
- ❌ Apps must respect HTTP_PROXY/HTTPS_PROXY
- ❌ Cannot enforce policy on non-compliant apps
- ⚠️ Lower security than strong mode

**Use weak mode when:**
- You don't have root access
- Testing on macOS (default behavior)
- Working with proxy-aware applications
- Running in containers without CAP_SYS_ADMIN
