# httpjail

[![Documentation](https://img.shields.io/badge/docs-coder.github.io%2Fhttpjail-blue?logo=readthedocs&style=flat-square)](https://coder.github.io/httpjail/)
[![Crates.io](https://img.shields.io/crates/v/httpjail.svg)](https://crates.io/crates/httpjail)
[![CI](https://github.com/coder/httpjail/actions/workflows/tests.yml/badge.svg)](https://github.com/coder/httpjail/actions/workflows/tests.yml)

A cross-platform tool for monitoring and restricting HTTP/HTTPS requests from processes using network isolation and transparent proxy interception.

Install:

```bash
cargo install httpjail
```

Or download a pre-built binary from the [releases page](https://github.com/coder/httpjail/releases).

## Features

> [!WARNING]
> httpjail is experimental and offers no API or CLI compatibility guarantees.

- 🔒 **Process-level network isolation** - Isolate processes in restricted network environments
- 🌐 **HTTP/HTTPS interception** - Transparent proxy with TLS certificate injection
- 🛡️ **DNS exfiltration protection** - Prevents data leakage through DNS queries
- 🔧 **Multiple evaluation approaches** - JS expressions or custom programs
- 🖥️ **Cross-platform** - Native support for Linux and macOS

## Quick Start

> By default, httpjail denies all network requests. Provide a JS rule or script to allow traffic.

```bash
# Allow only requests to github.com (JS)
httpjail --js "r.host === 'github.com'" -- your-app

# Load JS from a file (auto-reloads only in --server mode)
echo "/^api\\.example\\.com$/.test(r.host) && r.method === 'GET'" > rules.js
httpjail --js-file rules.js -- curl https://api.example.com/health
# In command mode the policy is frozen for this run so the app cannot edit it.
# In --server mode, file changes are detected and reloaded on each request.

# Log requests to a file
httpjail --request-log requests.log --js "true" -- npm install
# Log format: "<timestamp> <+/-> <METHOD> <URL>" (+ = allowed, - = blocked)

# Use shell script for request evaluation (process per request)
httpjail --sh "/path/to/script.sh" -- ./my-app
# Script receives env vars: HTTPJAIL_URL, HTTPJAIL_METHOD, HTTPJAIL_HOST, etc.
# Exit code 0 allows, non-zero blocks

# Use line processor for request evaluation (efficient persistent process)
httpjail --proc /path/to/filter.py -- ./my-app
# Program receives JSON on stdin (one per line) and outputs allow/deny decisions
# stdin  -> {"method": "GET", "url": "https://api.github.com", "host": "api.github.com", ...}
# stdout -> true

# Run as standalone proxy server (no command execution) and allow all
httpjail --server --js "true"
# Server defaults to ports 8080 (HTTP) and 8443 (HTTPS)
# Configure your application:
# HTTP_PROXY=http://localhost:8080 HTTPS_PROXY=http://localhost:8443

# Run Docker containers with network isolation (Linux only)
sudo httpjail --js "r.host === 'api.github.com'" --docker-run -- --rm alpine:latest wget -qO- https://api.github.com
```

## Security-related defaults

- Structured rule results must explicitly set `allow: true` (or an `allow` byte-limit policy) to permit traffic. An empty object or a result with only `deny_message` denies the request. Stalled `--proc` input or output times out and denies the request; shell evaluator output and processor response lines are limited to 64 KiB.
- `max_tx_bytes` counts request-line, header, body-data, and trailer fields; it is a logical-byte limit, not an exact HTTP wire-byte cap (chunked framing can add bytes).
- `--timeout` terminates the command process group before cleaning up its jail; a process that deliberately leaves that group or a separately daemon-managed process may require additional supervision.
- Linux strong mode requires a non-root invoking user through `sudo`; running directly as root is rejected so a jailed root process cannot edit its own firewall. The payload runs with `no_new_privs` and no supplementary groups. The native strong jail blocks connections to host Unix-domain services via seccomp; local stream socketpairs remain available for in-process IPC, while Unix-socket clients/agents may not work. It does **not** isolate the filesystem or close explicitly inherited descriptors: keep policy files and their parent directories outside payload write access.
- When run as root on Linux, including `--test`, `--sh` and `--proc` must name standalone executables in root-owned paths whose ancestors cannot be written by other users; inline `--sh` shell command strings are refused. Evaluators run as an unprivileged identity with a clean environment. Scripts that depend on user-owned imports, local agents, or privileged access need a separately trusted setup; these restrictions do not apply to weak or non-root server mode.
- Linux strong mode requires trusted system helpers at `/usr/sbin/ip`, `/usr/sbin/nft`, and `/usr/bin/setpriv` (Docker mode also requires `/usr/bin/docker`); privileged setup and cleanup never search a payload-controlled `PATH`.
- Native Linux strong mode gives the payload a private PID namespace and `/proc` mount so it cannot import file descriptors from same-user host processes; `/usr/bin/unshare` is required.
- Newly created CA private keys and request logs use owner-only permissions on Unix. When Linux httpjail runs as root under sudo, request logs must be in a directory owned by the invoking user; new logs are assigned to that user, and existing logs must already belong to them (symlinks and protected host files are rejected). Existing log permissions remain unchanged; logs include full URLs, including query strings, so protect them accordingly.
- On Linux, strong-mode canaries and Docker public-certificate snapshots live under root-owned `/var/lib/httpjail` rather than sudo-preserved `HOME` or `TMPDIR`; its ancestors must not be writable by other users. Privileged Linux CA files likewise live under `/var/lib/httpjail/ca` instead of a sudo-preserved home directory; upgrading from a user-home CA generates a new root-only CA, so update client trust and remove trust in the old certificate.
- HTTP/1 request headers have a 10-second read deadline; request bodies and upgraded connections do not inherit that deadline.
- Docker mode requires the local daemon at `/var/run/docker.sock` (remote Docker contexts are ignored), mounts only that public-certificate snapshot (never the signing key), drops `NET_RAW`, and accepts only restricted `docker run` flags before the image (environment, user, working directory, resource limits, read-only/init, and `--rm`). Network, DNS, privileged, volume, port-publishing, and other unrecognized Docker flags are rejected. Arguments after the image are passed to the container unchanged.
- `sudo httpjail --cleanup` also removes legacy Docker nftables routing tables only when their Docker network, current/legacy canaries, and namespace config are absent; it leaves active-jail guards in place. Canaryless namespaces or legacy networks require manual administrator inspection rather than unsafe automatic deletion.

## Documentation

Docs are stored in the `docs/` directory and served
at [coder.github.io/httpjail](https://coder.github.io/httpjail).

Table of Contents:

- [Installation](https://coder.github.io/httpjail/guide/installation.html)
- [Quick Start](https://coder.github.io/httpjail/guide/quick-start.html)
- [Configuration](https://coder.github.io/httpjail/guide/configuration.html)
- [Rule Engines](https://coder.github.io/httpjail/guide/rule-engines/index.html)
  - [JavaScript](https://coder.github.io/httpjail/guide/rule-engines/javascript.html)
  - [Shell](https://coder.github.io/httpjail/guide/rule-engines/shell.html)
  - [Line Processor](https://coder.github.io/httpjail/guide/rule-engines/line-processor.html)
- [Platform Support](https://coder.github.io/httpjail/guide/platform-support.html)
- [Request Logging](https://coder.github.io/httpjail/guide/request-logging.html)
- [TLS Interception](https://coder.github.io/httpjail/advanced/tls-interception.html)
- [DNS Exfiltration](https://coder.github.io/httpjail/advanced/dns-exfiltration.html)
- [Server Mode](https://coder.github.io/httpjail/advanced/server-mode.html)

## License

This project is released into the public domain under the CC0 1.0 Universal license. See [LICENSE](LICENSE) for details.
