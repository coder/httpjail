# Upstream Proxy

By default httpjail contacts destination servers directly. When httpjail itself
runs in an environment that has no direct internet access — for example behind a
corporate proxy — you can route httpjail's own outbound requests through an
upstream proxy with the `HTTP_PROXY` and/or `HTTPS_PROXY` environment variables.

Rule evaluation still happens locally on the intercepted traffic. Only the
request that httpjail re-originates towards the real destination is forwarded
through the upstream proxy.

```bash
# Route httpjail's HTTPS egress through a corporate proxy
HTTPS_PROXY=http://proxy.corp:3128 httpjail --js "true" -- curl https://api.github.com

# Route both HTTP and HTTPS egress through the same proxy
HTTP_PROXY=http://proxy.corp:3128 HTTPS_PROXY=http://proxy.corp:3128 \
  httpjail --js "true" -- ./my-app

# With Basic authentication
HTTPS_PROXY=http://user:pass@proxy.corp:3128 httpjail --js "true" -- ./my-app
```

## Accepted formats

| Form | Example | Notes |
| --- | --- | --- |
| `http://host:port` | `http://proxy.corp:3128` | Plain HTTP proxy |
| `host:port` | `proxy.corp:3128` | Bare authority, `http` scheme assumed |
| With credentials | `http://user:pass@proxy.corp:3128` | Sends `Proxy-Authorization: Basic ...` |

`HTTP_PROXY` is used for `http://` destinations. `HTTPS_PROXY` is used for
`https://` destinations. Credentials are never written to the logs.

Note that the value describes how httpjail reaches the proxy, not the scheme of
the destinations it covers: `HTTPS_PROXY=http://proxy.corp:3128` is the normal
configuration and sends HTTPS destinations through a plain HTTP proxy. Reaching
the proxy itself over TLS (an `https://` proxy URL) is not supported and is
rejected with an error.

## Bypassing the proxy with `NO_PROXY`

`NO_PROXY` is a comma-separated list of destinations that httpjail contacts
directly instead of through the upstream proxy.

| Form | Example | Notes |
| --- | --- | --- |
| Domain | `example.com` | Matches the domain and its subdomains |
| Address | `192.168.1.1` | Exact IP address match |
| IPv4 CIDR | `192.168.0.0/16` | Matches IP-literal destinations in the network |
| IPv6 CIDR | `2001:db8::/32` | Matches IP-literal destinations in the network |
| Wildcard | `*` | Disables upstream proxying when it is the whole value |

Domain matching is case-insensitive. CIDR entries apply only when the
destination is written as an IP literal; host names are not resolved for
matching. A bypassed request is still checked against httpjail's rules:
`NO_PROXY` only changes how an allowed request reaches its destination.

The lowercase `no_proxy` spelling is also accepted when `NO_PROXY` is unset.

## How it works

- **HTTPS destinations** are reached by issuing a `CONNECT` to the upstream
  proxy to obtain a raw TCP tunnel; httpjail then performs the destination TLS
  handshake over that tunnel. TLS is validated against Mozilla's webpki roots
  plus the httpjail CA, exactly as for a direct connection.
- **Plain HTTP destinations** are forwarded to the proxy in absolute-form, with
  the `Proxy-Authorization` header attached when credentials are configured. The
  header is never sent to a destination that `NO_PROXY` bypasses, nor to an HTTPS
  destination, whose request travels inside the tunnel to the origin server.
- Only connection setup (the TCP connect and the `CONNECT` exchange) is bounded
  by a timeout. The established tunnel carries no timeout, so long-running
  connections such as WebSocket and gRPC keep working.

## Relationship to jailed process proxy variables

The proxy environment variables configure httpjail's own egress. In weak mode,
httpjail overwrites `HTTP_PROXY` and `HTTPS_PROXY` inside the jailed process to
point sandboxed processes at httpjail itself.

```
[ jailed process ] --> [ httpjail ] --HTTP_PROXY/HTTPS_PROXY--> [ corporate proxy ] --> internet
```

The jailed process talks to httpjail; the proxy env vars only affect the hop
from httpjail to the outside world.

None of the parent's proxy variables are passed on to the jailed process, in any
mode. `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` are removed so the process
cannot reach the upstream proxy directly or read its credentials, and `NO_PROXY`
is replaced with the local addresses only. Inheriting `NO_PROXY` would let the
process connect straight to every destination it named, with no rule evaluation
at all. In weak mode httpjail then sets the proxy variables to its own address.
