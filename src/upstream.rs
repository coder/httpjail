//! Forward httpjail's own re-originated requests through an upstream
//! (e.g. corporate) HTTP proxy.
//!
//! httpjail terminates the jailed process's traffic and then re-originates the
//! request towards the real destination. When httpjail itself has no direct
//! egress, that re-originated request must instead traverse an upstream proxy.
//!
//! This is implemented as a hyper *connector* ([`ProxyConnector`]) so that the
//! same high-level `hyper_util` `Client` used for direct egress can be reused
//! unchanged: connection pooling, request serialization and (for HTTPS) the
//! destination TLS handshake are all handled by hyper's own machinery. The
//! connector only decides how the underlying byte stream is obtained:
//!
//! * for `https://` destinations it issues a `CONNECT` to the proxy to obtain a
//!   raw TCP tunnel; the surrounding `hyper_rustls::HttpsConnector` then performs
//!   the destination TLS handshake over that tunnel, and
//! * for `http://` destinations it returns the proxy connection marked as
//!   proxied, so hyper emits the request in absolute-form for the proxy to
//!   forward.
//!
//! Following the streaming style used elsewhere in httpjail (see `proxy_tls.rs`)
//! every bounded read during setup is guarded by a timeout, while the
//! established tunnel itself is left unbounded so long-running connections
//! (WebSocket, gRPC, ...) keep working.

use anyhow::{Context as _, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use hyper::Uri;
use hyper::header::HeaderValue;
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::TokioIo;
use ipnet::IpNet;
use percent_encoding::percent_decode_str;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};
use tower_service::Service;
use tracing::debug;
use url::{Host, Url};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Timeout for establishing the tunnel through the upstream proxy (TCP connect
/// and the `CONNECT` exchange). This bounds setup only; the resulting tunnel
/// carries no timeout so long-running connections keep working.
const PROXY_SETUP_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound on the size of the upstream proxy's `CONNECT` response headers.
/// A well-behaved proxy answers with a short status line and a few headers.
const MAX_CONNECT_RESPONSE_BYTES: usize = 16 * 1024;

/// How much of the proxy's `CONNECT` response to ask for per read. Large enough
/// that a well-behaved proxy's whole response arrives in one read, small enough
/// that the bytes read past the headers stay a bounded prefix.
const CONNECT_READ_CHUNK_BYTES: usize = 1024;

/// The only `NO_PROXY` value that acts as a wildcard. Compared against the whole
/// list verbatim, as curl does, so `" * "` is not a wildcard.
const NO_PROXY_WILDCARD: &str = "*";

/// One parsed `NO_PROXY` entry.
///
/// The destination decides which variants can apply: an IP literal destination is
/// only ever compared against [`NoProxyRule::Ip`] and [`NoProxyRule::Net`], and a
/// host name only against [`NoProxyRule::Domain`]. Domain rules and address rules
/// never cross-match, matching curl.
#[derive(Clone, Debug)]
enum NoProxyRule {
    /// Label-boundary suffix match. Already ASCII-lowercased with one leading
    /// and one trailing dot removed.
    Domain(String),
    /// An entry without a prefix length: exact address match.
    Ip(IpAddr),
    /// An entry with a prefix length.
    Net(IpNet),
}

/// The parsed `NO_PROXY` bypass list.
///
/// Entries are parsed once at startup so that the request path only compares.
/// A wildcard list is not represented here: [`UpstreamProxies::from_specs`]
/// turns it into "no upstream proxy at all" before this type is built.
#[derive(Clone, Debug, Default)]
struct NoProxy {
    rules: Vec<NoProxyRule>,
}

impl NoProxy {
    /// Parse a `NO_PROXY` list.
    ///
    /// Entries are separated by commas; unlike curl, whitespace separates too.
    /// curl stops parsing the whole list at the first whitespace-separated
    /// token, silently discarding the remainder, which loses configuration
    /// without saying so.
    fn parse(spec: Option<&str>) -> Result<Self> {
        let Some(spec) = spec else {
            return Ok(Self::default());
        };

        let mut rules = Vec::new();
        let tokens = spec
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|token| !token.is_empty());
        for (index, token) in tokens.enumerate() {
            if let Some(rule) = parse_no_proxy_rule(index + 1, token)? {
                rules.push(rule);
            }
        }
        Ok(Self { rules })
    }

    /// Whether a host from [`Uri::host`] bypasses the proxy.
    fn matches(&self, host: &str) -> bool {
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        if let Ok(ip) = host.parse::<IpAddr>() {
            return self.rules.iter().any(|rule| match rule {
                NoProxyRule::Ip(entry) => *entry == ip,
                NoProxyRule::Net(entry) => entry.contains(&ip),
                NoProxyRule::Domain(_) => false,
            });
        }

        // A single trailing dot denotes the same name; ignore it as curl does.
        let host = host.strip_suffix('.').unwrap_or(host);
        self.rules.iter().any(|rule| match rule {
            NoProxyRule::Domain(entry) => domain_matches(entry, host),
            NoProxyRule::Ip(_) | NoProxyRule::Net(_) => false,
        })
    }
}

/// Parse one `NO_PROXY` entry. `Ok(None)` means the entry can never match and is
/// dropped; `Err` is a configuration error that aborts startup.
///
/// Neither the returned error nor any log line may contain the entry itself: a
/// `NO_PROXY` value can hold a mistakenly pasted proxy URL with credentials, and
/// `redact_proxy_spec` does not cover text after a slash. Only `index` and the
/// address that already parsed successfully are reported.
fn parse_no_proxy_rule(index: usize, token: &str) -> Result<Option<NoProxyRule>> {
    // Treat an entry as CIDR only when the part before the slash is an address.
    // A URL-shaped entry (`https://internal.corp`) then stays a domain entry
    // rather than failing the whole configuration, which would refuse to start
    // in environments where curl works.
    if let Some((addr, _)) = token.split_once('/')
        && let Ok(addr) = addr.parse::<IpAddr>()
    {
        let net = token
            .parse::<IpNet>()
            .map_err(|_| anyhow!("entry {} (\"{}/…\") is not a valid CIDR", index, addr))?;
        return Ok(Some(NoProxyRule::Net(net)));
    }

    if let Ok(addr) = token.parse::<IpAddr>() {
        return Ok(Some(NoProxyRule::Ip(addr)));
    }

    // One leading and one trailing dot are ignored, trailing first, as curl
    // does. An entry of "." or ".." therefore becomes empty and must be dropped:
    // an empty domain rule would suffix-match every host and bypass everything.
    let domain = token.strip_suffix('.').unwrap_or(token);
    let domain = domain.strip_prefix('.').unwrap_or(domain);
    if domain.is_empty() {
        return Ok(None);
    }

    // Host names contain neither of these, so such an entry cannot ever match.
    // Report the position only, never the value.
    for unmatchable in ['/', ':'] {
        if domain.contains(unmatchable) {
            debug!(
                "NO_PROXY entry {} contains '{}' and can never match a host name; ignoring",
                index, unmatchable
            );
            return Ok(None);
        }
    }

    Ok(Some(NoProxyRule::Domain(domain.to_ascii_lowercase())))
}

/// Whether `host` is `entry` itself or a subdomain of it.
///
/// `entry` is already lowercased; `host` is compared case-insensitively. The
/// character before a suffix match must be a dot, so `example.com` matches
/// `www.example.com` but not `notexample.com`. Comparison is on bytes to avoid
/// slicing a multi-byte character.
fn domain_matches(entry: &str, host: &str) -> bool {
    let (entry, host) = (entry.as_bytes(), host.as_bytes());
    let Some(offset) = host.len().checked_sub(entry.len()) else {
        return false;
    };
    if !host[offset..].eq_ignore_ascii_case(entry) {
        return false;
    }
    offset == 0 || host[offset - 1] == b'.'
}

/// Parsed configuration for an upstream proxy.
#[derive(Clone, Debug)]
pub struct UpstreamProxy {
    /// Proxy host (DNS name or IP literal) to dial.
    host: String,
    /// Proxy port.
    port: u16,
    /// Pre-built `Proxy-Authorization` header value when credentials are given.
    auth: Option<HeaderValue>,
}

/// Upstream proxy configuration resolved from the proxy environment.
#[derive(Clone, Debug)]
pub struct UpstreamProxies {
    http: Option<UpstreamProxy>,
    https: Option<UpstreamProxy>,
    no_proxy: NoProxy,
}

impl UpstreamProxies {
    /// Resolve httpjail's own egress proxy settings from the proxy environment.
    pub fn from_env() -> Result<Option<Self>> {
        let (no_proxy, no_proxy_lower) = (env_var("NO_PROXY"), env_var("no_proxy"));
        let (http, http_lower) = (env_var("HTTP_PROXY"), env_var("http_proxy"));
        let (https, https_lower) = (env_var("HTTPS_PROXY"), env_var("https_proxy"));

        Self::from_specs(
            first_set(http.as_deref(), http_lower.as_deref()),
            first_set(https.as_deref(), https_lower.as_deref()),
            first_set(no_proxy.as_deref(), no_proxy_lower.as_deref()),
        )
    }

    /// Resolve the configuration from already-selected values.
    ///
    /// The order of the steps below is deliberate: an input is never parsed
    /// unless its value can actually affect the outcome. Parsing eagerly would
    /// turn an irrelevant leftover variable into a startup failure.
    fn from_specs(
        http: Option<&str>,
        https: Option<&str>,
        no_proxy: Option<&str>,
    ) -> Result<Option<Self>> {
        // A bare `*` disables proxying outright, so the proxy URLs are never
        // used and must not be validated.
        if no_proxy == Some(NO_PROXY_WILDCARD) {
            debug!("NO_PROXY is '*': contacting all destinations directly");
            return Ok(None);
        }

        let http = parse_optional_proxy_spec("HTTP_PROXY", http)?;
        let https = parse_optional_proxy_spec("HTTPS_PROXY", https)?;

        // Without a proxy there is nothing to bypass, so the bypass list is
        // irrelevant and is left unparsed.
        if http.is_none() && https.is_none() {
            return Ok(None);
        }

        Ok(Some(Self {
            http,
            https,
            no_proxy: NoProxy::parse(no_proxy).context("Failed to parse NO_PROXY")?,
        }))
    }

    /// The proxy to use for `uri`, or `None` when the destination is contacted
    /// directly (no proxy for that scheme, or the destination is bypassed).
    fn proxy_for_uri(&self, uri: &Uri) -> Option<&UpstreamProxy> {
        let proxy = match uri.scheme_str() {
            Some("http") => self.http.as_ref(),
            Some("https") => self.https.as_ref(),
            _ => None,
        }?;

        if let Some(host) = uri.host()
            && self.no_proxy.matches(host)
        {
            debug!("Bypassing upstream proxy for {}", host);
            return None;
        }

        Some(proxy)
    }

    /// The `Proxy-Authorization` value to attach to a request that is forwarded
    /// to the proxy in absolute-form.
    ///
    /// `None` for HTTPS destinations: those travel inside a `CONNECT` tunnel to
    /// the origin server, so a header added here would deliver the proxy's
    /// credentials to the destination site itself. The tunnel's own credentials
    /// are written by [`establish_connect_tunnel`].
    ///
    /// `None` for destinations that bypass the proxy, which would otherwise hand
    /// the credentials to an arbitrary internal host.
    pub(crate) fn http_auth_for_uri(&self, uri: &Uri) -> Option<HeaderValue> {
        if uri.scheme_str() != Some("http") {
            return None;
        }
        self.proxy_for_uri(uri).and_then(UpstreamProxy::http_auth)
    }

    /// Route every scheme through one proxy, with no bypass list. Only the
    /// tests build a configuration this way; `from_specs` is the real entry
    /// point.
    #[cfg(test)]
    pub(crate) fn all(proxy: UpstreamProxy) -> Self {
        Self {
            http: Some(proxy.clone()),
            https: Some(proxy),
            no_proxy: NoProxy::default(),
        }
    }
}

fn env_var(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// The first of the two values that is actually set, using the uppercase-first
/// precedence httpjail applies to every proxy environment variable.
///
/// A value counts as unset when it is empty or contains only whitespace, so
/// `NO_PROXY="   " no_proxy=example.com` falls through to the lowercase
/// spelling. curl treats only a truly empty value as absent; this is a
/// documented divergence (see docs/advanced/upstream-proxy.md).
///
/// The value is returned verbatim. Callers compare it against a literal (the
/// strict `*` check), so trimming here would change what they see.
fn first_set<'a>(primary: Option<&'a str>, fallback: Option<&'a str>) -> Option<&'a str> {
    [primary, fallback]
        .into_iter()
        .flatten()
        .find(|value| !value.trim().is_empty())
}

fn parse_optional_proxy_spec(name: &str, spec: Option<&str>) -> Result<Option<UpstreamProxy>> {
    let Some(spec) = spec.map(str::trim).filter(|spec| !spec.is_empty()) else {
        return Ok(None);
    };
    UpstreamProxy::parse(spec)
        .map(Some)
        .with_context(|| format!("Failed to parse {name}"))
}

impl UpstreamProxy {
    /// Parse an upstream proxy specification such as `http://proxy.corp:3128`,
    /// `http://user:pass@proxy.corp:3128` or a bare `proxy.corp:3128` (the
    /// `http` scheme is then assumed).
    ///
    /// Reaching the proxy itself over TLS (an `https://` proxy URL) is not
    /// supported; HTTPS *destinations* are tunneled through a plain HTTP proxy
    /// with `CONNECT`.
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() {
            bail!("Upstream proxy specification is empty");
        }
        let redacted_spec = redact_proxy_spec(spec);
        let normalized = if spec.contains("://") {
            spec.to_string()
        } else {
            format!("http://{spec}")
        };

        let url = Url::parse(&normalized)
            .with_context(|| format!("Invalid upstream proxy URL: {}", redacted_spec))?;

        match url.scheme() {
            "http" => {}
            "https" => bail!(
                "Connecting to an upstream proxy over TLS is not supported: {}. \
                 Use an 'http://' proxy URL; HTTPS destinations are still \
                 tunneled through it with CONNECT.",
                redacted_spec
            ),
            other => bail!(
                "Unsupported upstream proxy scheme '{}': {}",
                other,
                redacted_spec
            ),
        }

        let host = match url.host() {
            Some(Host::Domain(host)) => host.to_string(),
            Some(Host::Ipv4(host)) => host.to_string(),
            Some(Host::Ipv6(host)) => host.to_string(),
            None => bail!("Invalid upstream proxy authority: {}", redacted_spec),
        };

        let port = url
            .port_or_known_default()
            .ok_or_else(|| anyhow!("Invalid upstream proxy authority: {}", redacted_spec))?;

        let auth = if !url.username().is_empty() || url.password().is_some() {
            Some(build_basic_auth(url.username(), url.password())?)
        } else {
            None
        };

        Ok(UpstreamProxy { host, port, auth })
    }

    /// The `Proxy-Authorization` header value, if credentials were supplied.
    ///
    /// Needed by the plain-HTTP forwarding path, where the header travels on the
    /// forwarded request itself rather than on a `CONNECT`.
    pub fn http_auth(&self) -> Option<HeaderValue> {
        self.auth.clone()
    }
}

/// Redact userinfo from a proxy URL-like string before it is logged or included
/// in an error message.
pub fn redact_proxy_spec(spec: &str) -> String {
    let spec = spec.trim();
    let (prefix, rest) = match spec.split_once("://") {
        Some((scheme, rest)) => (format!("{scheme}://"), rest),
        None => (String::new(), spec),
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, suffix) = rest.split_at(authority_end);
    let Some((_, host_port)) = authority.rsplit_once('@') else {
        return spec.to_string();
    };
    format!("{prefix}<redacted>@{host_port}{suffix}")
}

/// Build a `Proxy-Authorization: Basic ...` header value from `user:pass`
/// userinfo, percent-decoding each component first.
fn build_basic_auth(user: &str, pass: Option<&str>) -> Result<HeaderValue> {
    let user = percent_decode_str(user).decode_utf8_lossy();
    let pass = percent_decode_str(pass.unwrap_or("")).decode_utf8_lossy();
    let token = STANDARD.encode(format!("{user}:{pass}"));
    let mut value = HeaderValue::from_str(&format!("Basic {}", token))
        .context("Invalid characters in upstream proxy credentials")?;
    value.set_sensitive(true);
    Ok(value)
}

/// A hyper connector that routes outbound connections through an
/// [`UpstreamProxy`].
///
/// It is intended to be used as the inner connector of a
/// `hyper_rustls::HttpsConnector`: this connector yields a raw byte stream (the
/// proxy connection for HTTP, or a `CONNECT` tunnel for HTTPS) and the
/// surrounding HTTPS connector layers the destination TLS on top when needed.
#[derive(Clone)]
pub struct ProxyConnector {
    /// Used solely to dial the proxy's `host:port` (never the destination).
    http: HttpConnector,
    proxies: Arc<UpstreamProxies>,
}

impl ProxyConnector {
    pub(crate) fn with_config(proxies: UpstreamProxies) -> Self {
        let mut http = HttpConnector::new();
        // The proxy is addressed via an http(s) URL; allow non-http schemes so
        // the connector does not reject the dial target.
        http.enforce_http(false);
        http.set_happy_eyeballs_timeout(Some(Duration::from_millis(250)));
        ProxyConnector {
            http,
            proxies: Arc::new(proxies),
        }
    }
}

impl Service<Uri> for ProxyConnector {
    type Response = ProxyStream;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<ProxyStream, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.http.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let mut http = self.http.clone();
        let proxy = self.proxies.proxy_for_uri(&dst).cloned();

        Box::pin(async move {
            let Some(proxy) = proxy else {
                let tcp = match timeout(PROXY_SETUP_TIMEOUT, http.call(dst.clone())).await {
                    Ok(result) => result?.into_inner(),
                    Err(_) => return Err(timed_out("connecting directly to destination")),
                };
                let _ = tcp.set_nodelay(true);
                return Ok(ProxyStream::new(tcp, Bytes::new(), false));
            };

            // Dial the proxy (TCP). The destination scheme is irrelevant here;
            // we always connect to the proxy's host:port.
            let proxy_uri: Uri =
                format!("http://{}", host_port_authority(&proxy.host, proxy.port)).parse()?;
            let mut stream = match timeout(PROXY_SETUP_TIMEOUT, http.call(proxy_uri)).await {
                Ok(result) => result?.into_inner(),
                Err(_) => return Err(timed_out("connecting to upstream proxy")),
            };
            let _ = stream.set_nodelay(true);

            let (prefetched, proxied) = if dst.scheme_str() == Some("https") {
                let host = dst.host().ok_or_else(|| {
                    BoxError::from(format!("CONNECT target has no host: {}", dst))
                })?;
                let port = dst.port_u16().unwrap_or(443);
                let prefetched =
                    establish_connect_tunnel(&mut stream, host, port, proxy.auth.as_ref())
                        .await
                        .map_err(|e| -> BoxError { e.into() })?;
                // The tunnel is transparent end-to-end; destination TLS is
                // layered on top by the surrounding HttpsConnector and the
                // request is sent in origin-form, so do not mark it proxied.
                (prefetched, false)
            } else {
                // Plain HTTP: the proxy forwards absolute-form requests. Mark the
                // connection proxied so hyper emits absolute-form request lines.
                (Bytes::new(), true)
            };

            Ok(ProxyStream::new(stream, prefetched, proxied))
        })
    }
}

/// Build a timeout error for the upstream proxy setup phase.
fn timed_out(phase: &str) -> BoxError {
    format!("Timeout {} with upstream proxy", phase).into()
}

/// The connector's response: a byte stream plus the proxied flag that hyper
/// consults to decide between absolute-form and origin-form request lines.
pub struct ProxyStream {
    io: TokioIo<TcpStream>,
    /// Tunnel bytes read ahead of time while consuming the `CONNECT` response.
    /// Replayed before anything is taken from the socket so the byte order the
    /// destination TLS handshake sees is unchanged.
    prefetched: Bytes,
    proxied: bool,
}

impl ProxyStream {
    fn new(io: TcpStream, prefetched: Bytes, proxied: bool) -> Self {
        ProxyStream {
            io: TokioIo::new(io),
            prefetched,
            proxied,
        }
    }
}

impl Connection for ProxyStream {
    fn connected(&self) -> Connected {
        Connected::new().proxy(self.proxied)
    }
}

impl Read for ProxyStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Drain the read-ahead first, and return without touching the socket
        // while any of it remains. Mixing the two in one poll would reorder the
        // stream.
        if !this.prefetched.is_empty() {
            let take = this.prefetched.len().min(buf.remaining());
            buf.put_slice(&this.prefetched[..take]);
            this.prefetched.advance(take);
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut this.io).poll_read(cx, buf)
    }
}

impl Write for ProxyStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write_vectored(cx, bufs)
    }
}

/// Send a `CONNECT` request to the upstream proxy and validate its response.
///
/// Returns any tunnel bytes that arrived in the same read as the end of the
/// response headers. Those bytes belong to the tunnel and must be replayed
/// before anything further is read from `stream`; see [`ProxyStream`].
async fn establish_connect_tunnel<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    auth: Option<&HeaderValue>,
) -> Result<Bytes>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Bracket IPv6 literals in the request-target and Host header.
    let target = host_port_authority(host, port);

    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(value) = auth {
        let value = value
            .to_str()
            .context("Proxy-Authorization contains non-ASCII bytes")?;
        request.push_str("Proxy-Authorization: ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");

    match timeout(PROXY_SETUP_TIMEOUT, stream.write_all(request.as_bytes())).await {
        Ok(result) => result.context("Failed to write CONNECT request")?,
        Err(_) => bail!("Timeout writing CONNECT request to upstream proxy"),
    }
    match timeout(PROXY_SETUP_TIMEOUT, stream.flush()).await {
        Ok(result) => result.context("Failed to flush CONNECT request")?,
        Err(_) => bail!("Timeout flushing CONNECT request to upstream proxy"),
    }

    // One timeout for the whole exchange rather than one per read: a proxy that
    // dribbles the response out a byte at a time would otherwise never trip a
    // per-read deadline and could hold the setup open indefinitely.
    let response = match timeout(PROXY_SETUP_TIMEOUT, read_connect_response(stream)).await {
        Ok(result) => result?,
        Err(_) => bail!("Timeout reading CONNECT response from upstream proxy"),
    };

    if !(200..300).contains(&response.status) {
        bail!(
            "Upstream proxy refused CONNECT to {}:{} with status {}",
            host,
            port,
            response.status
        );
    }

    debug!(
        "Established CONNECT tunnel to {}:{} via upstream proxy ({} byte(s) of tunnel data already read)",
        host,
        port,
        response.prefetched.len()
    );
    Ok(response.prefetched)
}

/// Format a host and port for use as an HTTP authority, bracketing IPv6
/// literals as required by URI syntax.
fn host_port_authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// The proxy's answer to `CONNECT`, plus whatever came after it.
struct ConnectResponse {
    status: u16,
    /// Tunnel bytes that arrived in the same read as the end of the headers.
    /// Reading in chunks means the response and the first tunnel data can land
    /// together; discarding the remainder would corrupt the TLS handshake that
    /// follows.
    prefetched: Bytes,
}

/// Read the proxy's `CONNECT` response up to the end of its headers.
///
/// Reads in chunks of [`CONNECT_READ_CHUNK_BYTES`] rather than a byte at a time,
/// and hands back the bytes that overshot the headers instead of dropping them.
/// The headers themselves are capped at [`MAX_CONNECT_RESPONSE_BYTES`], so memory
/// stays within that plus one chunk.
async fn read_connect_response<S>(stream: &mut S) -> Result<ConnectResponse>
where
    S: AsyncRead + Unpin,
{
    const TERMINATOR: &[u8] = b"\r\n\r\n";

    let mut buf = BytesMut::with_capacity(CONNECT_READ_CHUNK_BYTES);
    let header_end = loop {
        let filled = buf.len();

        // `BytesMut` reports nearly unbounded space, so cap each read explicitly
        // rather than letting it size the read for us.
        let mut chunk = (&mut buf).limit(CONNECT_READ_CHUNK_BYTES);
        if stream.read_buf(&mut chunk).await? == 0 {
            bail!("Upstream proxy closed connection during CONNECT");
        }

        // A terminator can straddle two reads, so rescan the last three bytes of
        // what was already there instead of only the newly added bytes.
        let search_from = filled.saturating_sub(TERMINATOR.len() - 1);
        if let Some(offset) = find_subslice(&buf[search_from..], TERMINATOR) {
            break search_from + offset + TERMINATOR.len();
        }

        // Only reached with no terminator in hand: everything read so far is
        // header, so the cap applies to all of it.
        if buf.len() >= MAX_CONNECT_RESPONSE_BYTES {
            bail!("Upstream proxy CONNECT response exceeded size limit");
        }
    };

    // Checked after the terminator is located, not before: a single read may
    // carry headers within the cap plus tunnel data that pushes the total over
    // it, and that case is a success.
    if header_end > MAX_CONNECT_RESPONSE_BYTES {
        bail!("Upstream proxy CONNECT response exceeded size limit");
    }

    let prefetched = buf.split_off(header_end).freeze();

    // Only the headers are text. The tunnel bytes are arbitrary binary (a TLS
    // ClientHello, typically) and must never be run through a UTF-8 check.
    let head = std::str::from_utf8(&buf).context("Non-UTF8 CONNECT response")?;
    let first_line = head.lines().next().unwrap_or("");
    let status = first_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| anyhow!("Malformed CONNECT status line: {:?}", first_line))?;

    Ok(ConnectResponse { status, prefetched })
}

/// Index of the first occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_proxy() {
        let p = UpstreamProxy::parse("http://proxy.corp:3128").unwrap();
        assert_eq!(p.host, "proxy.corp");
        assert_eq!(p.port, 3128);
        assert!(p.auth.is_none());
    }

    #[test]
    fn parse_proxy_ignores_path_query_and_fragment() {
        let p = UpstreamProxy::parse("http://proxy.corp:3128/path?ignored=true#frag").unwrap();
        assert_eq!(p.host, "proxy.corp");
        assert_eq!(p.port, 3128);
    }

    #[test]
    fn parse_bare_hostport_defaults_to_http() {
        let p = UpstreamProxy::parse("proxy.corp:8080").unwrap();
        assert_eq!(p.host, "proxy.corp");
        assert_eq!(p.port, 8080);
    }

    /// Reaching the proxy itself over TLS is not supported; the error must say
    /// so rather than silently treating the proxy as plain HTTP.
    #[test]
    fn reject_tls_proxy_scheme() {
        let err = UpstreamProxy::parse("https://proxy.corp:8443").unwrap_err();
        assert!(
            err.to_string().contains("over TLS is not supported"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn parse_ipv6_literal_with_port() {
        let p = UpstreamProxy::parse("http://[::1]:3128").unwrap();
        assert_eq!(p.host, "::1");
        assert_eq!(p.port, 3128);
    }

    #[test]
    fn host_port_authority_brackets_ipv6_literal() {
        assert_eq!(host_port_authority("::1", 3128), "[::1]:3128");
        assert_eq!(host_port_authority("proxy.corp", 3128), "proxy.corp:3128");
    }

    #[test]
    fn parse_proxy_with_credentials() {
        let p = UpstreamProxy::parse("http://alice:s3cr3t@proxy.corp:3128").unwrap();
        // base64("alice:s3cr3t")
        assert_eq!(p.auth.unwrap().to_str().unwrap(), "Basic YWxpY2U6czNjcjN0");
    }

    #[test]
    fn parse_credentials_are_percent_decoded() {
        // "p@ss:word" encoded in the userinfo.
        let p = UpstreamProxy::parse("http://user:p%40ss%3Aword@proxy.corp:3128").unwrap();
        assert_eq!(
            p.auth.unwrap().to_str().unwrap(),
            "Basic dXNlcjpwQHNzOndvcmQ="
        );
    }

    #[test]
    fn proxy_credentials_are_sensitive() {
        let p = UpstreamProxy::parse("http://user:secret@proxy.corp:3128").unwrap();
        assert!(p.auth.as_ref().unwrap().is_sensitive());
        assert!(!format!("{p:?}").contains("dXNlcjpzZWNyZXQ="));
    }

    #[test]
    fn redact_proxy_spec_removes_userinfo() {
        assert_eq!(
            redact_proxy_spec("http://user:secret@proxy.corp:3128/path"),
            "http://<redacted>@proxy.corp:3128/path"
        );
        assert_eq!(
            redact_proxy_spec("user:secret@proxy.corp:3128"),
            "<redacted>@proxy.corp:3128"
        );
        assert_eq!(
            redact_proxy_spec("http://proxy.corp:3128"),
            "http://proxy.corp:3128"
        );
    }

    #[test]
    fn reject_unknown_scheme() {
        assert!(UpstreamProxy::parse("ftp://proxy.corp:21").is_err());
    }

    #[test]
    fn reject_empty_spec() {
        assert!(UpstreamProxy::parse("   ").is_err());
    }

    #[test]
    fn proxy_config_uses_specs_by_scheme() {
        let proxies = UpstreamProxies::from_specs(
            Some("http://http-proxy.corp:3128"),
            Some("http://https-proxy.corp:8443"),
            None,
        )
        .unwrap()
        .unwrap();

        let http_uri: Uri = "http://example.com/".parse().unwrap();
        let https_uri: Uri = "https://example.com/".parse().unwrap();

        assert_eq!(
            proxies
                .proxy_for_uri(&http_uri)
                .map(|proxy| proxy.host.as_str()),
            Some("http-proxy.corp")
        );
        assert_eq!(
            proxies
                .proxy_for_uri(&https_uri)
                .map(|proxy| proxy.host.as_str()),
            Some("https-proxy.corp")
        );
    }

    #[test]
    fn proxy_config_ignores_empty_specs() {
        let proxies = UpstreamProxies::from_specs(Some("  "), None, None).unwrap();
        assert!(proxies.is_none());
    }

    fn proxies_with_no_proxy(no_proxy: &str) -> UpstreamProxies {
        UpstreamProxies::from_specs(
            Some("http://user:pass@proxy.corp:3128"),
            Some("http://proxy.corp:3128"),
            Some(no_proxy),
        )
        .unwrap()
        .unwrap()
    }

    #[test]
    fn no_proxy_bypasses_matching_destinations() {
        let cases = [
            ("example.com", "http://example.com/", true),
            ("example.com", "http://www.example.com/", true),
            ("example.com", "http://notexample.com/", false),
            ("EXAMPLE.COM", "http://ExAmPlE.cOm/", true),
            ("192.168.0.0/16", "http://192.168.4.5/", true),
            ("192.168.0.0/16", "http://192.169.4.5/", false),
            ("192.168.1.1", "http://192.168.1.1/", true),
            ("192.168.1.1", "http://192.168.1.2/", false),
            ("2001:db8::/32", "http://[2001:db8::1]/", true),
            ("2001:db8::/32", "http://[2001:db9::1]/", false),
            ("example.com", "https://example.com/", true),
        ];

        for (no_proxy, destination, bypassed) in cases {
            let proxies = proxies_with_no_proxy(no_proxy);
            let uri: Uri = destination.parse().unwrap();
            assert_eq!(
                proxies.proxy_for_uri(&uri).is_none(),
                bypassed,
                "NO_PROXY={no_proxy:?} destination={destination}"
            );
        }

        assert!(
            UpstreamProxies::from_specs(
                Some("http://proxy.corp:3128"),
                Some("http://proxy.corp:3128"),
                Some("*"),
            )
            .unwrap()
            .is_none()
        );
    }

    /// `Proxy-Authorization` must never leave the proxy it belongs to. Expected
    /// values are written out rather than derived, so a wrong rule in
    /// `http_auth_for_uri` cannot make the test agree with it.
    #[test]
    fn proxy_auth_only_for_proxied_http_destinations() {
        let proxies = proxies_with_no_proxy("internal.corp");

        // Forwarded in absolute-form to the proxy: the header belongs here.
        assert!(
            proxies
                .http_auth_for_uri(&"http://proxied.example/".parse().unwrap())
                .is_some()
        );
        // Connected to directly: the proxy's credentials must not be sent.
        assert!(
            proxies
                .http_auth_for_uri(&"http://internal.corp/".parse().unwrap())
                .is_none()
        );
        // Sent inside a CONNECT tunnel, i.e. to the origin server itself.
        assert!(
            proxies
                .http_auth_for_uri(&"https://proxied.example/".parse().unwrap())
                .is_none()
        );
        assert!(
            proxies
                .http_auth_for_uri(&"https://internal.corp/".parse().unwrap())
                .is_none()
        );
    }

    /// The uppercase spelling wins, and the value survives untouched. Shared by
    /// every proxy variable, so this fixes the precedence for all of them.
    #[test]
    fn uppercase_env_spelling_wins() {
        assert_eq!(first_set(Some("upper"), Some("lower")), Some("upper"));
        assert_eq!(first_set(None, Some("lower")), Some("lower"));
        assert_eq!(first_set(Some(""), Some("lower")), Some("lower"));
        // Unlike curl, a whitespace-only value does not shadow the other spelling.
        assert_eq!(first_set(Some("   "), Some("lower")), Some("lower"));
        assert_eq!(first_set(None, None), None);
        assert_eq!(first_set(Some(""), Some("  ")), None);
        // Returned verbatim: trimming here would turn `" * "` into a wildcard.
        assert_eq!(first_set(Some(" * "), None), Some(" * "));
    }

    /// Drive the proxy side of an in-memory duplex: read request headers up to
    /// the blank line, then reply with `response`. Returns the request text.
    async fn fake_proxy(mut end: tokio::io::DuplexStream, response: &'static [u8]) -> String {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = end.read(&mut byte).await.unwrap();
            if n == 0 {
                break;
            }
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        end.write_all(response).await.unwrap();
        end.flush().await.unwrap();
        String::from_utf8_lossy(&buf).into_owned()
    }

    #[tokio::test]
    async fn connect_tunnel_sends_request_and_accepts_2xx() {
        let (mut client_end, proxy_end) = tokio::io::duplex(1024);
        let proxy = tokio::spawn(fake_proxy(
            proxy_end,
            b"HTTP/1.1 200 Connection established\r\n\r\n",
        ));

        let auth = HeaderValue::from_static("Basic dXNlcjpwYXNz");
        establish_connect_tunnel(&mut client_end, "example.com", 443, Some(&auth))
            .await
            .unwrap();

        let request = proxy.await.unwrap();
        assert!(request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
        assert!(request.contains("Host: example.com:443\r\n"));
        assert!(request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
    }

    #[tokio::test]
    async fn connect_tunnel_brackets_ipv6_literal() {
        let (mut client_end, proxy_end) = tokio::io::duplex(1024);
        let proxy = tokio::spawn(fake_proxy(
            proxy_end,
            b"HTTP/1.1 200 Connection established\r\n\r\n",
        ));

        establish_connect_tunnel(&mut client_end, "::1", 443, None)
            .await
            .unwrap();

        let request = proxy.await.unwrap();
        assert!(request.starts_with("CONNECT [::1]:443 HTTP/1.1\r\n"));
    }

    /// Reading in chunks can pull tunnel data in with the response headers. Those
    /// bytes belong to the TLS handshake that follows and must survive intact,
    /// including bytes that are not valid UTF-8.
    #[tokio::test]
    async fn connect_tunnel_returns_bytes_read_past_the_headers() {
        const TUNNEL: &[u8] = &[0x16, 0x03, 0x01, 0x00, 0xff, 0x00, 0x80];

        let (mut client_end, mut proxy_end) = tokio::io::duplex(1024);
        let proxy = tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            while proxy_end.read(&mut byte).await.unwrap() != 0 {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            // Headers and tunnel data in a single write, so they arrive together.
            let mut response = b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec();
            response.extend_from_slice(TUNNEL);
            proxy_end.write_all(&response).await.unwrap();
            proxy_end.flush().await.unwrap();
        });

        let prefetched = establish_connect_tunnel(&mut client_end, "example.com", 443, None)
            .await
            .unwrap();

        assert_eq!(prefetched.as_ref(), TUNNEL);
        proxy.await.unwrap();
    }

    /// The read-ahead has to come out before anything from the socket, and has to
    /// survive being read in pieces smaller than itself.
    #[tokio::test]
    async fn proxy_stream_replays_prefetched_bytes_before_socket_bytes() {
        use tokio::io::AsyncReadExt as _;

        const PREFIX: &[u8] = b"prefetched-";
        const BODY: &[u8] = b"from-socket";

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(BODY).await.unwrap();
            sock.flush().await.unwrap();
        });

        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let stream = ProxyStream::new(client, Bytes::from_static(PREFIX), false);
        let mut io = TokioIo::new(stream);

        // Deliberately smaller than the prefix so the replay spans several reads.
        let mut got = Vec::new();
        let mut chunk = [0u8; 4];
        while got.len() < PREFIX.len() + BODY.len() {
            let n = io.read(&mut chunk).await.unwrap();
            assert_ne!(n, 0, "stream ended early: {:?}", got);
            got.extend_from_slice(&chunk[..n]);
        }

        assert_eq!(got, [PREFIX, BODY].concat());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn connect_tunnel_rejects_non_2xx() {
        let (mut client_end, proxy_end) = tokio::io::duplex(1024);
        tokio::spawn(fake_proxy(proxy_end, b"HTTP/1.1 403 Forbidden\r\n\r\n"));

        let err = establish_connect_tunnel(&mut client_end, "blocked.test", 443, None)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("403"), "unexpected error: {}", err);
    }
}
