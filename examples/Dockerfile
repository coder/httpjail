FROM debian:13-slim

LABEL org.opencontainers.image.title="httpjail" \
      org.opencontainers.image.description="HTTP/HTTPS proxy with JavaScript-based request filtering" \
      org.opencontainers.image.version="0.6.0" \
      org.opencontainers.image.source="https://github.com/coder/httpjail" \
      org.opencontainers.image.licenses="CC0-1.0"

# Install CA certificates for TLS connections
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates wget && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -u 1000 -m -s /bin/bash httpjail

# Download and install httpjail binary from GitHub releases
# Supports multi-arch builds (amd64 and arm64)
ARG TARGETARCH
RUN set -ex; \
    case "${TARGETARCH}" in \
        amd64) HTTPJAIL_ARCH="x86_64" ;; \
        arm64) HTTPJAIL_ARCH="aarch64" ;; \
        *) echo "Unsupported architecture: ${TARGETARCH}" && exit 1 ;; \
    esac; \
    wget -q https://github.com/coder/httpjail/releases/download/v0.5.1/httpjail-0.5.1-linux-${HTTPJAIL_ARCH}.tar.gz && \
    tar -xzf httpjail-0.5.1-linux-${HTTPJAIL_ARCH}.tar.gz && \
    mv httpjail-0.5.1-linux-${HTTPJAIL_ARCH}/httpjail /usr/local/bin/httpjail && \
    chmod +x /usr/local/bin/httpjail && \
    rm -rf httpjail-0.5.1-linux-${HTTPJAIL_ARCH}.tar.gz httpjail-0.5.1-linux-${HTTPJAIL_ARCH}

# Create directory for rules
RUN mkdir -p /rules && \
    chown -R httpjail:httpjail /rules

# Create default allow-all rule example
# This can be overridden by bind-mounting a custom rule file
RUN echo '// Default allow-all rule\n\
// The request object (r) has these properties:\n\
//   r.url    - Full URL\n\
//   r.method - HTTP method (GET, POST, etc.)\n\
//   r.host   - Hostname\n\
//   r.scheme - URL scheme (http/https)\n\
//   r.path   - URL path\n\
//\n\
// Return true to allow, false to deny\n\
// Or return {allow: false, deny_message: "Custom message"}\n\
// Or return {allow: {max_tx_bytes: 1024}} for size limits\n\
\n\
(function() {\n\
  // Your custom rules here\n\
  return true;\n\
})();\n\
' > /rules/rules.js && \
    chown httpjail:httpjail /rules/rules.js

# Switch to non-root user
USER httpjail

# Create config directory for certificates (will be auto-generated if not mounted)
RUN mkdir -p /home/httpjail/.config/httpjail

# Environment variables for server mode
# Bind to all interfaces (0.0.0.0) for Docker accessibility
ENV HTTPJAIL_HTTP_BIND=0.0.0.0:8080 \
    HTTPJAIL_HTTPS_BIND=0.0.0.0:8443

# Expose proxy ports
EXPOSE 8080/tcp 8443/tcp

# Declare volumes for certificates and rules
# Certificates are stored at /home/httpjail/.config/httpjail/
VOLUME ["/home/httpjail/.config/httpjail", "/rules"]

# Set entrypoint and default command
ENTRYPOINT ["httpjail"]
CMD ["--server", "--js-file", "/rules/rules.js", "--request-log", "/dev/stdout"]
