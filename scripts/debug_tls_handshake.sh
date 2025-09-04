#!/bin/bash
# Debug script to test TLS handshake with httpjail proxy

echo "=== TLS Handshake Debug ==="
echo ""

# Find httpjail binary
HTTPJAIL=""
for bin in target/debug/httpjail target/release/httpjail; do
    if [ -f "$bin" ]; then
        HTTPJAIL="$bin"
        echo "Using httpjail: $HTTPJAIL"
        break
    fi
done

if [ -z "$HTTPJAIL" ]; then
    echo "Error: httpjail binary not found"
    exit 1
fi

# Find CA cert
CA_CERT=""
for dir in /home/runner/.config/httpjail /root/.config/httpjail $HOME/.config/httpjail; do
    if [ -f "$dir/ca-cert.pem" ]; then
        CA_CERT="$dir/ca-cert.pem"
        echo "Using CA cert: $CA_CERT"
        break
    fi
done

if [ -z "$CA_CERT" ]; then
    echo "Warning: No CA cert found, will generate one"
fi

echo ""
echo "1. Starting httpjail in background (weak mode for testing)..."
# Start httpjail in weak mode to test proxy directly
$HTTPJAIL -r "allow: .*" --weak -- sleep 30 &
HTTPJAIL_PID=$!
sleep 2

# Get proxy ports from environment
HTTP_PROXY_PORT=$(ps aux | grep -E "httpjail.*--weak" | grep -v grep | sed -n 's/.*HTTP_PROXY=.*:\([0-9]*\).*/\1/p' | head -1)
HTTPS_PROXY_PORT=$(ps aux | grep -E "httpjail.*--weak" | grep -v grep | sed -n 's/.*HTTPS_PROXY=.*:\([0-9]*\).*/\1/p' | head -1)

if [ -z "$HTTP_PROXY_PORT" ]; then
    HTTP_PROXY_PORT=3128
fi
if [ -z "$HTTPS_PROXY_PORT" ]; then  
    HTTPS_PROXY_PORT=3129
fi

echo "Proxy ports: HTTP=$HTTP_PROXY_PORT, HTTPS=$HTTPS_PROXY_PORT"
echo ""

echo "2. Testing direct HTTPS connection to proxy..."
# Use openssl s_client to test the TLS handshake directly
echo "CONNECT example.com:443 HTTP/1.1" | openssl s_client -connect 127.0.0.1:$HTTPS_PROXY_PORT -servername example.com -CAfile "$CA_CERT" -showcerts 2>&1 | head -50

echo ""
echo "3. Testing with curl through proxy..."
if [ -n "$CA_CERT" ]; then
    curl -v --proxy https://127.0.0.1:$HTTPS_PROXY_PORT --cacert "$CA_CERT" -I https://example.com 2>&1 | head -30
else
    curl -v --proxy https://127.0.0.1:$HTTPS_PROXY_PORT -I https://example.com 2>&1 | head -30
fi

echo ""
echo "4. Extracting certificate details from proxy..."
# Connect and get the certificate the proxy is sending
echo | openssl s_client -connect 127.0.0.1:$HTTPS_PROXY_PORT -servername example.com 2>/dev/null | openssl x509 -text -noout 2>&1 | grep -E "Subject:|Issuer:|Signature Algorithm:|Public Key Algorithm:|Not Before:|Not After:" | head -20

# Kill httpjail
kill $HTTPJAIL_PID 2>/dev/null
wait $HTTPJAIL_PID 2>/dev/null

echo ""
echo "=== End TLS Handshake Debug ==="