#!/bin/bash
# Debug script to test certificate generation and validation

set -e

echo "=== Certificate Generation Debug ==="
echo "Date: $(date)"
echo "OpenSSL version: $(openssl version)"

# Create temp directory for testing
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo ""
echo "Testing certificate generation and validation..."

# Generate a test certificate using OpenSSL directly
cd "$TEMP_DIR"

# Generate CA key
openssl ecparam -genkey -name prime256v1 -out ca-key.pem 2>/dev/null

# Generate CA certificate
openssl req -new -x509 -key ca-key.pem -out ca-cert.pem -days 365 \
  -subj "/C=US/O=httpjail/CN=httpjail CA" 2>/dev/null

# Generate server key
openssl ecparam -genkey -name prime256v1 -out server-key.pem 2>/dev/null

# Generate server CSR
openssl req -new -key server-key.pem -out server.csr \
  -subj "/CN=test.example.com" 2>/dev/null

# Sign server certificate
openssl x509 -req -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out server-cert.pem -days 365 \
  -extfile <(echo "subjectAltName=DNS:test.example.com") 2>/dev/null

echo "Certificates generated successfully"

# Verify the certificate chain
echo ""
echo "Verifying certificate chain..."
openssl verify -CAfile ca-cert.pem server-cert.pem

# Check certificate details
echo ""
echo "Server certificate details:"
openssl x509 -in server-cert.pem -text -noout | grep -E "Subject:|Issuer:|Not Before:|Not After:|Signature Algorithm:" || true

# Test with curl
echo ""
echo "Testing with curl..."
# Create a simple HTTPS server response file
cat > server-chain.pem <<EOF
$(cat server-cert.pem)
$(cat ca-cert.pem)
EOF

# Try to parse with OpenSSL 3.0
echo ""
echo "Parsing certificate with OpenSSL..."
openssl x509 -in server-cert.pem -noout -dates

echo ""
echo "=== Certificate generation test completed successfully ==="