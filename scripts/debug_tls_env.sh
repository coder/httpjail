#!/bin/bash
# Debug script to understand TLS environment in CI

echo "=== TLS Environment Debug Information ==="
echo ""

echo "1. OpenSSL Version:"
openssl version -a
echo ""

echo "2. Curl Version and Features:"
curl --version
echo ""

echo "3. System CA certificates location:"
ls -la /etc/ssl/certs/ | head -10
echo "Total certs in /etc/ssl/certs: $(ls /etc/ssl/certs/*.pem 2>/dev/null | wc -l)"
echo ""

echo "4. User config directories:"
echo "HOME: $HOME"
echo "USER: $USER"
echo "SUDO_USER: $SUDO_USER"
echo "Current UID: $(id -u)"
echo "Current user: $(whoami)"
echo ""

echo "5. httpjail CA certificate locations:"
for dir in /home/runner/.config/httpjail /root/.config/httpjail $HOME/.config/httpjail; do
    if [ -d "$dir" ]; then
        echo "Found httpjail config at: $dir"
        ls -la "$dir"/*.pem 2>/dev/null || echo "  No .pem files found"
        
        # Check if CA cert is valid
        if [ -f "$dir/ca-cert.pem" ]; then
            echo "  Validating CA certificate:"
            openssl x509 -in "$dir/ca-cert.pem" -text -noout 2>&1 | grep -E "Subject:|Issuer:|Signature Algorithm:|Public Key Algorithm:" | head -10
            
            # Test if OpenSSL can parse it without errors
            if openssl x509 -in "$dir/ca-cert.pem" -noout 2>/dev/null; then
                echo "  ✓ Certificate parses successfully"
            else
                echo "  ✗ Certificate parsing failed!"
                openssl x509 -in "$dir/ca-cert.pem" -noout 2>&1
            fi
        fi
    else
        echo "No httpjail config at: $dir"
    fi
    echo ""
done

echo "6. Test ECDSA support:"
# Generate a test ECDSA key and certificate
TEMP_KEY=$(mktemp)
TEMP_CERT=$(mktemp)
openssl ecparam -genkey -name prime256v1 -out "$TEMP_KEY" 2>/dev/null
openssl req -new -x509 -key "$TEMP_KEY" -out "$TEMP_CERT" -days 1 -subj "/CN=test" 2>/dev/null

if openssl x509 -in "$TEMP_CERT" -noout 2>/dev/null; then
    echo "✓ ECDSA P-256 certificates work"
    openssl x509 -in "$TEMP_CERT" -text -noout 2>&1 | grep "Signature Algorithm:"
else
    echo "✗ ECDSA P-256 certificates failed"
fi
rm -f "$TEMP_KEY" "$TEMP_CERT"
echo ""

echo "7. Test certificate chain verification:"
# If httpjail CA exists, test creating and verifying a certificate with it
CA_CERT=""
for dir in /home/runner/.config/httpjail /root/.config/httpjail $HOME/.config/httpjail; do
    if [ -f "$dir/ca-cert.pem" ]; then
        CA_CERT="$dir/ca-cert.pem"
        break
    fi
done

if [ -n "$CA_CERT" ]; then
    echo "Testing with CA cert: $CA_CERT"
    # Extract the signature algorithm from the CA
    echo "CA Certificate details:"
    openssl x509 -in "$CA_CERT" -text -noout 2>&1 | grep -E "Signature Algorithm:|Public Key Algorithm:"
else
    echo "No httpjail CA certificate found to test"
fi
echo ""

echo "8. Environment variables:"
env | grep -E "SSL|TLS|CERT|CA" | sort
echo ""

echo "=== End Debug Information ==="