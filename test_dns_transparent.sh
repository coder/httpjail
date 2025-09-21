#!/bin/bash
set -e

echo "Testing DNS transparent redirect..."

# Build the binary first
echo "Building httpjail..."
cargo build --profile fast

# Test DNS queries get intercepted regardless of resolv.conf
echo "Testing DNS interception with curl..."
sudo ./target/fast/httpjail curl -s http://example.com || true

# Test with dig/nslookup if available
if command -v dig &> /dev/null; then
    echo "Testing with dig..."
    sudo ./target/fast/httpjail dig example.com @8.8.8.8 || true
fi

if command -v nslookup &> /dev/null; then
    echo "Testing with nslookup..."
    sudo ./target/fast/httpjail nslookup example.com || true
fi

echo "DNS transparent redirect test complete!"