#!/bin/bash
set -e

echo "Testing httpjail on macOS"
echo "========================="
echo "Using ports 8040 (HTTP) and 8043 (HTTPS)"
echo

# Build the project
echo "Building httpjail..."
cargo build

# Test 1: Basic jail test with allow rule
echo "Test 1: Allow httpbin.org GET requests"
echo "----------------------------------------"
sudo ./target/debug/httpjail --allow "httpbin\\.org" -vv -- curl -s http://httpbin.org/get | head -20

echo
echo "Test 2: Deny POST requests to httpbin.org" 
echo "----------------------------------------"
sudo ./target/debug/httpjail --allow-get "httpbin\\.org" -vv -- curl -X POST -s http://httpbin.org/post || echo "Request denied as expected"

echo
echo "Test 3: Log-only mode"
echo "----------------------------------------"
sudo ./target/debug/httpjail --log-only -vv -- curl -s http://example.com | head -5

echo
echo "Tests complete!"