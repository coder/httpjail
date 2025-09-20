#!/bin/bash

# Test script for line-based script engine

echo "Testing httpjail line-based script engine..."

# Build the project
echo "Building httpjail..."
cargo build --profile fast || exit 1

# Test 1: Allow GitHub
echo -e "\n[TEST 1] Testing allowed domain (github.com):"
./target/fast/httpjail --sh-line ./examples/line_based_filter.py --test GET https://github.com/test
if [ $? -eq 0 ]; then
    echo "✓ GitHub request was allowed as expected"
else
    echo "✗ GitHub request was denied unexpectedly"
fi

# Test 2: Block Facebook
echo -e "\n[TEST 2] Testing blocked domain (facebook.com):"
./target/fast/httpjail --sh-line ./examples/line_based_filter.py --test GET https://facebook.com/profile
if [ $? -ne 0 ]; then
    echo "✓ Facebook request was blocked as expected"
else
    echo "✗ Facebook request was allowed unexpectedly"
fi

# Test 3: Block unknown domain
echo -e "\n[TEST 3] Testing unknown domain (example.com):"
./target/fast/httpjail --sh-line ./examples/line_based_filter.py --test GET https://example.com/test
if [ $? -ne 0 ]; then
    echo "✓ Unknown domain was blocked as expected"
else
    echo "✗ Unknown domain was allowed unexpectedly"
fi

# Test 4: Block POST to webhook
echo -e "\n[TEST 4] Testing POST to webhook (should block):"
./target/fast/httpjail --sh-line ./examples/line_based_filter.py --test POST https://github.com/webhook
if [ $? -ne 0 ]; then
    echo "✓ POST to webhook was blocked as expected"
else
    echo "✗ POST to webhook was allowed unexpectedly"
fi

# Test 5: Compare performance with regular --sh
echo -e "\n[TEST 5] Performance comparison:"

# Create a simple script for --sh mode
cat > /tmp/test_sh.sh << 'EOF'
#!/bin/bash
if [[ "$HTTPJAIL_HOST" == *"github.com"* ]]; then
    exit 0
else
    exit 1
fi
EOF
chmod +x /tmp/test_sh.sh

echo "Testing 10 requests with --sh (spawns new process each time):"
time for i in {1..10}; do
    ./target/fast/httpjail --sh /tmp/test_sh.sh --test GET https://github.com/test >/dev/null 2>&1
done

echo -e "\nTesting 10 requests with --sh-line (persistent process):"
time for i in {1..10}; do
    ./target/fast/httpjail --sh-line ./examples/line_based_filter.py --test GET https://github.com/test >/dev/null 2>&1
done

echo -e "\n✅ All tests completed!"
echo ""
echo "Summary:"
echo "--------"
echo "The new --sh-line mode maintains a persistent process that:"
echo "1. Receives JSON requests on stdin (one per line)"
echo "2. Returns allow/deny decisions immediately"
echo "3. Avoids process spawn overhead for each request"
echo "4. Enables stateful filtering (rate limiting, caching, etc.)"
echo ""
echo "This makes it ideal for high-traffic scenarios and complex filtering logic."