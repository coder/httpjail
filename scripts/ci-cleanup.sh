#!/bin/bash
# CI Cleanup Script - Aggressive resource cleanup for CI environment
# This should be run before and after test suites to ensure clean state

set -euo pipefail

echo "=== Starting aggressive CI cleanup ==="

# 1. Kill all httpjail related processes
echo "Killing httpjail processes..."
pkill -9 -f httpjail || true
pkill -9 -f "__internal-dns-server" || true
sleep 1

# 2. Clean up network namespaces
echo "Cleaning network namespaces..."
for ns in $(ip netns list | grep httpjail | awk '{print $1}'); do
    echo "  Deleting namespace: $ns"
    # First kill all processes in the namespace
    ip netns pids "$ns" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    # Then delete the namespace
    ip netns del "$ns" 2>/dev/null || true
done

# 3. Clean up veth interfaces
echo "Cleaning veth interfaces..."
for veth in $(ip link show | grep -E 'vh_|vn_' | awk -F: '{print $2}' | tr -d ' '); do
    echo "  Deleting veth: $veth"
    ip link del "$veth" 2>/dev/null || true
done

# 4. Clean up nftables (the main culprit)
echo "Cleaning nftables..."
# Count them first
NFTABLE_COUNT=$(nft list tables 2>/dev/null | grep -c httpjail || echo "0")
echo "  Found $NFTABLE_COUNT httpjail nftables to clean"

if [ "$NFTABLE_COUNT" -gt 0 ]; then
    # Delete in batches to avoid overwhelming the system
    nft list tables | grep httpjail | awk '{print $3}' | while read -r table; do
        echo "  Deleting nftable: $table"
        timeout 2 nft delete table inet "$table" 2>/dev/null || \
        timeout 2 nft delete table ip "$table" 2>/dev/null || \
        echo "    Failed to delete $table (may already be deleted)"
    done
fi

# 5. Clean up namespace config directories
echo "Cleaning namespace configs..."
rm -rf /etc/netns/httpjail_* 2>/dev/null || true

# 6. Clean up canary files
echo "Cleaning canary files..."
rm -f /root/.local/share/httpjail/canaries/* 2>/dev/null || true
rm -f /home/*/.local/share/httpjail/canaries/* 2>/dev/null || true

# 7. Verify cleanup
echo ""
echo "=== Cleanup verification ==="
echo "Remaining httpjail namespaces: $(ip netns list | grep -c httpjail || echo 0)"
echo "Remaining httpjail veths: $(ip link show | grep -cE 'vh_|vn_' || echo 0)"
echo "Remaining httpjail nftables: $(nft list tables 2>/dev/null | grep -c httpjail || echo 0)"
echo "Remaining httpjail processes: $(pgrep -fc httpjail || echo 0)"

echo ""
echo "=== Cleanup complete ==="