#!/bin/bash
# Monitor script to track resource usage and alert on leaks

NAMESPACE_THRESHOLD=5
NFTABLE_THRESHOLD=50
LOAD_THRESHOLD=10

check_resources() {
    local ns_count=$(ip netns list | grep -c httpjail || echo 0)
    local nft_count=$(nft list tables 2>/dev/null | grep -c httpjail || echo 0)
    local load=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | cut -d, -f1)
    
    echo "Resource check at $(date):"
    echo "  Namespaces: $ns_count (threshold: $NAMESPACE_THRESHOLD)"
    echo "  NFTables: $nft_count (threshold: $NFTABLE_THRESHOLD)"
    echo "  Load average: $load (threshold: $LOAD_THRESHOLD)"
    
    if [ "$ns_count" -gt "$NAMESPACE_THRESHOLD" ] || \
       [ "$nft_count" -gt "$NFTABLE_THRESHOLD" ] || \
       [ "$(echo "$load > $LOAD_THRESHOLD" | bc)" -eq 1 ]; then
        echo "WARNING: Resource thresholds exceeded! Running cleanup..."
        bash "$(dirname "$0")/ci-cleanup.sh"
        return 1
    fi
    
    return 0
}

# Run as a service or cron job
if [ "$1" = "--daemon" ]; then
    while true; do
        check_resources
        sleep 300  # Check every 5 minutes
    done
else
    check_resources
fi