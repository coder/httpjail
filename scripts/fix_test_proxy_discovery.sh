#!/bin/bash
# Script to discover proxy inside the namespace

echo "=== Proxy Discovery ==="

# Get the actual gateway IP (host side of veth)
HOST_IP=$(ip route | grep default | awk '{print $3}')
echo "Host IP detected as: $HOST_IP"

# Also check actual interfaces to be sure
echo "Network interfaces:"
ip addr show | grep -E "inet |^[0-9]+:"

# Find the actual proxy port from environment or scan
echo "Scanning for proxy ports on $HOST_IP..."
for port in 8000 8001 8002 8003 8004 8005 8006 8007 8008 8009 8100 8200 8300 8400 8500 8600 8700 8800 8900; do
    if timeout 1 nc -zv "$HOST_IP" $port 2>/dev/null; then
        echo "Found proxy on port $port"
        # Save for later use
        echo "$HOST_IP:$port"
        exit 0
    fi
done

echo "ERROR: No proxy found on any scanned port"
exit 1