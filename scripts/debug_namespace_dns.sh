#!/bin/bash
# Comprehensive DNS debugging in network namespaces

NAMESPACE="httpjail_test_$$"

echo "=== Creating test namespace: $NAMESPACE ==="
sudo ip netns add $NAMESPACE

echo -e "\n=== 1. Check resolv.conf in host ==="
echo "Host /etc/resolv.conf:"
cat /etc/resolv.conf
echo "Is it a symlink?"
ls -la /etc/resolv.conf

echo -e "\n=== 2. Check resolv.conf in namespace (default) ==="
sudo ip netns exec $NAMESPACE cat /etc/resolv.conf 2>&1 || echo "FAILED to read"

echo -e "\n=== 3. Check if /etc/netns mechanism works ==="
sudo mkdir -p /etc/netns/$NAMESPACE
echo "nameserver 8.8.8.8" | sudo tee /etc/netns/$NAMESPACE/resolv.conf
echo "Created /etc/netns/$NAMESPACE/resolv.conf"
# Delete and recreate namespace to test bind mount
sudo ip netns del $NAMESPACE
sudo ip netns add $NAMESPACE
echo "After recreating namespace with /etc/netns:"
sudo ip netns exec $NAMESPACE cat /etc/resolv.conf 2>&1

echo -e "\n=== 4. Network interfaces in namespace ==="
sudo ip netns exec $NAMESPACE ip link show

echo -e "\n=== 5. Try to ping 8.8.8.8 (no DNS needed) ==="
sudo ip netns exec $NAMESPACE ping -c 1 -W 2 8.8.8.8 2>&1 || echo "FAILED"

echo -e "\n=== 6. Setup veth pair for connectivity ==="
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth1 netns $NAMESPACE
sudo ip addr add 10.99.0.1/30 dev veth0
sudo ip link set veth0 up
sudo ip netns exec $NAMESPACE ip addr add 10.99.0.2/30 dev veth1
sudo ip netns exec $NAMESPACE ip link set veth1 up
sudo ip netns exec $NAMESPACE ip link set lo up
sudo ip netns exec $NAMESPACE ip route add default via 10.99.0.1

echo -e "\n=== 7. Test connectivity with veth ==="
echo "Ping gateway from namespace:"
sudo ip netns exec $NAMESPACE ping -c 1 -W 2 10.99.0.1 2>&1 || echo "FAILED"
echo "Ping 8.8.8.8 from namespace:"
sudo ip netns exec $NAMESPACE ping -c 1 -W 2 8.8.8.8 2>&1 || echo "FAILED"

echo -e "\n=== 8. Check iptables/NAT on host ==="
sudo iptables -t nat -L POSTROUTING -n -v | grep -E "MASQUERADE|10.99" || echo "No NAT rules found"

echo -e "\n=== 9. Add NAT for namespace ==="
sudo iptables -t nat -A POSTROUTING -s 10.99.0.0/30 -j MASQUERADE
sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null
echo "After adding NAT:"
sudo ip netns exec $NAMESPACE ping -c 1 -W 2 8.8.8.8 2>&1 || echo "FAILED"

echo -e "\n=== 10. Test DNS resolution ==="
echo "Using nslookup:"
sudo ip netns exec $NAMESPACE nslookup google.com 8.8.8.8 2>&1 || echo "nslookup FAILED"
echo "Using dig:"
sudo ip netns exec $NAMESPACE dig +short google.com @8.8.8.8 2>&1 || echo "dig FAILED"
echo "Using host:"
sudo ip netns exec $NAMESPACE host google.com 8.8.8.8 2>&1 || echo "host FAILED"

echo -e "\n=== 11. Test raw DNS query with nc ==="
echo "Check if we can reach 8.8.8.8:53:"
sudo ip netns exec $NAMESPACE nc -zv -w2 8.8.8.8 53 2>&1 || echo "Cannot reach DNS port"

echo -e "\n=== 12. Check for DNS traffic with tcpdump ==="
sudo timeout 3 ip netns exec $NAMESPACE tcpdump -i veth1 -n 'port 53' 2>/dev/null &
TCPDUMP_PID=$!
sleep 1
sudo ip netns exec $NAMESPACE nslookup google.com 8.8.8.8 2>&1 > /dev/null
wait $TCPDUMP_PID 2>/dev/null || true

echo -e "\n=== 13. strace DNS resolution ==="
echo "Tracing nslookup:"
sudo ip netns exec $NAMESPACE strace -e network nslookup google.com 8.8.8.8 2>&1 | grep -E "socket|connect|send|recv" | head -10

echo -e "\n=== 14. Check systemd-resolved status ==="
systemctl is-active systemd-resolved || echo "systemd-resolved not active"
resolvectl status 2>/dev/null | head -20 || echo "resolvectl not available"

echo -e "\n=== 15. Test with different resolv.conf ==="
echo "nameserver 8.8.8.8" | sudo tee /tmp/test-resolv.conf > /dev/null
sudo ip netns exec $NAMESPACE mount --bind /tmp/test-resolv.conf /etc/resolv.conf 2>&1 || echo "Mount failed"
echo "After bind mount:"
sudo ip netns exec $NAMESPACE cat /etc/resolv.conf
sudo ip netns exec $NAMESPACE nslookup google.com 2>&1 || echo "Still FAILED"

echo -e "\n=== Cleanup ==="
sudo ip netns del $NAMESPACE
sudo ip link del veth0 2>/dev/null || true
sudo iptables -t nat -D POSTROUTING -s 10.99.0.0/30 -j MASQUERADE 2>/dev/null || true
sudo rm -f /tmp/test-resolv.conf
sudo rm -rf /etc/netns/$NAMESPACE

echo "=== Done ==="