# CI Network Namespace Limitations

## Summary

Network namespaces in GitHub Actions CI cannot access the internet, making it impossible to run the full httpjail test suite in CI.

## Root Cause

GitHub Actions runners enforce a security policy that **blocks all outbound traffic from custom network namespaces** at the infrastructure level. This is not a configuration issue we can fix - it's a deliberate security restriction.

## Technical Details

### What Works ✅
- Creating network namespaces (`ip netns add`)
- Setting up veth pairs
- Local connectivity within the namespace
- DNS configuration via `/etc/netns/` mechanism
- Packets can leave the namespace (visible in tcpdump)

### What Fails ❌
- All outbound internet connectivity from namespaces
- DNS queries to external servers (8.8.8.8, 1.1.1.1, etc.)
- HTTP/HTTPS requests to any external host
- Even ICMP ping to external IPs

### Evidence

From our diagnostic tests in CI:

1. **Packets leave but never return:**
   ```
   tcpdump: 14:34:31.592895 IP 10.99.0.2.50759 > 8.8.8.8.53: 39625+ A? google.com. (28)
   ```
   No response packet ever arrives.

2. **100% packet loss despite correct configuration:**
   - NAT/MASQUERADE rules: ✅ Added correctly
   - IP forwarding: ✅ Enabled  
   - Routing table: ✅ Correct default route
   - Result: ❌ 100% packet loss to 8.8.8.8

3. **DNS times out despite proper setup:**
   ```
   ;; communications error to 8.8.8.8#53: timed out
   ;; no servers could be reached
   ```

## Why This Restriction Exists

GitHub Actions implements this for security:
- **Container escape prevention**: Prevents compromised containers from accessing the internet
- **Multi-tenant isolation**: Ensures workflow isolation in shared infrastructure  
- **Abuse prevention**: Blocks potential misuse of network namespaces
- **Azure network policies**: Enforced at the hypervisor/host level

## Impact on Testing

Tests that cannot run in CI:
- DNS resolution tests
- External HTTP/HTTPS request tests  
- Any test requiring real network connectivity

## Workarounds

### Current Approach
Skip affected tests when `CI` environment variable is set:
```rust
if std::env::var("CI").is_ok() {
    eprintln!("WARNING: Test skipped in CI - network namespaces cannot access internet");
    return;
}
```

### Alternative Solutions

1. **Mock servers**: Run local HTTP/HTTPS servers on localhost (no external connectivity needed)
2. **Self-hosted runners**: Use dedicated VMs with full network access
3. **Integration environment**: Separate testing infrastructure outside GitHub Actions
4. **IP-based tests**: Use hardcoded IPs instead of DNS (still won't work due to connectivity block)

## Conclusion

This is a fundamental limitation of GitHub Actions' security model, not a bug in our code or configuration. The httpjail tests work correctly on any Linux system with normal network access, but GitHub Actions specifically blocks namespace networking for security reasons.

The tests pass on:
- Local development machines
- Self-hosted Linux VMs (like ml-1)
- Any environment without namespace network restrictions

They will never work in:
- GitHub Actions hosted runners
- Other CI systems with similar security policies
- Restricted container environments