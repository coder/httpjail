# Agent instructions

## Performance

All proxying must be done on a streaming basis so that all types of requests are
supported at minimal latency and a constant memory overhead.

Any time we need to read a specific number of bytes from the stream (e.g. to determine
protocol), we must establish a timeout for the operation.

Timeouts must not preclude long-running connections such as GRPC or WebSocket.

## Building

For faster builds during development and debugging, use the `fast` profile:

```bash
cargo build --profile fast
```

This profile inherits from release mode but uses lower optimization levels and disables LTO
for significantly faster build times while still providing reasonable performance.

## Testing

When writing tests, prefer pure rust solutions over shell script wrappers.

When testing behavior outside of the strong jailing, use `--weak` for an environment-only
invocation of the tool. `--weak` works by setting the `HTTP_PROXY` and `HTTPS_PROXY` environment
variables to the proxy address.

### Integration Tests

The integration tests run against the binary built by Cargo; no manual environment variables are required. On Linux, run the strong-jail integration tests with sudo:

```bash
sudo -E cargo test --test linux_integration
```

Weak-mode tests (environment-only, cross-platform) run without sudo:

```bash
cargo test --test weak_integration
```

Run the full suite:

```bash
cargo test
```

### Test Performance Requirements

**All tests must complete within seconds, not minutes.** The CI timeout is set to 30 seconds per test. Tests that require longer operations (like timeouts) should use minimal durations:

- Use `HttpjailCommand::timeout(2)` for timeout tests with `sleep 3`
- Network tests should use `--connect-timeout 5 --max-time 8` for curl commands
- Any test taking longer than a few seconds should be optimized or redesigned

This ensures fast feedback during development and prevents CI timeouts.

## Cargo Cache

Occasionally you will encounter permissions issues due to running the tests under sudo. In these cases,
DO NOT `cargo clean`. Instead, `chown -R <user> target`.

## macOS

- macOS uses weak mode (environment-only) and does not use PF. No root/sudo required for standard usage or tests.
- To run integration tests on macOS, prefer the weak-mode suite:
  ```bash
  cargo test --test weak_integration
  ```

### Certificate Trust on macOS

- **curl and most CLI tools**: Respect the `SSL_CERT_FILE`/`SSL_CERT_DIR` environment variables that httpjail sets, so they work even without the CA in the system keychain
- **Go programs (gh, go, etc.)**: Use the macOS Security.framework and ignore environment variables, requiring the CA to be installed in the keychain via `httpjail trust --install`
- When the CA is not trusted in the keychain, httpjail will:
  - Still attempt TLS interception (not pass-through)
  - Warn that applications may fail with certificate errors
  - Go programs will fail to connect until `httpjail trust --install` is run

## Documentation

User-facing documentation should be in the README.md file.

Code/testing/contributing documentation should be here.

When updating any user-facing interface of the tool in a way that breaks compatibility or adds a new feature, update the README.md file.

## Clippy

CI requires the following to pass on both macOS and Linux targets:

```
cargo clippy --all-targets -- -D warnings
```

When the user asks to run clippy and provides the ability to run on both targets, try to run it
on both targets.

## Formatting

After modifying code, run `cargo fmt` to ensure consistent formatting before committing changes.

## System Resource Cleanup

**CRITICAL: All global system resources MUST be properly cleaned up to prevent resource leaks.**

### Linux System Resources

The following system resources are created for each jail and MUST be cleaned up:

1. **Network Namespace** (`NetworkNamespace`) - `/var/run/netns/httpjail_<jail_id>`
2. **Virtual Ethernet Pairs** (`VethPair`) - `veth_host_<jail_id>` and `veth_ns_<jail_id>`
3. **NFTables Rules** (`NFTable`) - iptables/nftables rules for traffic redirection
4. **DNS Server Process** (`ForkedDnsProcess`) - Child process running in namespace
5. **Any namespace-specific configuration** - e.g., `/etc/netns/<namespace>` if created

### Cleanup Mechanisms

1. **Normal Exit**: Resources implement `Drop` trait for automatic cleanup
2. **Orphan Cleanup**: `cleanup_orphaned()` handles resources from crashed instances
3. **Process Cleanup**: Must kill ALL processes in namespace before deletion
4. **Order Matters**: Clean processes first, then network resources, then namespace

### Implementation Requirements

When adding new system resources:
- Implement `SystemResource` trait with proper `cleanup()` method
- Add to `cleanup_orphaned()` for crash recovery
- Ensure `Drop` implementation for normal cleanup
- Test with `--no-jail-cleanup` flag to verify cleanup works
- Use `ManagedResource<T>` wrapper for automatic cleanup on drop

### Testing Cleanup

```bash
# Test orphan cleanup
sudo ./target/debug/httpjail --js "true" -- sleep 100 &
PID=$!
sudo kill -9 $PID  # Simulate crash
sudo ./target/debug/httpjail --cleanup  # Should clean up orphaned resources

# Verify no resources left
ip netns list | grep httpjail  # Should be empty
ip link show | grep veth_      # Should show no jail veths
sudo iptables -L -t nat | grep httpjail  # Should show no jail rules
```

## Logging

In regular operation of the CLI-only jail (non-server mode), info and warn logs are not permitted as they would interfere with the underlying process output. Only use debug level logs for normal operation and error logs for actual errors. The server mode (`--server`) may use info/warn logs as appropriate since it has no underlying process.

## CI Debugging

The Linux CI tests run on a self-hosted runner (`ci-1`) in GCP. Only Coder employees can directly SSH into this instance for debugging.

The CI workspace is located at `/home/ci/actions-runner/_work/httpjail/httpjail`. **IMPORTANT: Never modify files in this directory directly as it will interfere with running CI jobs.**

### CI Helper Scripts

```bash
# SSH into CI-1 instance (interactive or with commands)
./scripts/ci-ssh.sh                          # Interactive shell
./scripts/ci-ssh.sh "ls /tmp/httpjail-*"    # Run command

# SCP files to/from CI-1
./scripts/ci-scp.sh src/ /tmp/httpjail-docker-run/     # Upload
./scripts/ci-scp.sh root@ci-1:/path/to/file ./         # Download

# Wait for PR checks to pass or fail
./scripts/wait-pr-checks.sh                  # Auto-detect PR from current branch
./scripts/wait-pr-checks.sh 47               # Monitor specific PR #47
./scripts/wait-pr-checks.sh 47 coder/httpjail # Specify PR and repo explicitly
```

### Manual Testing on CI

```bash
# Set up a fresh workspace for your branch
BRANCH_NAME="your-branch-name"
gcloud --quiet compute ssh root@ci-1 --zone us-central1-f --project httpjail -- "
  rm -rf /tmp/httpjail-$BRANCH_NAME
  git clone https://github.com/coder/httpjail /tmp/httpjail-$BRANCH_NAME
  cd /tmp/httpjail-$BRANCH_NAME
  git checkout $BRANCH_NAME
"

# Sync local changes to the test workspace
gcloud compute scp --recurse src/ root@ci-1:/tmp/httpjail-$BRANCH_NAME/ --zone us-central1-f --project httpjail
gcloud compute scp Cargo.toml root@ci-1:/tmp/httpjail-$BRANCH_NAME/ --zone us-central1-f --project httpjail

# Build and test in the isolated workspace (using shared cargo cache)
gcloud --quiet compute ssh root@ci-1 --zone us-central1-f --project httpjail -- "
  cd /tmp/httpjail-$BRANCH_NAME
  export CARGO_HOME=/home/ci/.cargo
  /home/ci/.cargo/bin/cargo build --profile fast
  sudo ./target/fast/httpjail --help
"
```

This ensures you don't interfere with active CI jobs and provides a clean environment for testing.
