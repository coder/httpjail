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

## Cargo Cache

Occasionally you will encounter permissions issues due to running the tests under sudo. In these cases,
DO NOT `cargo clean`. Instead, `chown -R <user> target`.

## macOS

- On macOS, use `SUDO_ASKPASS=$(pwd)/askpass_macos.sh sudo -A <cmd>` to test jail features with sufficient permissions.
- To debug pf, you may run the command with `--no-jail-cleanup` to leave around the `httpjail` group
  and PF rules.

## Documentation

User-facing documentation should be in the README.md file.

Code/testing/contributing documentation should be in the CONTRIBUTING.md file.

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

## Logging

In regular operation of the CLI-only jail (non-server mode), info and warn logs are not permitted as they would interfere with the underlying process output. Only use debug level logs for normal operation and error logs for actual errors. The server mode (`--server`) may use info/warn logs as appropriate since it has no underlying process.

## CI Debugging

The Linux CI tests run on a self-hosted runner (`ci-1`) in GCP. Only Coder employees can directly SSH into this instance for debugging.

To debug CI failures on Linux:
```bash
gcloud --quiet compute ssh root@ci-1 --zone us-central1-f --project httpjail
```

The CI workspace is located at `/home/ci/actions-runner/_work/httpjail/httpjail`. **IMPORTANT: Never modify files in this directory directly as it will interfere with running CI jobs.**

### Testing Local Changes on CI

When testing local changes on the CI instance, always work in a fresh directory named after your branch:

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
  export CARGO_TARGET_DIR=/home/ci/.cargo/shared-target
  /home/ci/.cargo/bin/cargo build --profile fast
  sudo /home/ci/.cargo/shared-target/fast/httpjail --help
"
```

This ensures you don't interfere with active CI jobs and provides a clean environment for testing.
