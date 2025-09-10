# Agent instructions

## Performance

All proxying must be done on a streaming basis so that all types of requests are
supported at minimal latency and a constant memory overhead.

Any time we need to read a specific number of bytes from the stream (e.g. to determine
protocol), we must establish a timeout for the operation.

Timeouts must not preclude long-running connections such as GRPC or WebSocket.

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
