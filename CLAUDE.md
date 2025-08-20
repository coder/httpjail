# Agent instructions

## Performance

All proxying must be done on a streaming basis so that all types of requests are
supported at minimal latency and a constant memory overhead.

Any time we need to read a specific number of bytes from the stream (e.g. to determine
protocol), we must establish a timeout for the operation.

Timeouts must not preclude long-running connections such as GRPC or WebSocket.

## Testing

When writing tests, prefer pure rust solutions over shell script wrappers.

### Permissions

- On macOS, use `SUDO_ASKPASS=$(pwd)/askpass_macos.sh sudo <cmd>` to test jail features with sufficient permissions
- When testing behavior outside of the strong jailing, use `--weak` for an environment-only
  invocation of the tool.

## Documentation

User-facing documentation should be in the README.md file.

Code/testing/contributing documentation should be in the CONTRIBUTING.md file.

When updating any user-facing interface of the tool in a way that breaks compatibility or adds a new feature, update the README.md file.
