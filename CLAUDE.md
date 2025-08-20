# Agent instructions

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
