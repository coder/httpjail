#!/bin/bash
# Build and verify static glibc binaries for Linux
# This uses the gnu target with crt-static for better portability while avoiding musl/V8 issues

set -e

# Parse arguments
NON_INTERACTIVE=false
if [[ "$1" == "--non-interactive" ]] || [[ "$1" == "--ci" ]]; then
    NON_INTERACTIVE=true
fi

echo "=== httpjail static build verification ==="
echo ""

# Determine architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)
        TARGET="x86_64-unknown-linux-gnu"
        ;;
    aarch64|arm64)
        TARGET="aarch64-unknown-linux-gnu"
        ;;
    *)
        echo "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

echo "Detected architecture: $ARCH"
echo "Target: $TARGET"
echo "Note: Using gnu target with crt-static for static glibc linking"
echo ""

# Check if rust target is installed
echo "1. Checking Rust target..."
if ! rustup target list --installed | grep -q "$TARGET"; then
    echo "Target $TARGET not installed. Installing..."
    rustup target add "$TARGET"
else
    echo "✓ Target $TARGET already installed"
fi
echo ""

# Build with static linking
echo "2. Building for $TARGET with static glibc..."
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --target "$TARGET"
echo ""

# Verify binary (check both local and shared cargo target)
BINARY="target/$TARGET/release/httpjail"
if [ ! -f "$BINARY" ] && [ -n "${CARGO_HOME}" ]; then
    # Check shared cargo target when CARGO_HOME is set
    BINARY="${CARGO_HOME}/shared-target/$TARGET/release/httpjail"
fi

if [ ! -f "$BINARY" ]; then
    echo "✗ Binary not found at $BINARY"
    exit 1
fi

echo "3. Verifying linking..."
echo ""

# Check file type
echo "File type:"
file "$BINARY"
echo ""

# Check dynamic dependencies
echo "Dynamic dependencies:"
if ldd "$BINARY" 2>&1; then
    echo ""
    echo "Note: Binary uses dynamic linking for some system libraries (expected with glibc)"
    echo "The C runtime is statically linked, improving portability to older systems"
else
    echo "✓ Binary is fully statically linked"
fi
echo ""

# Check binary size
SIZE=$(du -h "$BINARY" | cut -f1)
echo "Binary size: $SIZE"
echo ""

# Test basic functionality
echo "4. Testing binary..."
if "$BINARY" --version; then
    echo "✓ Binary runs successfully"
else
    echo "✗ Binary failed to run"
    exit 1
fi
echo ""

echo "=== Build verification complete ==="
echo ""
echo "Binary location: $BINARY"
echo "To test on an older system, copy this binary and run:"
echo "  ./httpjail --version"
echo ""
echo "The binary uses static glibc linking for improved portability while"
echo "still working with V8 prebuilt binaries (musl not supported by V8)."
