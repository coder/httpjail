#!/usr/bin/env bash
set -euo pipefail

# mdbook.sh - Wrapper script for mdbook that ensures preprocessors are installed
# Usage: ./scripts/mdbook.sh [mdbook-commands...]
# Example: ./scripts/mdbook.sh build
# Example: ./scripts/mdbook.sh serve

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[mdbook.sh]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[mdbook.sh]${NC} $*"
}

log_error() {
    echo -e "${RED}[mdbook.sh]${NC} $*" >&2
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Install mdbook if not present
ensure_mdbook() {
    if command_exists mdbook; then
        log_info "mdbook is already installed ($(mdbook --version))"
        return 0
    fi

    log_warn "mdbook not found, installing..."
    if command_exists cargo; then
        cargo install mdbook --locked
    else
        log_error "cargo not found. Please install Rust toolchain first: https://rustup.rs/"
        exit 1
    fi
}

# Install mdbook-mermaid if not present
ensure_mdbook_mermaid() {
    if command_exists mdbook-mermaid; then
        log_info "mdbook-mermaid is already installed ($(mdbook-mermaid --version 2>&1 | head -1 || echo 'unknown version'))"
        return 0
    fi

    log_warn "mdbook-mermaid not found, installing..."

    # Try cargo install first (works on all platforms)
    if command_exists cargo; then
        cargo install mdbook-mermaid --locked
    else
        log_error "cargo not found. Please install Rust toolchain first: https://rustup.rs/"
        exit 1
    fi

}

# Ensure mermaid assets (JS files) are present
ensure_mermaid_assets() {
    cd "${PROJECT_ROOT}"
    if [ ! -f "mermaid.min.js" ] || [ ! -f "mermaid-init.js" ]; then
        log_info "Installing mermaid assets..."
        mdbook-mermaid install .
    fi
}

# Install mdbook-linkcheck if not present
ensure_mdbook_linkcheck() {
    if command_exists mdbook-linkcheck; then
        log_info "mdbook-linkcheck is already installed ($(mdbook-linkcheck --version 2>&1 | head -1 || echo 'unknown version'))"
        return 0
    fi

    log_warn "mdbook-linkcheck not found, installing..."

    if command_exists cargo; then
        cargo install mdbook-linkcheck --locked
    else
        log_error "cargo not found. Please install Rust toolchain first: https://rustup.rs/"
        exit 1
    fi
}

# Main installation check
main() {
    log_info "Checking mdbook prerequisites..."

    ensure_mdbook
    ensure_mdbook_mermaid
    ensure_mdbook_linkcheck
    ensure_mermaid_assets

    log_info "All prerequisites satisfied"

    # Pass through all arguments to mdbook
    if [ $# -eq 0 ]; then
        log_warn "No command specified, running 'mdbook --help'"
        mdbook --help
    else
        log_info "Running: mdbook $*"
        cd "${PROJECT_ROOT}"
        mdbook "$@"
    fi
}

main "$@"
