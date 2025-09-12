#!/bin/bash
# Run httpjail binary on CI-1 for quick testing

set -e

BRANCH_NAME="${1:-$(git branch --show-current)}"
shift 2>/dev/null || true

if [ -z "$BRANCH_NAME" ]; then
    echo "Error: Could not determine branch name"
    echo "Usage: $0 [branch-name] [httpjail-args...]"
    echo "  branch-name: Name of the branch/workspace (default: current branch)"
    echo "  httpjail-args: Arguments to pass to httpjail"
    echo ""
    echo "Example:"
    echo "  $0 docker-run --js 'true' --docker-run -- alpine:latest echo hello"
    exit 1
fi

echo "Running httpjail on CI-1..."
echo "  Branch: $BRANCH_NAME"
echo "  Args: $@"
echo ""

gcloud --quiet compute ssh root@ci-1 --zone us-central1-f --project httpjail -- "
    cd /tmp/httpjail-$BRANCH_NAME
    
    # Find the httpjail binary (prefer release, then fast, then debug)
    if [ -f target/release/httpjail ]; then
        HTTPJAIL=target/release/httpjail
    elif [ -f target/fast/httpjail ]; then
        HTTPJAIL=target/fast/httpjail
    elif [ -f target/debug/httpjail ]; then
        HTTPJAIL=target/debug/httpjail
    else
        echo 'Error: httpjail binary not found. Run ci-build.sh first.'
        exit 1
    fi
    
    echo \"Using binary: \$HTTPJAIL\"
    echo ''
    
    sudo \$HTTPJAIL $*
"