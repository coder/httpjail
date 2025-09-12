#!/bin/bash
# Run tests on CI-1

set -e

BRANCH_NAME="${1:-$(git branch --show-current)}"
TEST_FILTER="${2:-}"

if [ -z "$BRANCH_NAME" ]; then
    echo "Error: Could not determine branch name"
    echo "Usage: $0 [branch-name] [test-filter]"
    echo "  branch-name: Name of the branch/workspace (default: current branch)"
    echo "  test-filter: Optional test name filter (e.g., 'docker_run')"
    exit 1
fi

echo "Running tests on CI-1..."
echo "  Branch: $BRANCH_NAME"
if [ -n "$TEST_FILTER" ]; then
    echo "  Filter: $TEST_FILTER"
fi
echo ""

# Build command with optional filter  
TEST_CMD="/home/ci/.cargo/bin/cargo test --release --test linux_integration"
if [ -n "$TEST_FILTER" ]; then
    TEST_CMD="$TEST_CMD $TEST_FILTER"
fi

gcloud --quiet compute ssh root@ci-1 --zone us-central1-f --project httpjail -- "
    cd /tmp/httpjail-$BRANCH_NAME
    export CARGO_HOME=/home/ci/.cargo
    export PATH=/home/ci/.cargo/bin:\$PATH
    export RUST_BACKTRACE=1
    
    echo 'Running Linux integration tests...'
    sudo -E $TEST_CMD 2>&1 | tee test-output.log
    
    echo ''
    echo 'Test summary:'
    grep -E '(test result:|running [0-9]+ test)' test-output.log || true
"