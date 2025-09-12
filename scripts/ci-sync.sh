#!/bin/bash
# Sync local changes to CI-1 for testing without committing

set -e

BRANCH_NAME="${1:-$(git branch --show-current)}"

if [ -z "$BRANCH_NAME" ]; then
    echo "Error: Could not determine branch name"
    echo "Usage: $0 [branch-name]"
    exit 1
fi

echo "Syncing branch '$BRANCH_NAME' to CI-1..."

# Ensure test directory exists with fresh clone
echo "Setting up test workspace..."
gcloud --quiet compute ssh root@ci-1 --zone us-central1-f --project httpjail -- "
    rm -rf /tmp/httpjail-$BRANCH_NAME
    git clone https://github.com/coder/httpjail /tmp/httpjail-$BRANCH_NAME
    cd /tmp/httpjail-$BRANCH_NAME
    git checkout $BRANCH_NAME || git checkout -b $BRANCH_NAME
" 2>/dev/null || true

# Sync source files
echo "Syncing source files..."
gcloud compute scp --recurse --quiet \
    src/ \
    root@ci-1:/tmp/httpjail-$BRANCH_NAME/ \
    --zone us-central1-f --project httpjail

# Sync Cargo files
echo "Syncing Cargo files..."
gcloud compute scp --quiet \
    Cargo.toml Cargo.lock \
    root@ci-1:/tmp/httpjail-$BRANCH_NAME/ \
    --zone us-central1-f --project httpjail 2>/dev/null || true

# Sync test files if they exist
if [ -d "tests" ]; then
    echo "Syncing test files..."
    gcloud compute scp --recurse --quiet \
        tests/ \
        root@ci-1:/tmp/httpjail-$BRANCH_NAME/ \
        --zone us-central1-f --project httpjail
fi

echo "Sync complete! Test workspace: /tmp/httpjail-$BRANCH_NAME"
echo ""
echo "To build:"
echo "  ./scripts/ci-build.sh $BRANCH_NAME"
echo ""
echo "To run tests:"
echo "  ./scripts/ci-test.sh $BRANCH_NAME"