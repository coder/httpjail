#!/bin/bash
# SCP files to/from the CI-1 instance

set -e

BRANCH_NAME="${BRANCH_NAME:-$(git branch --show-current)}"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <source> [destination]"
    echo "  Copy files to CI-1: $0 src/ /tmp/httpjail-\$BRANCH_NAME/"
    echo "  Copy from CI-1: $0 root@ci-1:/path/to/file local/"
    echo ""
    echo "Environment:"
    echo "  BRANCH_NAME: Target branch directory (default: current git branch)"
    exit 1
fi

SOURCE="$1"
DEST="${2:-/tmp/httpjail-$BRANCH_NAME/}"

# Check if source is remote (contains ci-1:)
if [[ "$SOURCE" == *"ci-1:"* ]]; then
    # Downloading from CI-1
    SOURCE_PATH="${SOURCE#*:}"
    gcloud compute scp --quiet --recurse \
        "root@ci-1:$SOURCE_PATH" \
        "$DEST" \
        --zone us-central1-f --project httpjail
else
    # Uploading to CI-1
    # If destination doesn't start with root@ci-1:, prepend it
    if [[ "$DEST" != "root@ci-1:"* ]]; then
        DEST="root@ci-1:$DEST"
    fi
    
    gcloud compute scp --quiet --recurse \
        "$SOURCE" \
        "$DEST" \
        --zone us-central1-f --project httpjail
fi