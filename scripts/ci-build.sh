#!/bin/bash
# Build httpjail on CI-1

set -e

BRANCH_NAME="${1:-$(git branch --show-current)}"
PROFILE="${2:-release}"

if [ -z "$BRANCH_NAME" ]; then
    echo "Error: Could not determine branch name"
    echo "Usage: $0 [branch-name] [profile]"
    echo "  branch-name: Name of the branch/workspace (default: current branch)"
    echo "  profile: Build profile - debug, release, or fast (default: release)"
    exit 1
fi

echo "Building httpjail on CI-1..."
echo "  Branch: $BRANCH_NAME"
echo "  Profile: $PROFILE"
echo ""

gcloud --quiet compute ssh root@ci-1 --zone us-central1-f --project httpjail -- "
    cd /tmp/httpjail-$BRANCH_NAME
    export CARGO_HOME=/home/ci/.cargo
    
    if [ '$PROFILE' = 'debug' ]; then
        echo 'Building debug profile...'
        /home/ci/.cargo/bin/cargo build
        echo 'Binary at: /tmp/httpjail-$BRANCH_NAME/target/debug/httpjail'
    elif [ '$PROFILE' = 'fast' ]; then
        echo 'Building fast profile...'
        /home/ci/.cargo/bin/cargo build --profile fast
        echo 'Binary at: /tmp/httpjail-$BRANCH_NAME/target/fast/httpjail'
    else
        echo 'Building release profile...'
        /home/ci/.cargo/bin/cargo build --release
        echo 'Binary at: /tmp/httpjail-$BRANCH_NAME/target/release/httpjail'
    fi
"