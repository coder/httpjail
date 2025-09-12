#!/bin/bash
# SSH into the CI-1 instance for debugging

set -e

if [ $# -eq 0 ]; then
    echo "Connecting to CI-1 instance (interactive)..."
    gcloud --quiet compute ssh root@ci-1 --zone us-central1-f --project httpjail
else
    # Execute command remotely
    gcloud --quiet compute ssh root@ci-1 --zone us-central1-f --project httpjail -- "$@"
fi