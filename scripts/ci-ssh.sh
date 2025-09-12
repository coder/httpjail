#!/bin/bash
# SSH into the CI-1 instance for debugging

set -e

echo "Connecting to CI-1 instance..."
gcloud --quiet compute ssh root@ci-1 --zone us-central1-f --project httpjail "$@"