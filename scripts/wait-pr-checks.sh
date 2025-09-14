#!/bin/bash
# wait-pr-checks.sh - Poll GitHub Actions status for a PR and exit on first failure or when all pass
#
# Usage: ./scripts/wait-pr-checks.sh <pr-number> [repo]
#   pr-number: The PR number to check
#   repo: Optional repository in format owner/repo (defaults to coder/httpjail)
#
# Exit codes:
#   0 - All checks passed
#   1 - A check failed
#   2 - Invalid arguments
#
# Requires: gh, jq

set -euo pipefail

# Parse arguments
if [ $# -lt 1 ]; then
    echo "Usage: $0 <pr-number> [repo]" >&2
    echo "Example: $0 47" >&2
    echo "Example: $0 47 coder/httpjail" >&2
    exit 2
fi

PR_NUMBER="$1"
REPO="${2:-coder/httpjail}"

# Check for required tools
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed" >&2
    exit 2
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "Monitoring PR #${PR_NUMBER} in ${REPO}..."
echo "Polling every second. Press Ctrl+C to stop."
echo ""

# Track the last status to avoid duplicate output
last_status=""

while true; do
    # Get check status as JSON
    if ! json_output=$(gh pr checks "${PR_NUMBER}" --repo "${REPO}" --json name,state,link 2>/dev/null); then
        echo -e "${YELLOW}Waiting for checks to start...${NC}"
        sleep 1
        continue
    fi
    
    # Parse JSON to get counts
    pending_count=$(echo "$json_output" | jq '[.[] | select(.state == "PENDING" or .state == "IN_PROGRESS" or .state == "QUEUED")] | length')
    failed_count=$(echo "$json_output" | jq '[.[] | select(.state == "FAILURE" or .state == "ERROR")] | length')
    passed_count=$(echo "$json_output" | jq '[.[] | select(.state == "SUCCESS")] | length')
    total_count=$(echo "$json_output" | jq 'length')
    
    # Build status string
    current_status="✓ ${passed_count} passed | ⏳ ${pending_count} pending | ✗ ${failed_count} failed"
    
    # Only print if status changed
    if [ "$current_status" != "$last_status" ]; then
        echo -ne "\r\033[K${current_status}"
        last_status="$current_status"
    fi
    
    # Check for failures
    if [ $failed_count -gt 0 ]; then
        echo -e "\n\n${RED}❌ The following check(s) failed:${NC}"
        echo "$json_output" | jq -r '.[] | select(.state == "FAILURE" or .state == "ERROR") | "  - \(.name)"'
        echo -e "\nView details at: https://github.com/${REPO}/pull/${PR_NUMBER}/checks"
        exit 1
    fi
    
    # Check if all passed
    if [ $total_count -gt 0 ] && [ $pending_count -eq 0 ] && [ $failed_count -eq 0 ]; then
        echo -e "\n\n${GREEN}✅ All ${passed_count} checks passed!${NC}"
        echo -e "PR #${PR_NUMBER} is ready to merge."
        exit 0
    fi
    
    sleep 1
done