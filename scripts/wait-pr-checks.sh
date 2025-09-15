#!/bin/bash
# wait-pr-checks.sh - Poll GitHub Actions status for a PR and exit on first failure or when all pass
#
# Usage: ./scripts/wait-pr-checks.sh [pr-number] [repo]
#   pr-number: Optional PR number (auto-detects from current branch if not provided)
#   repo: Optional repository in format owner/repo (defaults to coder/httpjail)
#
# Exit codes:
#   0 - All checks passed
#   1 - A check failed
#   2 - Invalid arguments or no PR found
#
# Requires: gh, jq

set -euo pipefail

# Parse arguments and auto-detect PR if needed
if [ $# -eq 0 ]; then
    # Auto-detect PR from current branch
    echo "Auto-detecting PR from current branch..." >&2
    CURRENT_BRANCH=$(git branch --show-current)
    
    # Try to find PR for current branch
    PR_INFO=$(gh pr list --head "${CURRENT_BRANCH}" --json number,headRefName --limit 1 2>/dev/null || echo "[]")
    PR_NUMBER=$(echo "$PR_INFO" | jq -r '.[0].number // empty')
    
    if [ -z "$PR_NUMBER" ]; then
        echo "Error: No PR found for branch '${CURRENT_BRANCH}'" >&2
        echo "" >&2
        echo "Usage: $0 [pr-number] [repo]" >&2
        echo "  When called without arguments, auto-detects PR from current branch" >&2
        echo "  Examples:" >&2
        echo "    $0                    # Auto-detect PR from current branch" >&2
        echo "    $0 47                 # Monitor PR #47" >&2
        echo "    $0 47 coder/httpjail  # Monitor PR #47 in specific repo" >&2
        exit 2
    fi
    
    # Auto-detect repo from git remote
    REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || echo "coder/httpjail")
    echo "Found PR #${PR_NUMBER} for branch '${CURRENT_BRANCH}' in ${REPO}" >&2
elif [ $# -eq 1 ]; then
    PR_NUMBER="$1"
    REPO="coder/httpjail"
else
    PR_NUMBER="$1"
    REPO="$2"
fi

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