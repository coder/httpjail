#!/bin/bash
# wait-pr-checks.sh - Poll GitHub Actions status for a PR and exit on first failure or when all pass
#
# Usage: ./scripts/wait-pr-checks.sh [pr-number] [repo] [filter-regex]
#   pr-number: Optional PR number (auto-detects from current branch if not provided)
#   repo: Optional repository in format owner/repo (defaults to coder/httpjail)
#   filter-regex: Optional regex to filter workflow names (e.g., "docs|deploy" to only watch docs/deploy workflows)
#
# Exit codes:
#   0 - All checks passed
#   1 - A check failed
#   2 - Invalid arguments or no PR found
#
# Requires: gh, jq

set -euo pipefail

# Initialize filter variable
FILTER_REGEX=""

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
        echo "Usage: $0 [pr-number] [repo] [filter-regex]" >&2
        echo "  When called without arguments, auto-detects PR from current branch" >&2
        echo "  Examples:" >&2
        echo "    $0                           # Auto-detect PR from current branch" >&2
        echo "    $0 47                        # Monitor PR #47" >&2
        echo "    $0 47 coder/httpjail         # Monitor PR #47 in specific repo" >&2
        echo "    $0 47 coder/httpjail 'docs'  # Monitor only docs-related checks" >&2
        exit 2
    fi
    
    # Auto-detect repo from git remote
    REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || echo "coder/httpjail")
    echo "Found PR #${PR_NUMBER} for branch '${CURRENT_BRANCH}' in ${REPO}" >&2
elif [ $# -eq 1 ]; then
    PR_NUMBER="$1"
    REPO="coder/httpjail"
elif [ $# -eq 2 ]; then
    PR_NUMBER="$1"
    REPO="$2"
elif [ $# -eq 3 ]; then
    PR_NUMBER="$1"
    REPO="$2"
    FILTER_REGEX="$3"
else
    echo "Error: Too many arguments" >&2
    echo "Usage: $0 [pr-number] [repo] [filter-regex]" >&2
    exit 2
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
if [ -n "$FILTER_REGEX" ]; then
    echo "Filtering checks to match: $FILTER_REGEX"
fi
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
    
    # Apply filter if specified
    if [ -n "$FILTER_REGEX" ]; then
        filtered_output=$(echo "$json_output" | jq --arg regex "$FILTER_REGEX" '[.[] | select(.name | test($regex; "i"))]')
    else
        filtered_output="$json_output"
    fi
    
    # Parse JSON to get counts
    pending_count=$(echo "$filtered_output" | jq '[.[] | select(.state == "PENDING" or .state == "IN_PROGRESS" or .state == "QUEUED")] | length')
    failed_count=$(echo "$filtered_output" | jq '[.[] | select(.state == "FAILURE" or .state == "ERROR")] | length')
    passed_count=$(echo "$filtered_output" | jq '[.[] | select(.state == "SUCCESS")] | length')
    total_count=$(echo "$filtered_output" | jq 'length')
    
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
        echo "$filtered_output" | jq -r '.[] | select(.state == "FAILURE" or .state == "ERROR") | "  - \(.name)"'
        
        # Try to fetch logs for the first failed check
        echo -e "\n${YELLOW}Fetching logs for first failed check...${NC}\n"
        
        # Get the first failed check details
        first_failed=$(echo "$filtered_output" | jq -r '.[] | select(.state == "FAILURE" or .state == "ERROR") | "\(.name)|\(.link)"' | head -1)
        
        if [ -n "$first_failed" ]; then
            IFS='|' read -r check_name check_link <<< "$first_failed"
            echo -e "${YELLOW}=== Logs for: ${check_name} ===${NC}"
            
            # Extract run ID and job ID from the link
            if [[ "$check_link" =~ /runs/([0-9]+)/job/([0-9]+) ]]; then
                run_id="${BASH_REMATCH[1]}"
                job_id="${BASH_REMATCH[2]}"
                
                # Use direct API call to get job logs (more reliable than gh run view)
                if job_logs=$(gh api "repos/${REPO}/actions/jobs/${job_id}/logs" --paginate 2>&1); then
                    # Look for error patterns in the logs
                    error_logs=$(echo "$job_logs" | grep -E "(error:|Error:|ERROR:|warning:|clippy::|failed|Failed|##\[error\])" | head -30)
                    if [ -n "$error_logs" ]; then
                        echo "$error_logs"
                    else
                        # If no error patterns found, show last 100 lines which often contain the failure
                        echo "$job_logs" | tail -100
                    fi
                else
                    # If logs aren't ready, try to at least show the conclusion
                    echo "Full logs not available yet. Check: ${check_link}"
                fi
            else
                echo "Could not parse check link: ${check_link}"
            fi
            echo ""
        fi
        
        echo -e "\nView full details at: https://github.com/${REPO}/pull/${PR_NUMBER}/checks"
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