#!/bin/bash
#
# Get PR review comments with line numbers
#
# Usage:
#   ./scripts/get-pr-comments.sh [PR_NUMBER] [OPTIONS]
#
# Options:
#   -r, --raw      Output raw format without colors
#   -c, --compact  Compact output (one line per comment)
#   -h, --help     Show this help message
#
# Examples:
#   ./scripts/get-pr-comments.sh           # Auto-detect PR from current branch
#   ./scripts/get-pr-comments.sh 54        # Get comments for PR #54
#   ./scripts/get-pr-comments.sh 54 --raw  # Get raw output for piping
#
# If PR_NUMBER is not provided, attempts to detect from current branch

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to get current PR number from branch
get_current_pr() {
    local branch=$(git branch --show-current 2>/dev/null)
    if [[ -z "$branch" ]]; then
        return 1
    fi
    
    # Try to get PR number using gh
    gh pr view --json number -q .number 2>/dev/null || return 1
}

# Parse arguments
PR_NUMBER=""
RAW_MODE=false
COMPACT_MODE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--raw)
            RAW_MODE=true
            shift
            ;;
        -c|--compact)
            COMPACT_MODE=true
            shift
            ;;
        -h|--help)
            grep '^#' "$0" | head -20 | tail -18 | sed 's/^# //'
            exit 0
            ;;
        -*)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
        *)
            if [[ -z "$PR_NUMBER" ]]; then
                PR_NUMBER="$1"
            fi
            shift
            ;;
    esac
done

# Disable colors in raw mode
if [[ "$RAW_MODE" == "true" ]]; then
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    NC=''
fi

# If no PR number provided, try to detect from current branch
if [[ -z "$PR_NUMBER" ]]; then
    echo -e "${BLUE}No PR number provided, detecting from current branch...${NC}"
    PR_NUMBER=$(get_current_pr) || {
        echo -e "${RED}Error: Could not detect PR number from current branch${NC}"
        echo "Usage: $0 [PR_NUMBER]"
        exit 1
    }
    echo -e "${GREEN}Detected PR #$PR_NUMBER${NC}"
fi

# Repository detection
REPO="${GITHUB_REPOSITORY:-coder/httpjail}"

echo -e "${BLUE}Fetching comments for PR #$PR_NUMBER in $REPO...${NC}"
echo ""

# Fetch and format review comments (comments on specific lines of code)
REVIEW_COMMENTS=$(gh api "repos/$REPO/pulls/$PR_NUMBER/comments" --paginate \
  -q '.[] | select(.line != null) | "\(.user.login) [CID=\(.id)] \(.path)#L\(.line): \(.body)"' 2>/dev/null)

# Fetch and format issue comments (general PR comments)
ISSUE_COMMENTS=$(gh api "repos/$REPO/issues/$PR_NUMBER/comments" --paginate \
  -q '.[] | "\(.user.login) [CID=\(.id)] [General]: \(.body)"' 2>/dev/null)

# Check if any comments were found
if [[ -z "$REVIEW_COMMENTS" ]] && [[ -z "$ISSUE_COMMENTS" ]]; then
    echo -e "${YELLOW}No comments found for PR #$PR_NUMBER${NC}"
    exit 0
fi

# Display review comments
if [[ -n "$REVIEW_COMMENTS" ]]; then
    if [[ "$COMPACT_MODE" == "true" ]]; then
        echo "$REVIEW_COMMENTS"
    else
        echo -e "${GREEN}=== Code Review Comments ===${NC}"
        echo "$REVIEW_COMMENTS" | while IFS= read -r line; do
            # Extract components for better formatting
            if [[ "$line" =~ ^([^[:space:]]+)[[:space:]]\[CID=([0-9]+)\][[:space:]]([^:]+):(.*)$ ]]; then
                user="${BASH_REMATCH[1]}"
                cid="${BASH_REMATCH[2]}"
                location="${BASH_REMATCH[3]}"
                comment="${BASH_REMATCH[4]}"
                
                echo -e "${YELLOW}@$user${NC} on ${BLUE}$location${NC} (ID: $cid)"
                echo "$comment" | sed 's/^/  /'
                echo ""
            else
                echo "$line"
                echo ""
            fi
        done
    fi
fi

# Display issue comments
if [[ -n "$ISSUE_COMMENTS" ]]; then
    if [[ "$COMPACT_MODE" == "true" ]]; then
        echo "$ISSUE_COMMENTS"
    else
        echo -e "${GREEN}=== General PR Comments ===${NC}"
        echo "$ISSUE_COMMENTS" | while IFS= read -r line; do
            if [[ "$line" =~ ^([^[:space:]]+)[[:space:]]\[CID=([0-9]+)\][[:space:]]\[General\]:(.*)$ ]]; then
                user="${BASH_REMATCH[1]}"
                cid="${BASH_REMATCH[2]}"
                comment="${BASH_REMATCH[3]}"
                
                echo -e "${YELLOW}@$user${NC} (ID: $cid)"
                echo "$comment" | sed 's/^/  /'
                echo ""
            else
                echo "$line"
                echo ""
            fi
        done
    fi
fi

# Summary (skip in compact mode)
if [[ "$COMPACT_MODE" != "true" ]]; then
    REVIEW_COUNT=$(echo "$REVIEW_COMMENTS" | grep -c '^' 2>/dev/null || echo "0")
    ISSUE_COUNT=$(echo "$ISSUE_COMMENTS" | grep -c '^' 2>/dev/null || echo "0")
    
    echo -e "${BLUE}---${NC}"
    echo -e "${BLUE}Summary: $REVIEW_COUNT code review comment(s), $ISSUE_COUNT general comment(s)${NC}"
fi

# Provide hint for resolving comments (skip in compact or raw mode)
if [[ "$COMPACT_MODE" != "true" ]] && [[ "$RAW_MODE" != "true" ]]; then
    if [[ "$REVIEW_COUNT" -gt 0 ]] || [[ "$ISSUE_COUNT" -gt 0 ]]; then
        echo ""
        echo -e "${YELLOW}Tip: To reply to a comment, use:${NC}"
        echo "  gh pr comment $PR_NUMBER --body 'Your reply here'"
        echo "  gh pr review $PR_NUMBER --comment --body 'Your review comment'"
    fi
fi