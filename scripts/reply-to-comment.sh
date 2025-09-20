#!/bin/bash
set -euo pipefail

# Script to reply to a GitHub PR review comment
# Usage: ./scripts/reply-to-comment.sh <COMMENT_ID> <MESSAGE>
# Example: ./scripts/reply-to-comment.sh 2365688250 "Fixed in commit abc123"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print usage
usage() {
    echo "Usage: $0 <COMMENT_ID> <MESSAGE>"
    echo ""
    echo "Reply to a GitHub PR review comment with 'Claude Code:' prefix"
    echo ""
    echo "Arguments:"
    echo "  COMMENT_ID    The ID of the comment to reply to (get from get-pr-comments.sh)"
    echo "  MESSAGE       The reply message (will be prefixed with 'Claude Code:')"
    echo ""
    echo "Examples:"
    echo "  $0 2365688250 'Fixed in commit abc123'"
    echo "  $0 2365688250 'Thanks for the feedback - addressed this issue'"
    echo ""
    echo "To find comment IDs, use:"
    echo "  ./scripts/get-pr-comments.sh --raw | grep CID"
    exit 1
}

# Check arguments
if [ $# -lt 2 ]; then
    usage
fi

COMMENT_ID="$1"
shift
MESSAGE="$*"

# Validate comment ID is a number
if ! [[ "$COMMENT_ID" =~ ^[0-9]+$ ]]; then
    echo -e "${RED}Error: Comment ID must be a number${NC}"
    exit 1
fi

# Get repository info from git remote
if ! git remote get-url origin &>/dev/null; then
    echo -e "${RED}Error: Not in a git repository${NC}"
    exit 1
fi

REPO_URL=$(git remote get-url origin)
if [[ "$REPO_URL" =~ github\.com[:/]([^/]+)/([^/.]+)(\.git)?$ ]]; then
    OWNER="${BASH_REMATCH[1]}"
    REPO="${BASH_REMATCH[2]}"
else
    echo -e "${RED}Error: Could not parse repository owner/name from remote URL${NC}"
    exit 1
fi

# Auto-detect PR number from current branch
echo -e "${YELLOW}Detecting PR number from current branch...${NC}"
PR_JSON=$(gh pr view --json number,state 2>/dev/null || echo "{}")
PR_NUMBER=$(echo "$PR_JSON" | jq -r '.number // empty')

if [ -z "$PR_NUMBER" ]; then
    echo -e "${RED}Error: No PR found for current branch${NC}"
    echo "Please ensure you have an open PR for this branch"
    exit 1
fi

PR_STATE=$(echo "$PR_JSON" | jq -r '.state // "UNKNOWN"')
echo -e "Found PR #${PR_NUMBER} (${PR_STATE}) for ${OWNER}/${REPO}"

# Prefix message with "Claude Code:"
FULL_MESSAGE="Claude Code: ${MESSAGE}"

# Send the reply
echo -e "${YELLOW}Sending reply to comment ${COMMENT_ID}...${NC}"
echo -e "Message: ${FULL_MESSAGE}"
echo ""

if gh api "repos/${OWNER}/${REPO}/pulls/${PR_NUMBER}/comments/${COMMENT_ID}/replies" \
    -f body="${FULL_MESSAGE}" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Successfully replied to comment ${COMMENT_ID}${NC}"
    echo -e "View at: https://github.com/${OWNER}/${REPO}/pull/${PR_NUMBER}"
else
    echo -e "${RED}✗ Failed to reply to comment${NC}"
    echo "Please check:"
    echo "  - Comment ID ${COMMENT_ID} exists in PR #${PR_NUMBER}"
    echo "  - You have permission to comment on the PR"
    echo "  - The comment is a review comment (not a general PR comment)"
    exit 1
fi