#!/bin/bash
#
# PR Comment Fetcher - Designed for AI/Agent Use
#
# This script is optimized for AI agents and automation tools to fetch
# unresolved PR code review comments. Output is plain text without colors
# and excludes resolved conversations.
#
# Usage:
#   ./scripts/get-pr-comments.sh [PR_NUMBER] [OPTIONS]
#
# Options:
#   --raw          Output raw format (included for compatibility)
#   --compact      Output in compact format (one line per comment)
#   -h, --help     Show this help message
#
# Examples:
#   ./scripts/get-pr-comments.sh           # Auto-detect PR from current branch
#   ./scripts/get-pr-comments.sh 54        # Get comments for PR #54
#   ./scripts/get-pr-comments.sh --compact # Get compact output
#
# Note: Only shows unresolved code review comments (resolvable comments on specific lines),
#       not general PR comments or resolved conversations
#
# If PR_NUMBER is not provided, attempts to detect from current branch
#
set -euo pipefail

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
COMPACT_MODE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --raw)
            # Included for compatibility, but output is always plain text
            shift
            ;;
        --compact)
            COMPACT_MODE=true
            shift
            ;;
        -h|--help)
            grep '^#' "$0" | head -25 | tail -23 | sed 's/^# //'
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

# If no PR number provided, try to detect from current branch
if [[ -z "$PR_NUMBER" ]]; then
    echo "No PR number provided, detecting from current branch..."
    PR_NUMBER=$(get_current_pr) || {
        echo "Error: Could not detect PR number from current branch"
        echo "Usage: $0 [PR_NUMBER]"
        exit 1
    }
    echo "Detected PR #$PR_NUMBER"
fi

# Repository detection
REPO="${GITHUB_REPOSITORY:-coder/httpjail}"

echo "Fetching unresolved code review comments for PR #$PR_NUMBER in $REPO..."
echo ""

# Fetch review comments with resolution status
# We need to get the comments and check if they're part of resolved conversations
REVIEW_COMMENTS=$(gh api "repos/$REPO/pulls/$PR_NUMBER/comments" --paginate \
  -q '.[] | select(.line != null) | {
    id: .id,
    user: .user.login,
    path: .path,
    line: .line,
    body: .body,
    in_reply_to_id: .in_reply_to_id,
    position: .position
  }' 2>/dev/null)

# Get resolved conversation thread IDs
# GitHub API doesn't directly tell us if a review comment is resolved,
# but we can check the review threads
RESOLVED_THREADS=$(gh api graphql -f query='
  query($owner: String!, $repo: String!, $pr: Int!) {
    repository(owner: $owner, name: $repo) {
      pullRequest(number: $pr) {
        reviewThreads(first: 100) {
          nodes {
            isResolved
            comments(first: 100) {
              nodes {
                databaseId
              }
            }
          }
        }
      }
    }
  }' -F owner="${REPO%%/*}" -F repo="${REPO##*/}" -F pr="$PR_NUMBER" \
  --jq '.data.repository.pullRequest.reviewThreads.nodes[] | select(.isResolved) | .comments.nodes[].databaseId' 2>/dev/null || echo "")

# Convert resolved thread IDs to a format we can use for filtering
RESOLVED_IDS=""
if [[ -n "$RESOLVED_THREADS" ]]; then
    RESOLVED_IDS=$(echo "$RESOLVED_THREADS" | paste -sd '|' -)
fi

# Process and filter comments
UNRESOLVED_COMMENTS=""
if [[ -n "$REVIEW_COMMENTS" ]]; then
    while IFS= read -r comment_json; do
        if [[ -z "$comment_json" ]]; then
            continue
        fi
        
        # Parse JSON fields
        comment_id=$(echo "$comment_json" | jq -r '.id')
        
        # Skip if this comment is in a resolved thread
        if [[ -n "$RESOLVED_IDS" ]] && echo "$comment_id" | grep -qE "^($RESOLVED_IDS)$"; then
            continue
        fi
        
        # Extract comment details
        user=$(echo "$comment_json" | jq -r '.user')
        path=$(echo "$comment_json" | jq -r '.path')
        line=$(echo "$comment_json" | jq -r '.line')
        body=$(echo "$comment_json" | jq -r '.body')
        
        # Build comment output
        if [[ "$COMPACT_MODE" == "true" ]]; then
            # Compact format: single line per comment
            body_compact=$(echo "$body" | tr '\n' ' ' | sed 's/  */ /g')
            comment_line="@$user [CID=$comment_id] $path#L$line: $body_compact"
        else
            # Standard format
            comment_line="@$user on $path#L$line (ID: $comment_id)
   $body"
        fi
        
        # Append to unresolved comments
        if [[ -z "$UNRESOLVED_COMMENTS" ]]; then
            UNRESOLVED_COMMENTS="$comment_line"
        else
            if [[ "$COMPACT_MODE" == "true" ]]; then
                UNRESOLVED_COMMENTS="$UNRESOLVED_COMMENTS
$comment_line"
            else
                UNRESOLVED_COMMENTS="$UNRESOLVED_COMMENTS

$comment_line"
            fi
        fi
    done <<< "$(echo "$REVIEW_COMMENTS" | jq -c '.')"
fi

# Check if any unresolved comments were found
if [[ -z "$UNRESOLVED_COMMENTS" ]]; then
    echo "No unresolved code review comments found for PR #$PR_NUMBER"
    exit 0
fi

# Display unresolved comments
echo "=== Unresolved Code Review Comments ==="
echo "$UNRESOLVED_COMMENTS"

# Count unresolved comments
UNRESOLVED_COUNT=$(echo "$UNRESOLVED_COMMENTS" | grep -c '@' 2>/dev/null || echo "0")

echo ""
echo "---"
echo "Summary: $UNRESOLVED_COUNT unresolved code review comment(s)"

# Tips for interactive use
if [[ -t 1 ]] && [[ "$COMPACT_MODE" != "true" ]]; then
    if [[ "$UNRESOLVED_COUNT" -gt 0 ]]; then
        echo ""
        echo "Tips:"
        echo "  • View in browser: gh pr view $PR_NUMBER --web"
        echo "  • Reply to comment: ./scripts/reply-to-comment.sh <COMMENT_ID> <MESSAGE>"
        echo "  • Mark as resolved: Use GitHub web interface"
    fi
fi