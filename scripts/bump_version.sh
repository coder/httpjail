#!/bin/bash
set -euo pipefail

# Parse arguments
BUMP_TYPE="patch"
if [[ "${1:-}" == "--minor" ]]; then
    BUMP_TYPE="minor"
fi

# Get current version from Cargo.toml
CURRENT_VERSION=$(grep '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')

# Parse version components
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"

# Calculate new version
if [[ "$BUMP_TYPE" == "minor" ]]; then
    NEW_VERSION="$MAJOR.$((MINOR + 1)).0"
else
    NEW_VERSION="$MAJOR.$MINOR.$((PATCH + 1))"
fi

TAG="v$NEW_VERSION"

echo "Bumping version from $CURRENT_VERSION to $NEW_VERSION"

# Update version in Cargo.toml
sed -i.bak "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml
rm Cargo.toml.bak

# Update Cargo.lock
cargo update --workspace

# Create commit
git add Cargo.toml Cargo.lock
git commit -m "$TAG"

# Create tag
git tag "$TAG"

echo "Version bumped to $NEW_VERSION"
echo "Commit and tag '$TAG' created locally"
echo "To push: git push && git push --tags"