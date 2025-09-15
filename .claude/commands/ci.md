Commit working changes and push them to CI

Run `cargo clippy -- -D warnings` before pushing changes.

Also fetch the latest version of the base branch and merge it into the current branch.

Enter loop where you wait for CI to complete using `./scripts/wait-pr-checks.sh` 
(auto-detects PR from current branch), resolve issues, and return to user once 
CI is green or a major decision is needed to resolve it.
