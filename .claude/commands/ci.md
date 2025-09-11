Commit working changes and push them to CI

Run `cargo clippy -- -D warning` before pushing changes.

Enter loop where you wait for CI to complete, resolve issues,
and return to user once CI is green or a major decision is needed
to resolve it.
