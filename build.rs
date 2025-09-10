use std::process::Command;
use std::env;

fn main() {
    // Retrieve crate version provided by Cargo
    let version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".to_string());

    // Try to get short commit hash
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| if o.status.success() {
            Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
        } else {
            None
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Export as environment variables for use in the code and tests
    println!("cargo:rustc-env=GIT_HASH={}", git_hash);
    println!("cargo:rustc-env=VERSION_WITH_GIT_HASH={} ({})", version, git_hash);
}
