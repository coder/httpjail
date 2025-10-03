use std::env;
use std::process::Command;

fn main() {
    // Retrieve crate version provided by Cargo
    let version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".to_string());

    // Try to get short commit hash
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".to_string());

    // Export as environment variables for use in the code and tests
    println!("cargo:rustc-env=GIT_HASH={}", git_hash);
    println!(
        "cargo:rustc-env=VERSION_WITH_GIT_HASH={} ({})",
        version, git_hash
    );

    // Configure static linking for Linux gnu targets
    // Note: We use gnu (glibc) instead of musl because V8 doesn't provide prebuilt musl binaries
    // and building V8 from source for musl fails. Static glibc linking provides good portability
    // while still allowing us to use V8 prebuilt binaries.
    let target = env::var("TARGET").unwrap_or_default();
    if target.contains("linux") && target.contains("gnu") {
        // Enable static linking of the C runtime and standard library
        // This links glibc statically, adding ~2-5MB to binary size but improving portability
        println!("cargo:rustc-link-arg=-static-libgcc");

        // Note: Full static linking (-static) would break NSS/DNS, so we use crt-static instead
        // which is applied via RUSTFLAGS in the build process
    }
}
