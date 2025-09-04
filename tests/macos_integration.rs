mod common;
mod system_integration;

#[macro_use]
mod platform_test_macro;

#[cfg(target_os = "macos")]
mod tests {
    use super::*;

    /// macOS-specific platform implementation
    struct MacOSPlatform;

    impl system_integration::JailTestPlatform for MacOSPlatform {
        fn require_privileges() {
            // Check if running as root
            let uid = unsafe { libc::geteuid() };
            if uid != 0 {
                eprintln!("\n⚠️  Test requires root privileges.");
                eprintln!("   Run with: sudo cargo test --test macos_integration");
                eprintln!("   Or use the SUDO_ASKPASS helper:");
                eprintln!("   SUDO_ASKPASS=$(pwd)/askpass_macos.sh sudo -A cargo test\n");
                panic!("Test skipped: requires root privileges");
            }
        }

        fn platform_name() -> &'static str {
            "macOS"
        }

        fn supports_https_interception() -> bool {
            true // macOS with PF supports transparent TLS interception
        }
    }

    // Generate all the shared platform tests
    platform_tests!(MacOSPlatform);

    // macOS-specific tests can be added here if needed
}
