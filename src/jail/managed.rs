use super::{Jail, JailConfig};
use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime};
use tracing::{debug, error, info, warn};

use crate::jail::get_canary_dir;

/// Manages jail lifecycle and cleanup with automatic cleanup on drop
pub struct ManagedJail<J: crate::jail::Jail> {
    jail: J,
    jail_id: String,
    canary_path: PathBuf,
    no_cleanup: bool,
}

impl<J: crate::jail::Jail> ManagedJail<J> {
    pub fn new(mut jail: J, config: &JailConfig, no_cleanup: bool) -> Result<Self> {
        let jail_id = config.jail_id.clone();

        // Create canary file to track jail lifetime
        let canary_dir = get_canary_dir();
        std::fs::create_dir_all(&canary_dir).ok();
        let canary_path = canary_dir.join(&config.jail_id);

        Ok(Self {
            jail,
            jail_id,
            canary_path,
            no_cleanup,
        })
    }

    /// Public method to trigger orphan cleanup for debugging
    pub fn debug_cleanup_orphans(&self) -> Result<()> {
        self.cleanup_orphans()
    }

    /// Scan and cleanup orphaned jails before setup
    fn cleanup_orphans(&self) -> Result<()> {
        debug!("Starting orphan cleanup scan in {:?}", self.canary_dir);

        // Create directory if it doesn't exist
        if !self.canary_dir.exists() {
            debug!("Canary directory does not exist, creating it");
            fs::create_dir_all(&self.canary_dir).context("Failed to create canary directory")?;
            return Ok(());
        }

        // Scan for stale canary files
        for entry in fs::read_dir(&self.canary_dir)? {
            let entry = entry?;
            let path = entry.path();

            // Skip if not a file
            if !path.is_file() {
                continue;
            }

            // Check file age using modification time (mtime) for broader fs support
            let metadata = fs::metadata(&path)?;
            let modified = metadata
                .modified()
                .context("Failed to get file modification time")?;
            let age = SystemTime::now()
                .duration_since(modified)
                .unwrap_or(Duration::from_secs(0));

            // If file is older than orphan timeout, clean it up
            if age > self.orphan_timeout {
                let jail_id = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");

                info!(
                    "Found orphaned jail '{}' (age: {:?}), cleaning up",
                    jail_id, age
                );

                // Call platform-specific cleanup
                J::cleanup_orphaned(jail_id)
                    .context(format!("Failed to cleanup orphaned jail '{}'", jail_id))?;

                // Remove canary file after cleanup attempt.
                // The sequence here is critical. We never delete the canary unless we're
                // certain that the system resources are cleaned up.
                if let Err(e) = fs::remove_file(&path) {
                    error!("Failed to remove orphaned canary file: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Start the heartbeat thread
    fn start_heartbeat(&mut self) -> Result<()> {
        if !self.enable_heartbeat {
            return Ok(());
        }

        // Create canary file first
        self.create_canary()?;

        // Setup heartbeat thread
        let canary_path = self.canary_path.clone();
        let interval = self.heartbeat_interval;
        let stop_flag = self.stop_heartbeat.clone();

        let handle = thread::spawn(move || {
            debug!("Starting heartbeat thread for {:?}", canary_path);

            while !stop_flag.load(Ordering::Relaxed) {
                // Touch the canary file (update mtime only)
                if let Err(e) = touch_file_mtime(&canary_path) {
                    warn!("Failed to touch canary file: {}", e);
                }

                // Sleep for the interval
                thread::sleep(interval);
            }

            debug!("Heartbeat thread stopped for {:?}", canary_path);
        });

        self.heartbeat_handle = Some(handle);
        info!(
            "Started lifecycle heartbeat for jail '{}'",
            self.jail.jail_id()
        );

        Ok(())
    }

    /// Stop the heartbeat thread
    fn stop_heartbeat(&mut self) -> Result<()> {
        if !self.enable_heartbeat {
            return Ok(());
        }

        // Signal thread to stop
        self.stop_heartbeat.store(true, Ordering::Relaxed);

        // Wait for thread to finish
        if let Some(handle) = self.heartbeat_handle.take() {
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("Failed to join heartbeat thread"))?;
        }

        debug!("Stopped heartbeat for jail '{}'", self.jail.jail_id());
        Ok(())
    }

    /// Signal the heartbeat thread to stop without joining
    /// Use this when we only have `&self` (e.g., during Jail::cleanup)
    fn signal_stop_heartbeat(&self) {
        if self.enable_heartbeat {
            self.stop_heartbeat.store(true, Ordering::Relaxed);
        }
    }

    /// Create the canary file
    fn create_canary(&self) -> Result<()> {
        // Ensure directory exists
        if !self.canary_dir.exists() {
            fs::create_dir_all(&self.canary_dir).context("Failed to create canary directory")?;
        }

        // Create empty canary file
        fs::write(&self.canary_path, b"").context("Failed to create canary file")?;

        debug!("Created canary file for jail '{}'", self.jail.jail_id());
        Ok(())
    }

    /// Delete the canary file
    fn delete_canary(&self) -> Result<()> {
        if self.canary_path.exists() {
            fs::remove_file(&self.canary_path).context("Failed to remove canary file")?;
            debug!("Deleted canary file for jail '{}'", self.jail.jail_id());
        }
        Ok(())
    }
}

/// Touch a file to update its modification time only (not access time)
/// This provides broader filesystem support as some filesystems don't track atime
fn touch_file_mtime(path: &PathBuf) -> Result<()> {
    if path.exists() {
        // Get current access time to preserve it
        let metadata = fs::metadata(path)?;
        let atime = metadata.accessed().unwrap_or_else(|_| SystemTime::now());

        // Update modification time to now, preserve access time
        let mtime = SystemTime::now();
        filetime::set_file_times(
            path,
            filetime::FileTime::from_system_time(atime),
            filetime::FileTime::from_system_time(mtime),
        )?;
    } else {
        // Create empty file if it doesn't exist
        fs::write(path, b"")?;
    }
    Ok(())
}

impl<J: Jail> Jail for ManagedJail<J> {
    fn setup(&mut self, proxy_port: u16) -> Result<()> {
        // Cleanup orphans first
        if self.enable_heartbeat {
            self.cleanup_orphans()?;
        }

        // Setup the inner jail
        self.jail.setup(proxy_port)?;

        // Start heartbeat after successful setup
        self.start_heartbeat()?;

        Ok(())
    }

    fn execute(&self, command: &[String], extra_env: &[(String, String)]) -> Result<ExitStatus> {
        // Simply delegate to the inner jail
        self.jail.execute(command, extra_env)
    }

    fn cleanup(&self) -> Result<()> {
        // Signal the heartbeat to stop so it doesn't recreate the canary
        self.signal_stop_heartbeat();

        // Cleanup the inner jail first
        let result = self.jail.cleanup();

        // Delete canary last
        if self.enable_heartbeat {
            self.delete_canary()?;
        }

        result
    }

    fn jail_id(&self) -> &str {
        self.jail.jail_id()
    }

    fn cleanup_orphaned(jail_id: &str) -> Result<()>
    where
        Self: Sized,
    {
        J::cleanup_orphaned(jail_id)
    }
}

impl<J: Jail> Drop for ManagedJail<J> {
    fn drop(&mut self) {
        // Best effort cleanup
        let _ = self.stop_heartbeat();
        if self.enable_heartbeat {
            let _ = self.delete_canary();
        }
    }
}