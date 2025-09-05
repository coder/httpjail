use super::{Jail, JailConfig};
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};
use tracing::{debug, error, info, warn};

/// Manages jail lifecycle including heartbeat and orphan cleanup
struct JailLifecycleManager {
    jail_id: String,
    canary_dir: PathBuf,
    canary_path: PathBuf,
    heartbeat_interval: Duration,
    orphan_timeout: Duration,

    // Heartbeat control
    stop_heartbeat: Arc<AtomicBool>,
    heartbeat_handle: Option<JoinHandle<()>>,
}

impl JailLifecycleManager {
    /// Create a new lifecycle manager for a jail
    pub fn new(
        jail_id: String,
        heartbeat_interval_secs: u64,
        orphan_timeout_secs: u64,
    ) -> Result<Self> {
        let canary_dir = PathBuf::from("/tmp/httpjail");
        let canary_path = canary_dir.join(&jail_id);

        Ok(Self {
            jail_id,
            canary_dir,
            canary_path,
            heartbeat_interval: Duration::from_secs(heartbeat_interval_secs),
            orphan_timeout: Duration::from_secs(orphan_timeout_secs),
            stop_heartbeat: Arc::new(AtomicBool::new(false)),
            heartbeat_handle: None,
        })
    }

    /// Scan and cleanup orphaned jails before setup
    pub fn cleanup_orphans<F>(&self, cleanup_fn: F) -> Result<()>
    where
        F: Fn(&str) -> Result<()>,
    {
        // Create directory if it doesn't exist
        if !self.canary_dir.exists() {
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

            // Check file age using access time
            let metadata = fs::metadata(&path)?;
            let accessed = metadata
                .accessed()
                .context("Failed to get file access time")?;
            let age = SystemTime::now()
                .duration_since(accessed)
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
                cleanup_fn(jail_id)
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
    pub fn start_heartbeat(&mut self) -> Result<()> {
        // Create canary file first
        self.create_canary()?;

        // Setup heartbeat thread
        let canary_path = self.canary_path.clone();
        let interval = self.heartbeat_interval;
        let stop_flag = self.stop_heartbeat.clone();

        let handle = thread::spawn(move || {
            debug!("Starting heartbeat thread for {:?}", canary_path);

            while !stop_flag.load(Ordering::Relaxed) {
                // Touch the canary file
                if let Err(e) = touch_file(&canary_path) {
                    warn!("Failed to touch canary file: {}", e);
                }

                // Sleep for the interval
                thread::sleep(interval);
            }

            debug!("Heartbeat thread stopped for {:?}", canary_path);
        });

        self.heartbeat_handle = Some(handle);
        info!("Started lifecycle heartbeat for jail '{}'", self.jail_id);

        Ok(())
    }

    /// Stop the heartbeat thread
    pub fn stop_heartbeat(&mut self) -> Result<()> {
        // Signal thread to stop
        self.stop_heartbeat.store(true, Ordering::Relaxed);

        // Wait for thread to finish
        if let Some(handle) = self.heartbeat_handle.take() {
            handle
                .join()
                .map_err(|_| anyhow::anyhow!("Failed to join heartbeat thread"))?;
        }

        debug!("Stopped heartbeat for jail '{}'", self.jail_id);
        Ok(())
    }

    /// Create the canary file
    pub fn create_canary(&self) -> Result<()> {
        // Ensure directory exists
        if !self.canary_dir.exists() {
            fs::create_dir_all(&self.canary_dir).context("Failed to create canary directory")?;
        }

        // Create empty canary file
        fs::write(&self.canary_path, b"").context("Failed to create canary file")?;

        debug!("Created canary file for jail '{}'", self.jail_id);
        Ok(())
    }

    /// Delete the canary file
    pub fn delete_canary(&self) -> Result<()> {
        if self.canary_path.exists() {
            fs::remove_file(&self.canary_path).context("Failed to remove canary file")?;
            debug!("Deleted canary file for jail '{}'", self.jail_id);
        }
        Ok(())
    }
}

impl Drop for JailLifecycleManager {
    fn drop(&mut self) {
        // Best effort cleanup
        let _ = self.stop_heartbeat();
        let _ = self.delete_canary();
    }
}

/// Touch a file to update its access and modification times
fn touch_file(path: &Path) -> Result<()> {
    if path.exists() {
        // Update access and modification times to now
        let now = std::time::SystemTime::now();
        filetime::set_file_times(
            path,
            filetime::FileTime::from_system_time(now),
            filetime::FileTime::from_system_time(now),
        )?;
    } else {
        // Create empty file if it doesn't exist
        fs::write(path, b"")?;
    }
    Ok(())
}

/// A jail with lifecycle management (heartbeat and orphan cleanup)
pub struct ManagedJail<J: Jail> {
    jail: J,
    lifecycle: Option<JailLifecycleManager>,
}

impl<J: Jail> ManagedJail<J> {
    /// Create a new managed jail
    pub fn new(jail: J, config: &JailConfig) -> Result<Self> {
        let lifecycle = if config.enable_heartbeat {
            Some(JailLifecycleManager::new(
                config.jail_id.clone(),
                config.heartbeat_interval_secs,
                config.orphan_timeout_secs,
            )?)
        } else {
            None
        };

        Ok(Self { jail, lifecycle })
    }
}

impl<J: Jail> Jail for ManagedJail<J> {
    fn setup(&mut self, proxy_port: u16) -> Result<()> {
        // Cleanup orphans first
        if let Some(ref lifecycle) = self.lifecycle {
            lifecycle.cleanup_orphans(|jail_id| J::cleanup_orphaned(jail_id))?;
        }

        // Setup the inner jail
        self.jail.setup(proxy_port)?;

        // Start heartbeat after successful setup
        if let Some(ref mut lifecycle) = self.lifecycle {
            lifecycle.start_heartbeat()?;
        }

        Ok(())
    }

    fn execute(&self, command: &[String], extra_env: &[(String, String)]) -> Result<ExitStatus> {
        // Simply delegate to the inner jail
        self.jail.execute(command, extra_env)
    }

    fn cleanup(&self) -> Result<()> {
        // Cleanup the inner jail first
        let result = self.jail.cleanup();

        // Delete canary last
        if let Some(ref lifecycle) = self.lifecycle {
            lifecycle.delete_canary()?;
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
