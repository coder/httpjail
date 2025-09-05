use anyhow::Result;

/// Trait for system resources that can be created, cleaned up, and automatically
/// cleaned up on drop. Each resource type knows how to derive its system identifiers
/// from a jail_id.
///
/// All implementors should also implement Drop to ensure automatic cleanup.
pub trait SystemResource {
    /// Create and acquire the resource for a new jail
    fn create(jail_id: &str) -> Result<Self>
    where
        Self: Sized;

    /// Explicitly clean up the resource
    fn cleanup(&mut self) -> Result<()>;

    /// Create a handle for an existing resource (for orphan cleanup)
    /// This doesn't create the resource, just a handle that will clean it up on drop
    fn for_existing(jail_id: &str) -> Self
    where
        Self: Sized;
}
