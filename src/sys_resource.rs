use anyhow::Result;
use tracing::error;

/// Trait for system resources that can be created, cleaned up, and automatically
/// cleaned up on drop. Each resource type knows how to derive its system identifiers
/// from a jail_id.
///
/// Use `ManagedResource<T>` to get automatic cleanup on drop.
///
/// # Important
///
/// The `cleanup()` method must be idempotent - it should be safe to call multiple times
/// and should internally track whether cleanup is needed.
pub trait SystemResource {
    /// Create and acquire the resource for a new jail
    fn create(jail_id: &str) -> Result<Self>
    where
        Self: Sized;

    /// Clean up the resource. This method must be idempotent - safe to call multiple times.
    /// Implementations should track internally whether cleanup is needed.
    fn cleanup(&mut self) -> Result<()>;

    /// Create a handle for an existing resource (for orphan cleanup)
    /// This doesn't create the resource, just a handle that will clean it up on drop
    fn for_existing(jail_id: &str) -> Self
    where
        Self: Sized;
}

/// Wrapper that provides automatic cleanup on drop for any SystemResource
pub struct ManagedResource<T: SystemResource> {
    resource: Option<T>,
}

impl<T: SystemResource> ManagedResource<T> {
    /// Create a new managed resource
    pub fn create(jail_id: &str) -> Result<Self> {
        Ok(Self {
            resource: Some(T::create(jail_id)?),
        })
    }

    /// Create a managed resource for an existing system resource (for cleanup)
    pub fn for_existing(jail_id: &str) -> Self {
        Self {
            resource: Some(T::for_existing(jail_id)),
        }
    }

    /// Wrap an already-created resource (for resources that need custom creation logic)
    pub fn from_resource(resource: T) -> Self {
        Self {
            resource: Some(resource),
        }
    }

    /// Get a reference to the inner resource
    pub fn inner(&self) -> Option<&T> {
        self.resource.as_ref()
    }

    /// Get a mutable reference to the inner resource
    pub fn inner_mut(&mut self) -> Option<&mut T> {
        self.resource.as_mut()
    }
}

impl<T: SystemResource> Drop for ManagedResource<T> {
    fn drop(&mut self) {
        if let Some(mut resource) = self.resource.take()
            && let Err(e) = resource.cleanup()
        {
            error!("Failed to cleanup resource on drop: {}", e);
        }
    }
}
