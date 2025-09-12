//! Docker container execution with httpjail network isolation

use anyhow::{Context, Result};
use std::path::Path;
use std::process::{Child, Command, ExitStatus};
use tracing::{debug, info, warn};

/// A wrapper around Child that kills the process on drop
struct NamespaceHolder {
    child: Child,
    namespace_name: String,
}

impl NamespaceHolder {
    fn new(child: Child, namespace_name: String) -> Self {
        Self {
            child,
            namespace_name,
        }
    }
}

impl Drop for NamespaceHolder {
    fn drop(&mut self) {
        debug!("Cleaning up namespace holder for {}", self.namespace_name);
        self.child.kill().ok();
        self.child.wait().ok();

        // Clean up the Docker namespace mount if it exists
        let docker_ns_path = format!("/var/run/docker/netns/{}", self.namespace_name);
        if Path::new(&docker_ns_path).exists() {
            Command::new("umount").arg(&docker_ns_path).status().ok();
            std::fs::remove_file(&docker_ns_path).ok();
            debug!(
                "Cleaned up Docker namespace mount for {}",
                self.namespace_name
            );
        }
    }
}

/// Execute Docker container with httpjail network isolation
///
/// This function:
/// 1. Ensures the network namespace created by httpjail is accessible to Docker
/// 2. Modifies the docker run command to use our network namespace
/// 3. Executes the container and returns its exit status
#[cfg(target_os = "linux")]
pub async fn execute_docker_run(
    jail_id: &str,
    docker_args: &[String],
    extra_env: &[(String, String)],
) -> Result<ExitStatus> {
    info!("Setting up Docker container with httpjail network isolation");

    let namespace_name = format!("httpjail_{}", jail_id);

    // Ensure the namespace is accessible to Docker
    // The holder will automatically clean up when dropped
    let _namespace_holder = ensure_namespace_mounted(&namespace_name)?;

    // Build and execute the docker command
    let mut cmd = build_docker_command(&namespace_name, docker_args, extra_env)?;

    info!(
        "Executing docker run with network namespace {}",
        namespace_name
    );
    debug!("Docker command: {:?}", cmd);

    // Execute docker run and wait for it to complete
    let status = cmd
        .status()
        .context("Failed to execute docker run command")?;

    // The namespace holder will be automatically cleaned up on drop

    Ok(status)
}

/// Ensure there's a process in the namespace and it's visible to Docker
/// Returns a holder that keeps the process alive
#[cfg(target_os = "linux")]
fn ensure_namespace_mounted(namespace_name: &str) -> Result<Option<NamespaceHolder>> {
    // The namespace should already exist from the strong jail setup
    // We need to ensure there's a process in it and make it visible to Docker
    debug!("Setting up namespace {} for Docker", namespace_name);

    // Start a minimal process in the namespace that will keep it alive
    // We use sleep infinity which uses minimal resources
    let namespace_holder = Command::new("ip")
        .args([
            "netns",
            "exec",
            namespace_name,
            "sh",
            "-c",
            "exec sleep infinity",
        ])
        .spawn()
        .context("Failed to spawn holder process in namespace")?;

    let holder_pid = namespace_holder.id();
    debug!(
        "Started holder process {} in namespace {}",
        holder_pid, namespace_name
    );

    // Docker looks for namespaces in /var/run/docker/netns, not /var/run/netns
    // We need to make our namespace visible there
    let docker_netns_dir = Path::new("/var/run/docker/netns");
    if !docker_netns_dir.exists() {
        std::fs::create_dir_all(docker_netns_dir)
            .context("Failed to create Docker netns directory")?;
    }

    let docker_ns_path = format!("/var/run/docker/netns/{}", namespace_name);
    let system_ns_path = format!("/var/run/netns/{}", namespace_name);

    // Create a bind mount from the system namespace to Docker's directory
    if !Path::new(&docker_ns_path).exists() {
        // Create the target file
        std::fs::File::create(&docker_ns_path)
            .context("Failed to create Docker namespace mount point")?;

        // Bind mount the existing namespace to Docker's directory
        let mount_status = Command::new("mount")
            .args(["--bind", &system_ns_path, &docker_ns_path])
            .status()
            .context("Failed to bind mount namespace to Docker directory")?;

        if !mount_status.success() {
            // Clean up on failure
            std::fs::remove_file(&docker_ns_path).ok();
            anyhow::bail!("Failed to make namespace visible to Docker");
        }

        debug!(
            "Made namespace {} visible to Docker at {}",
            namespace_name, docker_ns_path
        );
    }

    Ok(Some(NamespaceHolder::new(
        namespace_holder,
        namespace_name.to_string(),
    )))
}

/// Build the docker command with network namespace and environment variables
#[cfg(target_os = "linux")]
fn build_docker_command(
    namespace_name: &str,
    docker_args: &[String],
    extra_env: &[(String, String)],
) -> Result<Command> {
    // Parse docker arguments to check if --network is already specified
    let modified_args = filter_network_args(docker_args);

    // Build the docker run command
    let mut cmd = Command::new("docker");
    cmd.arg("run");

    // Add our network namespace (using Docker's netns directory)
    cmd.args([
        "--network",
        &format!("ns:/var/run/docker/netns/{}", namespace_name),
    ]);

    // Add CA certificate environment variables
    for (key, value) in extra_env {
        cmd.arg("-e").arg(format!("{}={}", key, value));
    }

    // Add all the user's docker arguments
    for arg in &modified_args {
        cmd.arg(arg);
    }

    Ok(cmd)
}

/// Filter out any existing --network arguments from docker args
#[cfg(target_os = "linux")]
fn filter_network_args(docker_args: &[String]) -> Vec<String> {
    let mut modified_args = Vec::new();
    let mut i = 0;

    while i < docker_args.len() {
        if docker_args[i] == "--network" || docker_args[i].starts_with("--network=") {
            warn!("Docker --network flag already specified, overriding with httpjail namespace");

            if docker_args[i] == "--network" {
                // Skip the next argument too
                i += 2;
                continue;
            }
        } else {
            modified_args.push(docker_args[i].clone());
        }
        i += 1;
    }

    modified_args
}

/// Stub implementation for non-Linux platforms
#[cfg(not(target_os = "linux"))]
pub async fn execute_docker_run(
    _jail_id: &str,
    _docker_args: &[String],
    _extra_env: &[(String, String)],
) -> Result<ExitStatus> {
    anyhow::bail!("--docker-run is only supported on Linux")
}
