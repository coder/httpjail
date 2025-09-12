//! Docker container execution with httpjail network isolation

use anyhow::{Context, Result};
use std::path::Path;
use std::process::{Command, ExitStatus};
use tracing::{debug, info, warn};

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
    ensure_namespace_mounted(&namespace_name)?;

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

    // Clean up the namespace mount point if we created it
    cleanup_namespace_mount(&namespace_name);

    Ok(status)
}

/// Ensure the network namespace is mounted and accessible to Docker
#[cfg(target_os = "linux")]
fn ensure_namespace_mounted(namespace_name: &str) -> Result<()> {
    // Ensure /var/run/netns directory exists
    let netns_dir = Path::new("/var/run/netns");
    if !netns_dir.exists() {
        std::fs::create_dir_all(netns_dir).context("Failed to create /var/run/netns directory")?;
    }

    // Check if namespace is already accessible
    let output = Command::new("ip")
        .args(["netns", "list"])
        .output()
        .context("Failed to list network namespaces")?;

    let namespaces = String::from_utf8_lossy(&output.stdout);
    if namespaces.contains(namespace_name) {
        debug!("Namespace {} already mounted", namespace_name);
        return Ok(());
    }

    // Mount the namespace for Docker access
    mount_namespace(namespace_name)?;

    Ok(())
}

/// Mount the namespace to /var/run/netns for Docker access
#[cfg(target_os = "linux")]
fn mount_namespace(namespace_name: &str) -> Result<()> {
    debug!("Mounting namespace {} to /var/run/netns", namespace_name);

    let namespace_path = format!("/var/run/netns/{}", namespace_name);

    // Create the mount point file
    std::fs::File::create(&namespace_path).context("Failed to create namespace mount point")?;

    // Find the PID of any process already running in the namespace
    // httpjail keeps a process alive in the namespace, so we can use that
    let output = Command::new("ip")
        .args(["netns", "pids", namespace_name])
        .output()
        .context("Failed to get PIDs in namespace")?;

    if !output.status.success() {
        anyhow::bail!(
            "Failed to get PIDs from namespace: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let pids_str = String::from_utf8_lossy(&output.stdout);
    let first_pid = pids_str
        .lines()
        .next()
        .and_then(|line| line.trim().parse::<u32>().ok())
        .context("No process found in namespace")?;

    let proc_ns = format!("/proc/{}/ns/net", first_pid);

    // Verify the namespace file exists
    if !Path::new(&proc_ns).exists() {
        anyhow::bail!("Namespace file {} does not exist", proc_ns);
    }

    // Bind mount the namespace
    let mount_status = Command::new("mount")
        .args(["--bind", &proc_ns, &namespace_path])
        .status()
        .context("Failed to bind mount namespace")?;

    if !mount_status.success() {
        // Clean up the mount point if mount failed
        std::fs::remove_file(&namespace_path).ok();
        anyhow::bail!("Failed to bind mount namespace");
    }

    debug!(
        "Mounted namespace at {} using PID {}",
        namespace_path, first_pid
    );

    Ok(())
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

    // Add our network namespace
    cmd.args([
        "--network",
        &format!("ns:/var/run/netns/{}", namespace_name),
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

/// Clean up the namespace mount point
#[cfg(target_os = "linux")]
fn cleanup_namespace_mount(namespace_name: &str) {
    let namespace_path = format!("/var/run/netns/{}", namespace_name);

    if Path::new(&namespace_path).exists() {
        Command::new("umount").arg(&namespace_path).status().ok();
        std::fs::remove_file(&namespace_path).ok();
        debug!("Cleaned up namespace mount at {}", namespace_path);
    }
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
