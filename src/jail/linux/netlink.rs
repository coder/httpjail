//! Network namespace operations using netlink instead of `ip` CLI
//!
//! This module provides direct syscall/netlink based alternatives to the `ip` command,
//! allowing httpjail to work in container environments (like sysbox) that have
//! CAP_SYS_ADMIN but don't include the iproute2 package.

use anyhow::{Context, Result};
use futures::stream::TryStreamExt;
use nix::mount::umount;
use nix::sched::{CloneFlags, setns};
use rtnetlink::{Handle, new_connection};
use std::fs;
use std::net::Ipv4Addr;
use std::os::unix::io::AsRawFd;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use tracing::debug;

const NETNS_RUN_DIR: &str = "/var/run/netns";

/// Create a named network namespace
///
/// This mimics `ip netns add <name>` by:
/// 1. Creating a new network namespace
/// 2. Bind-mounting it to /var/run/netns/<name> for persistence
pub fn create_netns(name: &str) -> Result<()> {
    let netns_path = PathBuf::from(NETNS_RUN_DIR).join(name);

    // Ensure /var/run/netns exists
    fs::create_dir_all(NETNS_RUN_DIR)
        .with_context(|| format!("Failed to create directory {}", NETNS_RUN_DIR))?;

    // Create an empty file to use as bind mount target
    fs::File::create(&netns_path)
        .with_context(|| format!("Failed to create namespace file {:?}", netns_path))?;

    // Fork to create the namespace, then bind mount it
    unsafe {
        match libc::fork() {
            -1 => anyhow::bail!("fork() failed: {}", std::io::Error::last_os_error()),
            0 => {
                // Child process
                // Create new network namespace
                if libc::unshare(libc::CLONE_NEWNET) != 0 {
                    libc::_exit(1);
                }

                // Bind mount our namespace to the file
                let source = b"/proc/self/ns/net\0";
                let target = format!("{}\0", netns_path.display());
                let result = libc::mount(
                    source.as_ptr() as *const libc::c_char,
                    target.as_ptr() as *const libc::c_char,
                    std::ptr::null(),
                    libc::MS_BIND,
                    std::ptr::null(),
                );

                if result != 0 {
                    libc::_exit(1);
                }

                libc::_exit(0);
            }
            child_pid => {
                // Parent process - wait for child
                let mut status: libc::c_int = 0;
                if libc::waitpid(child_pid, &mut status, 0) == -1 {
                    let _ = fs::remove_file(&netns_path);
                    anyhow::bail!("waitpid() failed: {}", std::io::Error::last_os_error());
                }

                if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
                    let _ = fs::remove_file(&netns_path);
                    anyhow::bail!("Failed to create network namespace");
                }
            }
        }
    }

    debug!("Created network namespace: {}", name);
    Ok(())
}

/// Delete a named network namespace
///
/// This mimics `ip netns del <name>` by unmounting and removing the namespace file
pub fn delete_netns(name: &str) -> Result<()> {
    let netns_path = PathBuf::from(NETNS_RUN_DIR).join(name);

    if !netns_path.exists() {
        debug!("Namespace {} does not exist, nothing to delete", name);
        return Ok(());
    }

    // Unmount the namespace
    if let Err(e) = umount(&netns_path) {
        // If already unmounted, that's fine
        debug!("umount failed (may already be unmounted): {}", e);
    }

    // Remove the file
    fs::remove_file(&netns_path)
        .with_context(|| format!("Failed to remove namespace file {:?}", netns_path))?;

    debug!("Deleted network namespace: {}", name);
    Ok(())
}

/// Create a veth pair (mimics `ip link add <name1> type veth peer name <name2>`)
pub async fn create_veth_pair(name1: &str, name2: &str) -> Result<()> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);
    handle
        .link()
        .add()
        .veth(name1.to_string(), name2.to_string())
        .execute()
        .await
        .with_context(|| format!("Failed to create veth pair {} <-> {}", name1, name2))?;
    debug!("Created veth pair: {} <-> {}", name1, name2);
    Ok(())
}

/// Move a network interface into a namespace (mimics `ip link set <interface> netns <namespace>`)
pub async fn move_link_to_netns(interface: &str, netns_name: &str) -> Result<()> {
    let netns_path = PathBuf::from(NETNS_RUN_DIR).join(netns_name);
    let netns_fd = fs::File::open(&netns_path)
        .with_context(|| format!("Failed to open namespace {:?}", netns_path))?;

    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);
    let idx = get_link_index(&handle, interface).await?;
    handle
        .link()
        .set(idx)
        .setns_by_fd(netns_fd.as_raw_fd())
        .execute()
        .await
        .with_context(|| format!("Failed to move {} to namespace {}", interface, netns_name))?;
    debug!("Moved interface {} to namespace {}", interface, netns_name);
    Ok(())
}

/// Get link index by name
async fn get_link_index(handle: &Handle, interface: &str) -> Result<u32> {
    let mut links = handle
        .link()
        .get()
        .match_name(interface.to_string())
        .execute();
    links
        .try_next()
        .await?
        .map(|link| link.header.index)
        .ok_or_else(|| anyhow::anyhow!("Interface {} not found", interface))
}

/// Set an interface up or down (mimics `ip link set <interface> up/down`)
pub async fn set_link_up(handle: &Handle, interface: &str, up: bool) -> Result<()> {
    let idx = get_link_index(handle, interface).await?;
    let req = handle.link().set(idx);
    if up {
        req.up().execute().await?;
        debug!("Set interface {} up", interface);
    } else {
        req.down().execute().await?;
        debug!("Set interface {} down", interface);
    }
    Ok(())
}

/// Add an IP address to an interface (mimics `ip addr add <addr>/<prefix> dev <interface>`)
pub async fn add_addr(
    handle: &Handle,
    interface: &str,
    addr: Ipv4Addr,
    prefix_len: u8,
) -> Result<()> {
    let idx = get_link_index(handle, interface).await?;
    handle
        .address()
        .add(idx, addr.into(), prefix_len)
        .execute()
        .await
        .with_context(|| {
            format!(
                "Failed to add address {}/{} to {}",
                addr, prefix_len, interface
            )
        })?;
    debug!("Added address {}/{} to {}", addr, prefix_len, interface);
    Ok(())
}

/// Add a default route (mimics `ip route add default via <gateway>`)
pub async fn add_default_route(handle: &Handle, gateway: Ipv4Addr) -> Result<()> {
    handle
        .route()
        .add()
        .v4()
        .gateway(gateway)
        .execute()
        .await
        .context("Failed to add default route")?;
    debug!("Added default route via {}", gateway);
    Ok(())
}

/// Delete a link (mimics `ip link del <interface>`)
pub async fn delete_link(interface: &str) -> Result<()> {
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);
    match get_link_index(&handle, interface).await {
        Ok(idx) => {
            handle
                .link()
                .del(idx)
                .execute()
                .await
                .with_context(|| format!("Failed to delete interface {}", interface))?;
            debug!("Deleted interface {}", interface);
        }
        Err(_) => {
            debug!("Interface {} not found, nothing to delete", interface);
        }
    }
    Ok(())
}

/// Get a netlink handle connected to a specific namespace
pub async fn get_handle_in_netns(name: &str) -> Result<Handle> {
    let netns_path = PathBuf::from(NETNS_RUN_DIR).join(name);
    let netns_fd = fs::File::open(&netns_path)
        .with_context(|| format!("Failed to open namespace {:?}", netns_path))?;

    // Open current namespace to restore later
    let current_ns =
        fs::File::open("/proc/self/ns/net").context("Failed to open current network namespace")?;

    // Enter the target namespace
    setns(&netns_fd, CloneFlags::CLONE_NEWNET).context("Failed to enter namespace")?;

    // Create connection in this namespace
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    // Return to original namespace
    let _ = setns(&current_ns, CloneFlags::CLONE_NEWNET);

    Ok(handle)
}

/// Execute a command in a namespace (equivalent to `ip netns exec`)
///
/// This uses setns to enter the namespace and then fork/exec the command.
pub fn execute_in_netns(
    namespace_name: &str,
    command: &[String],
    extra_env: &[(String, String)],
    drop_privs: Option<(u32, u32)>, // (uid, gid)
) -> Result<std::process::ExitStatus> {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    if command.is_empty() {
        anyhow::bail!("No command specified");
    }

    let netns_path = PathBuf::from(NETNS_RUN_DIR).join(namespace_name);
    let netns_fd = std::fs::File::open(&netns_path)
        .with_context(|| format!("Failed to open namespace {:?}", netns_path))?;
    let netns_raw_fd = netns_fd.as_raw_fd();

    // Fork and exec in the namespace
    unsafe {
        match libc::fork() {
            -1 => anyhow::bail!("fork() failed: {}", std::io::Error::last_os_error()),
            0 => {
                // Child process
                // Enter the network namespace using raw libc call
                if libc::setns(netns_raw_fd, libc::CLONE_NEWNET) != 0 {
                    libc::_exit(127);
                }

                // Drop privileges if requested
                if let Some((uid, gid)) = drop_privs {
                    // Set GID first (must be done before dropping UID)
                    if libc::setgid(gid) != 0 {
                        libc::_exit(126);
                    }
                    // Initialize supplementary groups
                    if libc::setgroups(0, std::ptr::null()) != 0 {
                        libc::_exit(126);
                    }
                    // Set UID
                    if libc::setuid(uid) != 0 {
                        libc::_exit(126);
                    }
                }

                // Build command
                let mut cmd = Command::new(&command[0]);
                for arg in &command[1..] {
                    cmd.arg(arg);
                }

                // Set environment variables
                for (key, value) in extra_env {
                    cmd.env(key, value);
                }

                // Preserve SUDO environment variables
                if let Ok(sudo_user) = std::env::var("SUDO_USER") {
                    cmd.env("SUDO_USER", sudo_user);
                }
                if let Ok(sudo_uid) = std::env::var("SUDO_UID") {
                    cmd.env("SUDO_UID", sudo_uid);
                }
                if let Ok(sudo_gid) = std::env::var("SUDO_GID") {
                    cmd.env("SUDO_GID", sudo_gid);
                }

                // Execute (this replaces the current process)
                let err = cmd.exec();
                // If we get here, exec failed
                eprintln!("Failed to exec: {}", err);
                libc::_exit(127);
            }
            child_pid => {
                // Parent process - wait for child
                let mut status: libc::c_int = 0;
                if libc::waitpid(child_pid, &mut status, 0) == -1 {
                    anyhow::bail!("waitpid() failed: {}", std::io::Error::last_os_error());
                }

                // Convert status to ExitStatus
                if libc::WIFEXITED(status) {
                    let code = libc::WEXITSTATUS(status);
                    Ok(std::process::ExitStatus::from_raw(code << 8))
                } else if libc::WIFSIGNALED(status) {
                    let signal = libc::WTERMSIG(status);
                    Ok(std::process::ExitStatus::from_raw(signal))
                } else {
                    Ok(std::process::ExitStatus::from_raw(status))
                }
            }
        }
    }
}
