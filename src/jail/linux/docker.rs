//! Docker container execution wrapped in Linux jail network isolation

use super::LinuxJail;
use crate::jail::{Jail, JailConfig};
use crate::sys_resource::{ManagedResource, SystemResource};
use anyhow::{Context, Result};
use std::process::{Command, ExitStatus};
use tracing::{debug, info, warn};

/// Docker network resource that gets cleaned up on drop
struct DockerNetwork {
    network_name: String,
}

/// Docker routing nftables resource that gets cleaned up on drop
struct DockerRoutingTable {
    jail_id: String,
    table_name: String,
}

impl SystemResource for DockerRoutingTable {
    fn create(jail_id: &str) -> Result<Self> {
        let table_name = format!("httpjail_docker_{}", jail_id);
        Ok(Self {
            jail_id: jail_id.to_string(),
            table_name,
        })
    }

    fn cleanup(&mut self) -> Result<()> {
        debug!("Cleaning up Docker routing table: {}", self.table_name);

        let output = Command::new("nft")
            .args(["delete", "table", "ip", &self.table_name])
            .output()
            .context("Failed to delete Docker routing table")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("No such file or directory") && !stderr.contains("does not exist") {
                warn!("Failed to delete Docker routing table: {}", stderr);
            } else {
                debug!("Docker routing table {} already removed", self.table_name);
            }
        } else {
            info!("Removed Docker routing table {}", self.table_name);
        }

        Ok(())
    }

    fn for_existing(jail_id: &str) -> Self {
        let table_name = format!("httpjail_docker_{}", jail_id);
        Self {
            jail_id: jail_id.to_string(),
            table_name,
        }
    }
}

impl DockerNetwork {
    #[allow(dead_code)]
    fn new(jail_id: &str) -> Result<Self> {
        let network_name = format!("httpjail_{}", jail_id);
        Ok(Self { network_name })
    }
}

impl SystemResource for DockerNetwork {
    fn create(jail_id: &str) -> Result<Self> {
        let network_name = format!("httpjail_{}", jail_id);

        // Create Docker network with no default gateway (isolated)
        // Using a /24 subnet in the 172.20.x.x range
        let subnet = Self::compute_docker_subnet(jail_id);

        let output = Command::new("docker")
            .args([
                "network",
                "create",
                "--driver",
                "bridge",
                "--subnet",
                &subnet,
                "--opt",
                "com.docker.network.bridge.enable_ip_masquerade=false",
                &network_name,
            ])
            .output()
            .context("Failed to create Docker network")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("already exists") {
                info!("Docker network {} already exists", network_name);
            } else {
                anyhow::bail!("Failed to create Docker network: {}", stderr);
            }
        } else {
            info!(
                "Created Docker network {} with subnet {}",
                network_name, subnet
            );
        }

        Ok(Self { network_name })
    }

    fn cleanup(&mut self) -> Result<()> {
        debug!("Cleaning up Docker network: {}", self.network_name);

        let output = Command::new("docker")
            .args(["network", "rm", &self.network_name])
            .output()
            .context("Failed to remove Docker network")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("not found") {
                debug!("Docker network {} already removed", self.network_name);
            } else {
                warn!("Failed to remove Docker network: {}", stderr);
            }
        } else {
            info!("Removed Docker network {}", self.network_name);
        }

        Ok(())
    }

    fn for_existing(jail_id: &str) -> Self {
        let network_name = format!("httpjail_{}", jail_id);
        Self { network_name }
    }
}

impl DockerNetwork {
    /// Compute a unique Docker subnet for this jail (172.20.x.0/24)
    fn compute_docker_subnet(jail_id: &str) -> String {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        jail_id.hash(&mut hasher);
        let h = hasher.finish();
        let third_octet = ((h % 256) as u8).max(1); // 1-255
        format!("172.20.{}.0/24", third_octet)
    }

    /// Get the Docker bridge interface name for this network
    fn get_bridge_name(&self) -> Result<String> {
        let output = Command::new("docker")
            .args(["network", "inspect", &self.network_name, "-f", "{{.Id}}"])
            .output()
            .context("Failed to inspect Docker network")?;

        if !output.status.success() {
            anyhow::bail!("Failed to get Docker network ID");
        }

        let network_id = String::from_utf8_lossy(&output.stdout)
            .trim()
            .chars()
            .take(12)
            .collect::<String>();

        Ok(format!("br-{}", network_id))
    }
}

/// DockerLinux jail implementation that combines Docker containers with Linux jail isolation
///
/// This jail wraps the standard LinuxJail to provide network isolation for Docker containers.
/// Unlike the previous approach, this implementation:
///
/// 1. Creates a complete Linux jail with network namespace
/// 2. Creates an isolated Docker network with no default connectivity
/// 3. Uses nftables on the host to route traffic from Docker network to jail
/// 4. Runs containers in the isolated Docker network
///
/// The implementation reuses all LinuxJail networking, nftables, and resource management
/// while adding Docker-specific network creation and routing.
pub struct DockerLinux {
    /// The underlying Linux jail that provides network isolation
    inner_jail: LinuxJail,
    /// Configuration for the jail
    config: JailConfig,
    /// The Docker network resource
    docker_network: Option<ManagedResource<DockerNetwork>>,
    /// The Docker routing table resource
    docker_routing: Option<ManagedResource<DockerRoutingTable>>,
}

impl DockerLinux {
    /// Create a new DockerLinux jail
    pub fn new(config: JailConfig) -> Result<Self> {
        let inner_jail = LinuxJail::new(config.clone())?;
        Ok(Self {
            inner_jail,
            config,
            docker_network: None,
            docker_routing: None,
        })
    }

    /// Build the docker command with isolated network
    fn build_docker_command(
        &self,
        docker_args: &[String],
        extra_env: &[(String, String)],
    ) -> Result<Command> {
        let network_name = format!("httpjail_{}", self.config.jail_id);
        // Parse docker arguments to filter out conflicting options and find the image
        let modified_args = Self::filter_network_args(docker_args);

        // Find where the image name is in the args
        let mut image_idx = None;
        let mut skip_next = false;

        for (i, arg) in modified_args.iter().enumerate() {
            if skip_next {
                skip_next = false;
                continue;
            }

            // Skip known flags that take values
            if arg == "-e"
                || arg == "-v"
                || arg == "-p"
                || arg == "--name"
                || arg == "--entrypoint"
                || arg == "-w"
                || arg == "--user"
            {
                skip_next = true;
                continue;
            }

            // If it doesn't start with -, it's likely the image
            if !arg.starts_with('-') {
                image_idx = Some(i);
                break;
            }
        }

        let image_idx = image_idx.context("Could not find Docker image in arguments")?;

        // Split args into: docker options, image, and command
        let docker_opts = &modified_args[..image_idx];
        let image = &modified_args[image_idx];
        let user_command = if modified_args.len() > image_idx + 1 {
            &modified_args[image_idx + 1..]
        } else {
            &[]
        };

        // Build the docker run command
        let mut cmd = Command::new("docker");
        cmd.arg("run");

        // Use our isolated Docker network
        cmd.args(["--network", &network_name]);

        // Add CA certificate environment variables
        for (key, value) in extra_env {
            cmd.arg("-e").arg(format!("{}={}", key, value));
        }

        // Add user's docker options
        for opt in docker_opts {
            cmd.arg(opt);
        }

        // Add the image
        cmd.arg(image);

        // Add user command if provided
        for arg in user_command {
            cmd.arg(arg);
        }

        Ok(cmd)
    }

    /// Filter out any existing --network arguments from docker args
    fn filter_network_args(docker_args: &[String]) -> Vec<String> {
        let mut modified_args = Vec::new();
        let mut i = 0;

        while i < docker_args.len() {
            if docker_args[i] == "--network" || docker_args[i].starts_with("--network=") {
                info!("Overriding Docker --network flag with httpjail namespace");

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

    /// Setup nftables rules to route Docker network traffic to jail
    fn setup_docker_routing(&mut self) -> Result<()> {
        let docker_network = self
            .docker_network
            .as_ref()
            .context("Docker network not created")?;

        if let Some(network) = docker_network.inner() {
            let bridge_name = network.get_bridge_name()?;

            // Get the jail's veth host IP
            let host_ip = LinuxJail::compute_host_ip_for_jail_id(&self.config.jail_id);
            let host_ip_str = super::format_ip(host_ip);

            info!(
                "Setting up routing from Docker bridge {} to jail at {}",
                bridge_name, host_ip_str
            );

            // Add nftables rules to:
            // 1. Allow traffic from Docker network to jail's proxy ports
            // 2. DNAT HTTP/HTTPS traffic to the proxy
            let table_name = format!("httpjail_docker_{}", self.config.jail_id);

            // Create nftables rules
            let nft_rules = format!(
                "table ip {} {{
                    chain prerouting {{
                        type nat hook prerouting priority -100;
                        iifname \"{}\" tcp dport 80 dnat to {}:{};
                        iifname \"{}\" tcp dport 443 dnat to {}:{};
                    }}
                    
                    chain forward {{
                        type filter hook forward priority 0;
                        iifname \"{}\" oifname \"vh_{}\" accept;
                        iifname \"vh_{}\" oifname \"{}\" ct state established,related accept;
                    }}
                }}",
                table_name,
                bridge_name,
                host_ip_str,
                self.config.http_proxy_port,
                bridge_name,
                host_ip_str,
                self.config.https_proxy_port,
                bridge_name,
                self.config.jail_id,
                self.config.jail_id,
                bridge_name
            );

            // Apply the rules
            let mut nft_cmd = Command::new("nft");
            nft_cmd.arg("-f").arg("-");
            nft_cmd.stdin(std::process::Stdio::piped());

            let mut child = nft_cmd.spawn().context("Failed to spawn nft command")?;

            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                stdin
                    .write_all(nft_rules.as_bytes())
                    .context("Failed to write nftables rules")?;
            }

            let status = child.wait().context("Failed to wait for nft command")?;

            if !status.success() {
                anyhow::bail!("Failed to apply nftables rules for Docker routing");
            }

            info!("Docker routing rules applied successfully");

            // Store the routing table as a managed resource for cleanup
            // Note: We create the resource AFTER applying the rules
            self.docker_routing = Some(ManagedResource::<DockerRoutingTable>::create(
                &self.config.jail_id,
            )?);
        }

        Ok(())
    }
}

impl Jail for DockerLinux {
    fn setup(&mut self, proxy_port: u16) -> Result<()> {
        // First setup the inner Linux jail
        self.inner_jail.setup(proxy_port)?;

        // Create the Docker network
        self.docker_network = Some(ManagedResource::<DockerNetwork>::create(
            &self.config.jail_id,
        )?);

        // Setup routing from Docker network to jail
        self.setup_docker_routing()?;

        info!("DockerLinux jail setup complete with Docker network isolation");
        Ok(())
    }

    fn execute(&self, command: &[String], extra_env: &[(String, String)]) -> Result<ExitStatus> {
        info!("Executing Docker container in isolated network");

        // Build and execute the docker command
        let mut cmd = self.build_docker_command(command, extra_env)?;

        debug!("Docker command: {:?}", cmd);

        // Execute docker run and wait for it to complete
        let status = cmd
            .status()
            .context("Failed to execute docker run command")?;

        Ok(status)
    }

    fn cleanup(&self) -> Result<()> {
        // Docker network and routing will be cleaned up automatically via ManagedResource drop

        // Delegate to inner jail for cleanup
        self.inner_jail.cleanup()
    }

    fn jail_id(&self) -> &str {
        self.inner_jail.jail_id()
    }

    fn cleanup_orphaned(jail_id: &str) -> Result<()>
    where
        Self: Sized,
    {
        // Clean up Docker-specific resources first
        // These will be automatically cleaned up when they go out of scope
        let _docker_network = ManagedResource::<DockerNetwork>::for_existing(jail_id);
        let _docker_routing = ManagedResource::<DockerRoutingTable>::for_existing(jail_id);

        // Then delegate to LinuxJail for standard orphan cleanup
        LinuxJail::cleanup_orphaned(jail_id)
    }
}

impl Clone for DockerLinux {
    fn clone(&self) -> Self {
        Self {
            inner_jail: self.inner_jail.clone(),
            config: self.config.clone(),
            docker_network: None,
            docker_routing: None,
        }
    }
}
