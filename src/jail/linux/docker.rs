//! Docker container execution wrapped in Linux jail network isolation

use super::LinuxJail;
use crate::jail::{Jail, JailConfig};
use crate::sys_resource::{ManagedResource, SystemResource};
use anyhow::{Context, Result};
use std::process::{Command, ExitStatus};
use tracing::{debug, info, warn};

fn stale_docker_table_id<'a>(
    line: &'a str,
    networks: &std::collections::HashSet<String>,
    root_canaries: &std::path::Path,
    legacy_canaries: Option<&std::path::Path>,
    namespace_configs: &std::path::Path,
) -> Option<&'a str> {
    let mut parts = line.split_whitespace();
    let (Some("table"), Some(family), Some(name)) = (parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if family != "ip" && family != "inet" {
        return None;
    }
    let id = name.strip_prefix("httpjail_docker_")?;
    (crate::jail::valid_jail_id(id)
        && !networks.contains(&DockerNetwork::network_name_from_jail_id(id))
        && !root_canaries.join(id).exists()
        && !legacy_canaries.is_some_and(|path| path.join(id).exists())
        && !namespace_configs.join(format!("httpjail_{id}")).exists())
    .then_some(id)
}

/// Reclaim routing tables left behind by older runs whose Docker network was
/// removed before the process could drop its nftables resources. This is an
/// explicit maintenance operation, not part of the latency-sensitive startup.
pub fn cleanup_orphaned_docker_tables() -> Result<()> {
    use std::collections::HashSet;
    if !std::path::Path::new("/usr/bin/docker").exists() {
        return Ok(());
    }
    let output = local_docker_command()
        .args(["network", "ls", "--format", "{{.Name}}"])
        .output()?;
    if !output.status.success() {
        debug!("Docker daemon unavailable; skipping stale routing table cleanup");
        return Ok(());
    }
    let networks: HashSet<String> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(ToOwned::to_owned)
        .collect();
    let tables = Command::new("/usr/sbin/nft")
        .args(["list", "tables"])
        .output()?;
    anyhow::ensure!(tables.status.success(), "Failed to list nftables tables");
    let root_canaries = crate::jail::get_canary_dir();
    crate::jail::ensure_trusted_root_dir(&root_canaries)?;
    // Previous versions used sudo-preserved HOME. A legacy live process may
    // still rely on its old canary; err on the side of retaining its guard.
    let legacy_canaries = dirs::data_dir().map(|path| path.join("httpjail/canaries"));
    let mut ids = HashSet::new();
    for line in String::from_utf8_lossy(&tables.stdout).lines() {
        if let Some(id) = stale_docker_table_id(
            line,
            &networks,
            &root_canaries,
            legacy_canaries.as_deref(),
            std::path::Path::new("/etc/netns"),
        ) {
            ids.insert(id.to_string());
        }
    }
    for id in ids {
        DockerRoutingTable::for_existing(&id).cleanup()?;
    }
    Ok(())
}

/// Docker network resource that gets cleaned up on drop
struct DockerNetwork {
    network_name: String,
}

impl DockerNetwork {
    const NETWORK_PREFIX: &'static str = "httpjail_";

    /// Generate network name from jail ID
    fn network_name_from_jail_id(jail_id: &str) -> String {
        format!("{}{}", Self::NETWORK_PREFIX, jail_id)
    }

    /// Check if a Docker command failed due to resource not existing
    fn is_not_found_error(stderr: &str) -> bool {
        stderr.contains("not found")
            || stderr.contains("No such")
            || stderr.contains("does not exist")
    }

    /// Check if a Docker command failed due to resource already existing
    fn is_already_exists_error(stderr: &str) -> bool {
        stderr.contains("already exists")
    }
}

/// Docker routing nftables resource that gets cleaned up on drop
struct DockerRoutingTable {
    #[allow(dead_code)]
    jail_id: String,
    table_name: String,
}

impl DockerRoutingTable {
    /// Generate table name from jail ID
    fn table_name_from_jail_id(jail_id: &str) -> String {
        format!("httpjail_docker_{}", jail_id)
    }
}

impl SystemResource for DockerRoutingTable {
    fn create(jail_id: &str) -> Result<Self> {
        Ok(Self {
            jail_id: jail_id.to_string(),
            table_name: Self::table_name_from_jail_id(jail_id),
        })
    }

    fn cleanup(&mut self) -> Result<()> {
        debug!("Cleaning up Docker routing table: {}", self.table_name);

        for family in ["inet", "ip"] {
            let output = Command::new("/usr/sbin/nft")
                .args(["delete", "table", family, &self.table_name])
                .output()
                .context("Failed to delete Docker routing table")?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                if !DockerNetwork::is_not_found_error(&stderr) {
                    anyhow::bail!("Failed to delete Docker routing table: {}", stderr);
                }
            } else {
                info!(
                    "Removed Docker {} routing table {}",
                    family, self.table_name
                );
            }
        }

        Ok(())
    }

    fn for_existing(jail_id: &str) -> Self {
        Self {
            jail_id: jail_id.to_string(),
            table_name: Self::table_name_from_jail_id(jail_id),
        }
    }
}

// The nftables guard is installed on this host, so Docker must use its local daemon.
// Ignore caller-selected contexts; a remote daemon would bypass the bridge guard.
fn local_docker_command() -> Command {
    let mut cmd = Command::new("/usr/bin/docker");
    cmd.env_remove("DOCKER_HOST")
        .env_remove("DOCKER_CONTEXT")
        .env_remove("DOCKER_CONFIG")
        .arg("--host=unix:///var/run/docker.sock");
    cmd
}

impl SystemResource for DockerNetwork {
    fn create(jail_id: &str) -> Result<Self> {
        let network_name = Self::network_name_from_jail_id(jail_id);

        // Create Docker network with no default gateway (isolated)
        // Using a /24 subnet in the 172.20.x.x range
        let subnet = Self::compute_docker_subnet(jail_id);

        let output = local_docker_command()
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
            if Self::is_already_exists_error(&stderr) {
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

        let output = local_docker_command()
            .args(["network", "rm", &self.network_name])
            .output()
            .context("Failed to remove Docker network")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if Self::is_not_found_error(&stderr) {
                debug!("Docker network {} already removed", self.network_name);
            } else {
                anyhow::bail!("Failed to remove Docker network: {}", stderr);
            }
        } else {
            info!("Removed Docker network {}", self.network_name);
        }

        Ok(())
    }

    fn for_existing(jail_id: &str) -> Self {
        Self {
            network_name: Self::network_name_from_jail_id(jail_id),
        }
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
        let output = local_docker_command()
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

        let bridge = format!("br-{}", network_id);
        anyhow::ensure!(
            std::path::Path::new("/sys/class/net")
                .join(&bridge)
                .exists(),
            "Docker bridge {bridge} is not present on the local host"
        );
        Ok(bridge)
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

    fn container_name(&self) -> String {
        format!("httpjail_{}_run", self.config.jail_id)
    }

    /// Only options that cannot change the container's network, privileges, or host access.
    const SAFE_VALUE_FLAGS: &'static [&'static str] = &[
        "-e",
        "--env",
        "--entrypoint",
        "-w",
        "--workdir",
        "-u",
        "--user",
        "--pull",
        "--memory",
        "--cpus",
        "--label",
    ];
    const SAFE_BOOL_FLAGS: &'static [&'static str] = &[
        "--rm",
        "--read-only",
        "--init",
        "--no-healthcheck",
        "-i",
        "-t",
    ];

    /// Build the docker command with isolated network
    #[allow(clippy::collapsible_if)]
    fn build_docker_command(
        &self,
        docker_args: &[String],
        extra_env: &[(String, String)],
    ) -> Result<(Command, Option<tempfile::TempDir>)> {
        let network_name = DockerNetwork::network_name_from_jail_id(&self.config.jail_id);
        let image_idx = Self::find_image_index(docker_args)?;
        let docker_opts = &docker_args[..image_idx];
        let image = &docker_args[image_idx];
        let user_command = &docker_args[image_idx + 1..];

        // Build the docker run command
        let mut cmd = local_docker_command();
        cmd.arg("run");

        // Route DNS to the dummy resolver, never Docker's host-configured resolver.
        let host_ip =
            super::format_ip(LinuxJail::compute_host_ip_for_jail_id(&self.config.jail_id));
        let container_name = self.container_name();
        cmd.args([
            "--network",
            &network_name,
            "--dns",
            &host_ip,
            "--name",
            &container_name,
            "--cap-drop=NET_RAW",
            "--rm",
        ]);

        // Mount only a public certificate snapshot, never the CA key directory.
        let mut ca_cert_path = None;
        for (key, value) in extra_env {
            if key == "SSL_CERT_DIR" {
                continue; // That directory also holds the CA private key.
            }
            cmd.arg("-e").arg(format!("{}={}", key, value));
            if key == "SSL_CERT_FILE" && ca_cert_path.is_none() {
                ca_cert_path = Some(value.clone());
            }
        }

        // Docker resolves bind sources later. A separate local actor could change
        // the original path in between, so mount a root-private regular-file copy.
        let mut cert_dir = None;
        if let Some(cert_path) = ca_cert_path {
            use std::io::Read;
            use std::os::unix::fs::OpenOptionsExt;
            let cert = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&cert_path)
                .context("Failed to open public CA certificate")?;
            let metadata = cert.metadata()?;
            anyhow::ensure!(
                metadata.is_file() && metadata.len() < 1024 * 1024,
                "Invalid public CA certificate"
            );
            let mut pem = String::new();
            cert.take(1024 * 1024).read_to_string(&mut pem)?;
            anyhow::ensure!(
                pem.trim_start().starts_with("-----BEGIN CERTIFICATE-----")
                    && pem.contains("-----END CERTIFICATE-----")
                    && !pem.contains("PRIVATE KEY"),
                "Invalid public CA certificate"
            );
            let dir = if unsafe { libc::geteuid() == 0 } {
                let root_dir = std::path::Path::new("/var/lib/httpjail");
                crate::jail::ensure_trusted_root_dir(root_dir)?;
                tempfile::Builder::new()
                    .prefix("cert-")
                    .tempdir_in(root_dir)
            } else {
                tempfile::tempdir()
            }
            .context("Failed to create protected CA mount directory")?;
            let snapshot = dir.path().join("ca-cert.pem");
            std::fs::write(&snapshot, pem).context("Failed to write public CA snapshot")?;
            cmd.arg("-v")
                .arg(format!("{}:{}:ro", snapshot.display(), cert_path));
            cert_dir = Some(dir);
            cmd.env_remove("SSL_CERT_DIR");
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

        Ok((cmd, cert_dir))
    }

    /// Find the image while rejecting Docker options that could bypass isolation.
    /// Everything after the image belongs to the container command, not Docker.
    fn find_image_index(args: &[String]) -> Result<usize> {
        let mut i = 0;
        while let Some(arg) = args.get(i) {
            if !arg.starts_with('-') {
                anyhow::ensure!(!arg.is_empty(), "Docker image must not be empty");
                return Ok(i);
            }
            if Self::SAFE_BOOL_FLAGS.contains(&arg.as_str()) {
                i += 1;
                continue;
            }
            let (flag, inline_value) = arg
                .split_once('=')
                .map_or((arg.as_str(), None), |(name, value)| (name, Some(value)));
            anyhow::ensure!(
                Self::SAFE_VALUE_FLAGS.contains(&flag),
                "Docker option not permitted in an isolated jail: {}",
                arg
            );
            if let Some(value) = inline_value {
                anyhow::ensure!(
                    !value.is_empty(),
                    "Missing value for Docker option {}",
                    flag
                );
                i += 1;
            } else {
                let value = args.get(i + 1).context("Missing Docker option value")?;
                anyhow::ensure!(
                    !value.starts_with('-'),
                    "Invalid value for Docker option {}",
                    flag
                );
                i += 2;
            }
        }
        anyhow::bail!("Could not find Docker image in arguments")
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
            let table_name = DockerRoutingTable::table_name_from_jail_id(&self.config.jail_id);

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

            // Docker bridge traffic to its host gateway takes INPUT, not FORWARD.
            // This inet guard blocks both IPv4 and IPv6 outside proxy and dummy DNS.
            let guard = format!(
                r#"table inet {table_name} {{
                    chain input {{
                        type filter hook input priority -5; policy accept;
                        iifname "{bridge_name}" ip saddr {docker_subnet} ip daddr {host_ip_str} tcp dport {{ {http_port}, {https_port} }} accept
                        iifname "{bridge_name}" ip saddr {docker_subnet} ip daddr {host_ip_str} udp dport 53 accept
                        iifname "{bridge_name}" drop
                    }}
                    chain forward {{
                        type filter hook forward priority -5; policy accept;
                        iifname "{bridge_name}" drop
                    }}
                }}"#,
                table_name = table_name,
                bridge_name = bridge_name,
                docker_subnet = DockerNetwork::compute_docker_subnet(&self.config.jail_id),
                host_ip_str = host_ip_str,
                http_port = self.config.http_proxy_port,
                https_port = self.config.https_proxy_port,
            );
            let nft_rules = format!("{nft_rules}\n{guard}");

            // Apply the rules
            let mut nft_cmd = Command::new("/usr/sbin/nft");
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
        // A missing canary cannot prove an older jail is dead: it may live
        // beneath another sudo-preserved HOME. Never delete its network here.

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
        let (cmd, _cert_dir) = self.build_docker_command(command, extra_env)?;

        debug!("Docker command: {:?}", cmd);

        // Execute docker run and wait for it to complete
        crate::jail::run_command(cmd, None).context("Failed to execute docker run command")
    }

    fn execute_with_timeout(
        &self,
        command: &[String],
        extra_env: &[(String, String)],
        timeout: std::time::Duration,
    ) -> Result<ExitStatus> {
        let (cmd, _cert_dir) = self.build_docker_command(command, extra_env)?;
        let status = crate::jail::run_command(cmd, Some(timeout))
            .context("Failed to execute docker run command")?;
        if status.code() == Some(124) {
            // Killing the Docker CLI does not necessarily stop its daemon-owned container.
            let output = local_docker_command()
                .args(["rm", "-f", &self.container_name()])
                .output()
                .context("Failed to stop timed-out Docker container")?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::ensure!(
                    DockerNetwork::is_not_found_error(&stderr),
                    "Failed to stop timed-out Docker container: {}",
                    stderr
                );
            }
        }
        Ok(status)
    }

    fn cleanup(&self) -> Result<()> {
        // The command may exit via process::exit and a signal handler holds a
        // clone, so do not rely on Drop to clean up daemon-owned resources.
        // Remove the network before its guard; on failure retain both and the
        // canary so a later orphan cleanup can retry without exposing traffic.
        DockerNetwork::for_existing(&self.config.jail_id).cleanup()?;
        DockerRoutingTable::for_existing(&self.config.jail_id).cleanup()?;
        self.inner_jail.cleanup()
    }

    fn jail_id(&self) -> &str {
        self.inner_jail.jail_id()
    }

    fn cleanup_orphaned(jail_id: &str) -> Result<()>
    where
        Self: Sized,
    {
        // Keep the bridge firewall until Docker confirms the network is gone.
        DockerNetwork::for_existing(jail_id).cleanup()?;
        DockerRoutingTable::for_existing(jail_id).cleanup()?;
        LinuxJail::cleanup_orphaned(jail_id)
    }
}

impl Drop for DockerLinux {
    fn drop(&mut self) {
        // Never remove the firewall guard while Docker still reports an active
        // network: a surviving container would regain direct host/Internet access.
        if let Some(mut network) = self.docker_network.take() {
            let result = network.inner_mut().map_or(Ok(()), SystemResource::cleanup);
            if let Err(error) = result {
                warn!(
                    "Retaining Docker bridge firewall after network cleanup failure: {}",
                    error
                );
                if let Some(guard) = self.docker_routing.take() {
                    std::mem::forget(guard);
                }
            }
        }
        // Otherwise the routing guard is removed after the network.
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

#[cfg(test)]
mod tests {
    use super::DockerLinux;

    #[test]
    fn stale_tables_skip_live_networks_and_canaries() {
        use std::collections::HashSet;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        let legacy = dir.path().join("legacy");
        let namespace_configs = dir.path().join("netns");
        std::fs::create_dir_all(&namespace_configs).unwrap();
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&legacy).unwrap();
        let line = "table ip httpjail_docker_abcd1234";
        let mut networks = HashSet::new();
        assert_eq!(
            super::stale_docker_table_id(line, &networks, &root, Some(&legacy), &namespace_configs),
            Some("abcd1234")
        );
        networks.insert("httpjail_abcd1234".to_string());
        assert_eq!(
            super::stale_docker_table_id(line, &networks, &root, Some(&legacy), &namespace_configs),
            None
        );
        networks.clear();
        std::fs::write(legacy.join("abcd1234"), "1").unwrap();
        assert_eq!(
            super::stale_docker_table_id(line, &networks, &root, Some(&legacy), &namespace_configs),
            None
        );
        std::fs::remove_file(legacy.join("abcd1234")).unwrap();
        std::fs::create_dir(namespace_configs.join("httpjail_abcd1234")).unwrap();
        assert_eq!(
            super::stale_docker_table_id(line, &networks, &root, Some(&legacy), &namespace_configs),
            None
        );
        assert_eq!(
            super::stale_docker_table_id(
                "table ip httpjail_docker_bad!",
                &networks,
                &root,
                None,
                &namespace_configs
            ),
            None
        );
    }

    #[test]
    fn docker_mounts_only_public_ca_file() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("ca-cert.pem");
        std::fs::write(
            &cert,
            b"-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("ca-key.pem"), b"dummy private key").unwrap();
        let cert_path = cert.to_string_lossy().to_string();
        let parent = dir.path().to_string_lossy().to_string();
        let jail = DockerLinux::new(crate::jail::JailConfig::new()).unwrap();
        let (cmd, _cert_dir) = jail
            .build_docker_command(
                &["alpine:latest".to_string()],
                &[
                    ("SSL_CERT_FILE".to_string(), cert_path.clone()),
                    ("SSL_CERT_DIR".to_string(), parent.clone()),
                ],
            )
            .unwrap();
        let args = cmd
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        let mount = args
            .iter()
            .find(|arg| arg.ends_with(&format!(":{cert_path}:ro")))
            .unwrap();
        let source = mount.strip_suffix(&format!(":{cert_path}:ro")).unwrap();
        assert_ne!(source, cert_path);
        assert!(
            std::fs::read_to_string(source)
                .unwrap()
                .contains("BEGIN CERTIFICATE")
        );
        assert!(!args.contains(&format!("{parent}:{parent}:ro")));
        assert!(!args.iter().any(|arg| arg.starts_with("SSL_CERT_DIR=")));

        std::fs::remove_file(&cert).unwrap();
        std::os::unix::fs::symlink("ca-key.pem", &cert).unwrap();
        assert!(
            std::fs::read_to_string(source)
                .unwrap()
                .contains("BEGIN CERTIFICATE")
        );
        assert!(
            jail.build_docker_command(
                &["alpine:latest".to_string()],
                &[("SSL_CERT_FILE".to_string(), cert_path)]
            )
            .is_err()
        );
    }

    #[test]
    fn docker_options_cannot_override_isolation() {
        let args = |parts: &[&str]| parts.iter().map(|s| (*s).to_string()).collect::<Vec<_>>();
        assert_eq!(
            DockerLinux::find_image_index(&args(&[
                "--rm",
                "-e",
                "FOO=bar",
                "alpine",
                "--net=other"
            ]))
            .unwrap(),
            3
        );
        for option in [
            "--net=other",
            "--network=host",
            "--privileged",
            "--dns=8.8.8.8",
            "-v",
        ] {
            assert!(
                DockerLinux::find_image_index(&args(&[option, "alpine"])).is_err(),
                "unsafe Docker option {option} was accepted"
            );
        }
    }
}
