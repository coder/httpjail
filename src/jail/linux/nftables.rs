use anyhow::{Context, Result};
use std::process::Command;
use tracing::{debug, info};

/// RAII wrapper for nftables table that ensures cleanup on drop
#[derive(Debug)]
pub struct NFTable {
    /// The table name (e.g., "httpjail_<jail_id>")
    name: String,
    /// Optional namespace where the table exists (None = host)
    namespace: Option<String>,
    /// Whether the table was successfully created
    created: bool,
}

impl NFTable {
    /// Create a host-side nftables table with NAT, forward, and input rules
    ///
    /// Note: We use numeric priorities instead of named ones (srcnat, dstnat) for
    /// compatibility with older nftables versions (< 0.9.6)
    pub fn new_host_table(
        jail_id: &str,
        subnet_cidr: &str,
        http_port: u16,
        https_port: u16,
    ) -> Result<Self> {
        let table_name = format!("httpjail_{}", jail_id);
        let veth_host = format!("vh_{}", jail_id);

        // Generate the ruleset for host-side NAT, forwarding, and input acceptance
        let ruleset = format!(
            r#"
table ip {} {{
    chain prerouting {{
        type filter hook prerouting priority -150; policy accept;
        iifname "{}" accept comment "httpjail_{} prerouting"
    }}
    
    chain postrouting {{
        type nat hook postrouting priority 100; policy accept;
        ip saddr {} masquerade comment "httpjail_{}"
    }}
    
    chain forward {{
        type filter hook forward priority -100; policy accept;
        ip saddr {} accept comment "httpjail_{} out"
        ip daddr {} accept comment "httpjail_{} in"
    }}
    
    chain input {{
        type filter hook input priority -100; policy accept;
        iifname "{}" tcp dport {{ {}, {} }} accept comment "httpjail_{} proxy"
        iifname "{}" udp dport 5353 accept comment "httpjail_{} dns"
        iifname "{}" tcp dport 5353 accept comment "httpjail_{} dns tcp"
        iifname "{}" accept comment "httpjail_{} all"
    }}
    
    chain output {{
        type filter hook output priority -100; policy accept;
        oifname "{}" accept comment "httpjail_{} out"
    }}
}}
"#,
            table_name,
            veth_host,
            jail_id,
            subnet_cidr,
            jail_id,
            subnet_cidr,
            jail_id,
            subnet_cidr,
            jail_id,
            veth_host,
            http_port,
            https_port,
            jail_id,
            veth_host,
            jail_id,
            veth_host,
            jail_id,
            veth_host,
            jail_id,
            veth_host,
            jail_id
        );

        debug!("Creating nftables table: {}", table_name);
        debug!("Ruleset placeholders count check - ensuring format args match");

        // Apply the ruleset atomically
        use std::io::Write;
        let mut child = Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("Failed to spawn nft command")?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(ruleset.as_bytes())
                .context("Failed to write ruleset to nft")?;
        }

        let output = child
            .wait_with_output()
            .context("Failed to execute nft command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to create nftables table: {}", stderr);
        }

        info!(
            "Created nftables table {} with NAT rules for subnet {}",
            table_name, subnet_cidr
        );

        Ok(Self {
            name: table_name,
            namespace: None,
            created: true,
        })
    }

    /// Create namespace-side nftables rules for traffic redirection and egress filtering
    pub fn new_namespace_table(
        namespace: &str,
        host_ip: &str,
        http_port: u16,
        https_port: u16,
    ) -> Result<Self> {
        Self::new_namespace_table_with_dns(namespace, host_ip, http_port, https_port, 5353)
    }

    /// Create namespace-side nftables rules for traffic redirection and egress filtering with DNS redirection
    pub fn new_namespace_table_with_dns(
        namespace: &str,
        host_ip: &str,
        http_port: u16,
        https_port: u16,
        dns_port: u16,
    ) -> Result<Self> {
        let table_name = "httpjail".to_string();

        // Generate the ruleset for namespace-side DNAT + FILTER
        let ruleset = format!(
            r#"
table ip {} {{
    # NAT output chain: redirect HTTP/HTTPS and DNS to host proxy
    chain output {{
        type nat hook output priority -100; policy accept;

        # Redirect DNS traffic to our dummy DNS server on host
        udp dport 53 dnat to {}:{}
        tcp dport 53 dnat to {}:{}

        # Redirect HTTP to proxy running on host
        tcp dport 80 dnat to {}:{}

        # Redirect HTTPS to proxy running on host
        tcp dport 443 dnat to {}:{}
    }}

    # FILTER output chain: block non-HTTP/HTTPS egress
    chain outfilter {{
        type filter hook output priority 0; policy drop;

        # Always allow established/related traffic
        ct state established,related accept

        # Allow redirected DNS traffic to the host
        ip daddr {} udp dport {} accept
        ip daddr {} tcp dport {} accept

        # Allow traffic to the host proxy ports after DNAT
        ip daddr {} tcp dport {{ {}, {} }} accept

        # Explicitly block all other UDP (e.g., QUIC on 443)
        # This must come AFTER allowing DNS traffic
        ip protocol udp drop
    }}
}}
"#,
            table_name,
            host_ip,
            dns_port, // UDP DNS redirect
            host_ip,
            dns_port, // TCP DNS redirect
            host_ip,
            http_port, // HTTP redirect
            host_ip,
            https_port, // HTTPS redirect
            host_ip,
            dns_port, // Allow UDP DNS to host
            host_ip,
            dns_port, // Allow TCP DNS to host
            host_ip,
            http_port,
            https_port // Allow HTTP/HTTPS to host
        );

        debug!(
            "Creating nftables table in namespace {}: {}",
            namespace, table_name
        );

        // Execute nft within the namespace
        let mut child = Command::new("ip")
            .args(["netns", "exec", namespace, "nft", "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("Failed to spawn nft command in namespace")?;

        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin
                .write_all(ruleset.as_bytes())
                .context("Failed to write ruleset to nft")?;
        }

        let output = child
            .wait_with_output()
            .context("Failed to execute nft command in namespace")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Failed to create namespace nftables table: {}", stderr);
        }

        info!(
            "Created nftables rules in namespace {} for HTTP:{} HTTPS:{}",
            namespace, http_port, https_port
        );

        Ok(Self {
            name: table_name,
            namespace: Some(namespace.to_string()),
            created: true,
        })
    }

    /// Remove the nftables table
    fn remove(&mut self) -> Result<()> {
        if !self.created {
            return Ok(());
        }

        let output = if let Some(ref namespace) = self.namespace {
            // Delete table in namespace
            Command::new("ip")
                .args([
                    "netns", "exec", namespace, "nft", "delete", "table", "ip", &self.name,
                ])
                .output()
                .context("Failed to execute nft delete in namespace")?
        } else {
            // Delete table on host
            Command::new("nft")
                .args(["delete", "table", "ip", &self.name])
                .output()
                .context("Failed to execute nft delete")?
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore if table doesn't exist (already removed)
            if !stderr.contains("No such file or directory") && !stderr.contains("does not exist") {
                // Log but don't fail - best effort cleanup
                debug!("Failed to remove nftables table {}: {}", self.name, stderr);
            }
        } else {
            debug!("Removed nftables table: {}", self.name);
        }

        self.created = false;
        Ok(())
    }

    /// Create table for existing jail (for cleanup purposes)
    pub fn for_existing(jail_id: &str, is_namespace: bool) -> Self {
        Self {
            name: if is_namespace {
                "httpjail".to_string()
            } else {
                format!("httpjail_{}", jail_id)
            },
            namespace: if is_namespace {
                Some(format!("httpjail_{}", jail_id))
            } else {
                None
            },
            created: true,
        }
    }
}

impl Drop for NFTable {
    fn drop(&mut self) {
        if self.created
            && let Err(e) = self.remove()
        {
            debug!("Failed to remove nftables table on drop: {}", e);
        }
    }
}
