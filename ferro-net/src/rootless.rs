use crate::validate::{validate_cidr, validate_interface_name};
use std::net::Ipv6Addr;
use serde_json::json;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootlessNetConfig {
    pub tap_name: String,
    pub cidr: String,
    pub enable_ipv6: bool,
    /// Optional host IPv6 address for slirp4netns outbound traffic.
    /// This is deliberately opt-in because it must be routable on the host.
    pub outbound_addr6: Option<String>,
    pub api_socket: Option<String>,
}

impl RootlessNetConfig {
    /// Validate the rootless network configuration for security (SEC-03)
    pub fn validate(&self) -> Result<(), String> {
        // Validate tap_name using validate module
        validate_interface_name(&self.tap_name).map_err(|e| format!("Invalid tap name: {}", e))?;

        // Validate cidr using validate module
        validate_cidr(&self.cidr).map_err(|e| format!("Invalid CIDR: {}", e))?;

        if let Some(address) = &self.outbound_addr6 {
            if !self.enable_ipv6 {
                return Err("outbound IPv6 address requires IPv6 to be enabled".to_string());
            }
            address
                .parse::<Ipv6Addr>()
                .map_err(|_| format!("Invalid outbound IPv6 address: {address}"))?;
        }

        Ok(())
    }
}

pub fn build_slirp4netns_cmd(pid: u32, config: &RootlessNetConfig) -> Result<Vec<String>, String> {
    // SEC-03: Call validation before command construction
    config.validate()?;

    Ok(vec![
        "slirp4netns".to_string(),
        "--configure".to_string(),
        "--mtu=65520".to_string(),
        if config.enable_ipv6 {
            "--enable-ipv6".to_string()
        } else {
            String::new()
        },
        config
            .outbound_addr6
            .as_ref()
            .map(|address| format!("--outbound-addr6={address}"))
            .unwrap_or_default(),
        "--cidr".to_string(),
        config.cidr.clone(),
        config
            .api_socket
            .as_ref()
            .map(|socket| format!("--api-socket={socket}"))
            .unwrap_or_default(),
        pid.to_string(),
        config.tap_name.clone(),
    ]
    .into_iter()
    .filter(|argument| !argument.is_empty())
    .collect())
}

/// Build one slirp4netns API request for an IPv4 host-port forward.
/// slirp4netns exposes this API over the Unix socket supplied at startup.
pub fn build_hostfwd_request(
    host_port: u16,
    container_port: u16,
    protocol: &str,
) -> Result<Vec<u8>, String> {
    if host_port == 0 || container_port == 0 {
        return Err("host and container ports must be non-zero".to_string());
    }
    let protocol = protocol.to_ascii_lowercase();
    if protocol != "tcp" && protocol != "udp" {
        return Err(format!(
            "unsupported rootless port mapping protocol: {protocol}"
        ));
    }
    serde_json::to_vec(&json!({
        "execute": "add_hostfwd",
        "arguments": {
            "proto": protocol,
            "host_addr": "0.0.0.0",
            "host_port": host_port,
            "guest_addr": "10.0.2.100",
            "guest_port": container_port,
        }
    }))
    .map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
    use super::{build_slirp4netns_cmd, RootlessNetConfig};

    #[test]
    fn builds_slirp4netns_cmd() {
        let config = RootlessNetConfig {
            tap_name: "tap0".to_string(),
            cidr: "10.0.2.0/24".to_string(),
            enable_ipv6: false,
            outbound_addr6: None,
            api_socket: None,
        };
        let cmd = build_slirp4netns_cmd(1234, &config).unwrap();
        assert_eq!(
            cmd,
            vec![
                "slirp4netns",
                "--configure",
                "--mtu=65520",
                "--cidr",
                "10.0.2.0/24",
                "1234",
                "tap0"
            ]
        );
    }

    #[test]
    fn builds_slirp4netns_cmd_with_edge_values() {
        let config = RootlessNetConfig {
            tap_name: "tap-long-name1".to_string(),
            cidr: "192.168.0.0/16".to_string(),
            enable_ipv6: false,
            outbound_addr6: None,
            api_socket: None,
        };
        let cmd = build_slirp4netns_cmd(9999, &config).unwrap();
        assert_eq!(
            cmd,
            vec![
                "slirp4netns",
                "--configure",
                "--mtu=65520",
                "--cidr",
                "192.168.0.0/16",
                "9999",
                "tap-long-name1"
            ]
        );
    }

    #[test]
    fn rejects_invalid_tap_name() {
        let config = RootlessNetConfig {
            tap_name: "tap@0".to_string(), // Invalid character
            cidr: "10.0.2.0/24".to_string(),
            enable_ipv6: false,
            outbound_addr6: None,
            api_socket: None,
        };
        assert!(build_slirp4netns_cmd(1234, &config).is_err());
    }

    #[test]
    fn rejects_invalid_cidr() {
        let config = RootlessNetConfig {
            tap_name: "tap0".to_string(),
            cidr: "invalid-cidr".to_string(), // Invalid CIDR
            enable_ipv6: false,
            outbound_addr6: None,
            api_socket: None,
        };
        assert!(build_slirp4netns_cmd(1234, &config).is_err());
    }

    #[test]
    fn enables_ipv6_only_when_explicitly_requested() {
        let config = RootlessNetConfig {
            tap_name: "tap0".to_string(),
            cidr: "10.0.2.0/24".to_string(),
            enable_ipv6: true,
            outbound_addr6: None,
            api_socket: None,
        };
        let command = build_slirp4netns_cmd(1234, &config).unwrap();
        assert!(command.iter().any(|argument| argument == "--enable-ipv6"));
    }

    #[test]
    fn adds_api_socket_to_command() {
        let config = RootlessNetConfig {
            tap_name: "tap0".to_string(),
            cidr: "10.0.2.0/24".to_string(),
            enable_ipv6: false,
            outbound_addr6: None,
            api_socket: Some("/run/ferro/slirp.sock".to_string()),
        };
        let command = build_slirp4netns_cmd(1234, &config).unwrap();
        assert!(command
            .iter()
            .any(|argument| argument == "--api-socket=/run/ferro/slirp.sock"));
    }

    #[test]
    fn adds_outbound_ipv6_only_when_explicitly_configured() {
        let config = RootlessNetConfig {
            tap_name: "tap0".to_string(),
            cidr: "10.0.2.0/24".to_string(),
            enable_ipv6: true,
            outbound_addr6: Some("2001:db8::1".to_string()),
            api_socket: None,
        };
        let command = build_slirp4netns_cmd(1234, &config).unwrap();
        assert!(command.iter().any(|argument| argument == "--enable-ipv6"));
        assert!(command
            .iter()
            .any(|argument| argument == "--outbound-addr6=2001:db8::1"));
    }

    #[test]
    fn rejects_outbound_ipv6_without_ipv6() {
        let config = RootlessNetConfig {
            tap_name: "tap0".to_string(),
            cidr: "10.0.2.0/24".to_string(),
            enable_ipv6: false,
            outbound_addr6: Some("2001:db8::1".to_string()),
            api_socket: None,
        };
        assert!(build_slirp4netns_cmd(1234, &config).is_err());
    }

    #[test]
    fn rejects_invalid_outbound_ipv6() {
        let config = RootlessNetConfig {
            tap_name: "tap0".to_string(),
            cidr: "10.0.2.0/24".to_string(),
            enable_ipv6: true,
            outbound_addr6: Some("not-an-ipv6-address".to_string()),
            api_socket: None,
        };
        assert!(build_slirp4netns_cmd(1234, &config).is_err());
    }

    #[test]
    fn builds_tcp_host_forward_request() {
        let request = super::build_hostfwd_request(8080, 80, "TCP").unwrap();
        let value: serde_json::Value = serde_json::from_slice(&request).unwrap();
        assert_eq!(value["execute"], "add_hostfwd");
        assert_eq!(value["arguments"]["proto"], "tcp");
        assert_eq!(value["arguments"]["guest_addr"], "10.0.2.100");
    }

    #[test]
    fn rejects_unsupported_host_forward_protocol() {
        assert!(super::build_hostfwd_request(8080, 80, "sctp").is_err());
    }
}
