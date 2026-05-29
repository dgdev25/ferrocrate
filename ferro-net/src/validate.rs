//! Input validation for network command builders.
//!
//! This module provides validation functions to prevent shell injection
//! and ensure network parameters are well-formed.

use thiserror::Error;

/// Maximum length for interface names (IFNAMSIZ - 1)
const IFNAMSIZ: usize = 15;

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("interface name too long (max {max} chars): {name}")]
    InterfaceNameTooLong { name: String, max: usize },
    #[error("interface name contains invalid characters: {name}")]
    InvalidInterfaceName { name: String },
    #[error("invalid CIDR notation: {cidr}")]
    InvalidCidr { cidr: String },
    #[error("invalid IP address: {addr}")]
    InvalidIpAddress { addr: String },
    #[error("invalid port number: {port}")]
    InvalidPort { port: u16 },
    #[error("invalid protocol: {proto}")]
    InvalidProtocol { proto: String },
    #[error("invalid nftables family: {family}")]
    InvalidNftFamily { family: String },
    #[error("path traversal detected: {path}")]
    PathTraversal { path: String },
    #[error("shell injection attempt detected: {value}")]
    ShellInjection { value: String },
    #[error("null byte in value")]
    NullByte,
}

/// Validates an interface/bridge name.
///
/// Rules:
/// - Max 15 characters (IFNAMSIZ - 1)
/// - Alphanumeric, dash, underscore, dot only
/// - Cannot start with a dot
pub fn validate_interface_name(name: &str) -> Result<(), ValidationError> {
    if name.len() > IFNAMSIZ {
        return Err(ValidationError::InterfaceNameTooLong {
            name: name.to_string(),
            max: IFNAMSIZ,
        });
    }
    if name.is_empty() {
        return Err(ValidationError::InvalidInterfaceName {
            name: name.to_string(),
        });
    }
    if name.starts_with('.') {
        return Err(ValidationError::InvalidInterfaceName {
            name: name.to_string(),
        });
    }
    // Check for valid characters: alphanumeric, dash, underscore, dot
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(ValidationError::InvalidInterfaceName {
            name: name.to_string(),
        });
    }
    check_shell_safe(name)?;
    Ok(())
}

/// Maximum length for a network namespace name (a filename under /var/run/netns).
const NETNS_NAME_MAX: usize = 255;

/// Validates a network namespace name.
///
/// Unlike interface names, netns names are filenames under `/var/run/netns/` and
/// are NOT bound by IFNAMSIZ (15). The same injection-safety rules apply, but the
/// length limit is the filesystem name limit rather than the interface limit.
pub fn validate_netns_name(name: &str) -> Result<(), ValidationError> {
    if name.len() > NETNS_NAME_MAX {
        return Err(ValidationError::InterfaceNameTooLong {
            name: name.to_string(),
            max: NETNS_NAME_MAX,
        });
    }
    if name.is_empty() || name.starts_with('.') {
        return Err(ValidationError::InvalidInterfaceName {
            name: name.to_string(),
        });
    }
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(ValidationError::InvalidInterfaceName {
            name: name.to_string(),
        });
    }
    check_shell_safe(name)?;
    Ok(())
}

/// Validates a CIDR notation (IPv4 or IPv6).
pub fn validate_cidr(cidr: &str) -> Result<(), ValidationError> {
    check_shell_safe(cidr)?;
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(ValidationError::InvalidCidr {
            cidr: cidr.to_string(),
        });
    }
    let ip = parts[0];
    let prefix = parts[1];

    // Try parsing as IPv4 or IPv6
    let prefix_num: u8 = prefix.parse().map_err(|_| ValidationError::InvalidCidr {
        cidr: cidr.to_string(),
    })?;

    if ip.contains(':') {
        // IPv6
        if prefix_num > 128 {
            return Err(ValidationError::InvalidCidr {
                cidr: cidr.to_string(),
            });
        }
        ip.parse::<std::net::Ipv6Addr>()
            .map_err(|_| ValidationError::InvalidCidr {
                cidr: cidr.to_string(),
            })?;
    } else {
        // IPv4
        if prefix_num > 32 {
            return Err(ValidationError::InvalidCidr {
                cidr: cidr.to_string(),
            });
        }
        ip.parse::<std::net::Ipv4Addr>()
            .map_err(|_| ValidationError::InvalidCidr {
                cidr: cidr.to_string(),
            })?;
    }
    Ok(())
}

/// Validates an IP address (IPv4 or IPv6).
pub fn validate_ip(addr: &str) -> Result<(), ValidationError> {
    check_shell_safe(addr)?;
    if addr.parse::<std::net::IpAddr>().is_err() {
        return Err(ValidationError::InvalidIpAddress {
            addr: addr.to_string(),
        });
    }
    Ok(())
}

/// Validates a port number.
pub fn validate_port(port: u16) -> Result<(), ValidationError> {
    if port == 0 {
        return Err(ValidationError::InvalidPort { port });
    }
    Ok(())
}

/// Validates a network protocol.
pub fn validate_protocol(proto: &str) -> Result<(), ValidationError> {
    check_shell_safe(proto)?;
    let valid = ["tcp", "udp", "icmp", "icmpv6", "sctp", "udplite"];
    if !valid.contains(&proto.to_lowercase().as_str()) {
        return Err(ValidationError::InvalidProtocol {
            proto: proto.to_string(),
        });
    }
    Ok(())
}

/// Validates nftables family.
pub fn validate_nft_family(family: &str) -> Result<(), ValidationError> {
    check_shell_safe(family)?;
    let valid = ["ip", "ip6", "inet", "bridge", "arp", "netdev"];
    if !valid.contains(&family) {
        return Err(ValidationError::InvalidNftFamily {
            family: family.to_string(),
        });
    }
    Ok(())
}

/// Validates a file path (no null bytes, no path traversal).
pub fn validate_path(path: &str) -> Result<(), ValidationError> {
    if path.contains('\0') {
        return Err(ValidationError::NullByte);
    }
    // Check for path traversal
    if path.contains("..") {
        return Err(ValidationError::PathTraversal {
            path: path.to_string(),
        });
    }
    Ok(())
}

/// Checks for shell injection characters.
fn check_shell_safe(value: &str) -> Result<(), ValidationError> {
    if value.contains('\0') {
        return Err(ValidationError::NullByte);
    }
    // Shell metacharacters that could be dangerous
    let dangerous = [
        ';', '|', '`', '$', '(', ')', '{', '}', '[', ']', '<', '>', '&', '\n', '\r',
    ];
    for c in dangerous {
        if value.contains(c) {
            return Err(ValidationError::ShellInjection {
                value: value.to_string(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_interface_names() {
        assert!(validate_interface_name("eth0").is_ok());
        assert!(validate_interface_name("ferro-bridge").is_ok());
        assert!(validate_interface_name("veth_123").is_ok());
        assert!(validate_interface_name("br0.lan").is_ok());

        // Too long
        assert!(validate_interface_name("this_name_is_way_too_long_for_linux").is_err());
        // Invalid chars
        assert!(validate_interface_name("eth@0").is_err());
        // Starts with dot
        assert!(validate_interface_name(".hidden").is_err());
        // Shell injection
        assert!(validate_interface_name("eth0;rm -rf /").is_err());
    }

    #[test]
    fn validates_cidr() {
        assert!(validate_cidr("10.0.0.0/24").is_ok());
        assert!(validate_cidr("192.168.1.1/32").is_ok());
        assert!(validate_cidr("fd00::/64").is_ok());
        assert!(validate_cidr("::1/128").is_ok());

        // Invalid
        assert!(validate_cidr("10.0.0.0").is_err()); // No prefix
        assert!(validate_cidr("10.0.0.0/33").is_err()); // Prefix too large
        assert!(validate_cidr("fd00::/129").is_err()); // IPv6 prefix too large
        assert!(validate_cidr("10.0.0.0/24;rm -rf").is_err()); // Injection
    }

    #[test]
    fn validates_ip_addresses() {
        assert!(validate_ip("10.0.0.1").is_ok());
        assert!(validate_ip("192.168.1.1").is_ok());
        assert!(validate_ip("::1").is_ok());
        assert!(validate_ip("fd00::1").is_ok());

        assert!(validate_ip("256.0.0.1").is_err());
        assert!(validate_ip("not-an-ip").is_err());
    }

    #[test]
    fn validates_protocols() {
        assert!(validate_protocol("tcp").is_ok());
        assert!(validate_protocol("UDP").is_ok());
        assert!(validate_protocol("icmp").is_ok());

        assert!(validate_protocol("unknown").is_err());
    }

    #[test]
    fn validates_nft_families() {
        assert!(validate_nft_family("ip").is_ok());
        assert!(validate_nft_family("ip6").is_ok());
        assert!(validate_nft_family("inet").is_ok());

        assert!(validate_nft_family("invalid").is_err());
    }

    #[test]
    fn detects_shell_injection() {
        assert!(validate_interface_name("eth0;cat /etc/passwd").is_err());
        assert!(validate_interface_name("eth0$(whoami)").is_err());
        assert!(validate_interface_name("eth0`id`").is_err());
        assert!(validate_interface_name("eth0|cat /etc/shadow").is_err());
    }

    #[test]
    fn validates_paths() {
        assert!(validate_path("/var/run/docker.sock").is_ok());
        assert!(validate_path("/tmp/test").is_ok());

        // Path traversal
        assert!(validate_path("../../../etc/passwd").is_err());
        assert!(validate_path("/tmp/../etc/passwd").is_err());
    }
}
