//! Validation tests for ferro-net
//!
//! Tests for input validation and shell injection prevention.

use ferro_net::validate::*;

#[test]
fn validates_interface_name() {
    assert!(validate_interface_name("eth0").is_ok());
    assert!(validate_interface_name("veth-123").is_ok());
    assert!(validate_interface_name("br.lan").is_ok());
    assert!(validate_interface_name("test_bridge").is_ok());

    // Too long (max 15 chars)
    assert!(validate_interface_name("this_is_too_long_name").is_err());

    // Invalid characters
    assert!(validate_interface_name("eth@0").is_err());
    assert!(validate_interface_name("eth 0").is_err());
}

#[test]
fn validates_cidr() {
    assert!(validate_cidr("192.168.1.0/24").is_ok());
    assert!(validate_cidr("10.0.0.0/8").is_ok());
    assert!(validate_cidr("fd00::/64").is_ok());
    assert!(validate_cidr("2001:db8::/32").is_ok());

    // Invalid CIDR
    assert!(validate_cidr("not-a-cidr").is_err());
    assert!(validate_cidr("192.168.1.0").is_err()); // No prefix
    assert!(validate_cidr("192.168.1.0/33").is_err()); // Invalid prefix
}

#[test]
fn validates_ip_address() {
    assert!(validate_ip("192.168.1.1").is_ok());
    assert!(validate_ip("10.0.0.1").is_ok());
    assert!(validate_ip("::1").is_ok());
    assert!(validate_ip("fd00::1").is_ok());

    // Invalid IPs
    assert!(validate_ip("not-an-ip").is_err());
    assert!(validate_ip("256.256.256.256").is_err());
}

#[test]
fn validates_port() {
    assert!(validate_port(1).is_ok());
    assert!(validate_port(80).is_ok());
    assert!(validate_port(443).is_ok());
    assert!(validate_port(65535).is_ok());

    // Port 0 is invalid (reserved)
    assert!(validate_port(0).is_err());
}

#[test]
fn validates_protocol() {
    assert!(validate_protocol("tcp").is_ok());
    assert!(validate_protocol("udp").is_ok());
    assert!(validate_protocol("icmp").is_ok());
    assert!(validate_protocol("icmpv6").is_ok());
    assert!(validate_protocol("sctp").is_ok());

    // Case insensitive
    assert!(validate_protocol("TCP").is_ok());
    assert!(validate_protocol("UDP").is_ok());

    // Invalid protocols
    assert!(validate_protocol("invalid").is_err());
}

#[test]
fn validates_nft_family() {
    assert!(validate_nft_family("ip").is_ok());
    assert!(validate_nft_family("ip6").is_ok());
    assert!(validate_nft_family("inet").is_ok());
    assert!(validate_nft_family("bridge").is_ok());

    // Invalid families
    assert!(validate_nft_family("invalid").is_err());
}

#[test]
fn validates_path() {
    assert!(validate_path("/etc/passwd").is_ok());
    assert!(validate_path("/var/run/docker.sock").is_ok());
    assert!(validate_path("./relative/path").is_ok());

    // Path traversal attempts
    assert!(validate_path("../../../etc/passwd").is_err());
    assert!(validate_path("/etc/../../../etc/passwd").is_err());

    // Null bytes
    assert!(validate_path("/etc/passwd\0").is_err());
}

#[test]
fn shell_injection_in_interface_name() {
    // Interface names with shell metacharacters should be rejected
    // because they contain invalid characters for interface names
    assert!(validate_interface_name("eth0; rm -rf /").is_err());
    assert!(validate_interface_name("eth0 && cat /etc/passwd").is_err());
    assert!(validate_interface_name("$(whoami)").is_err());
}

#[test]
fn combined_validation_rejects_malicious_input() {
    // Interface name with shell injection
    let result = validate_interface_name("eth0; rm -rf /");
    assert!(result.is_err());

    // CIDR with shell injection
    let result = validate_cidr("10.0.0.0/24; rm -rf /");
    assert!(result.is_err());

    // Protocol with shell injection
    let result = validate_protocol("tcp; rm -rf /");
    assert!(result.is_err());
}
