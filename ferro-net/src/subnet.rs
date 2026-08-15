//! Pure IPv4 subnet math used to derive a network address from a gateway CIDR.

use std::net::Ipv4Addr;

/// Given a gateway IP and prefix length, return the network address as `A.B.C.D/prefix`.
///
/// Example: `network_cidr_v4("10.0.0.1", 24)` -> `"10.0.0.0/24"`.
pub fn network_cidr_v4(gateway: &str, prefix: u8) -> Result<String, String> {
    if prefix > 32 {
        return Err(format!("invalid ipv4 prefix: {prefix}"));
    }
    let addr: Ipv4Addr = gateway
        .parse()
        .map_err(|_| format!("invalid ipv4 gateway: {gateway}"))?;
    let bits = u32::from(addr);
    let mask: u32 = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = Ipv4Addr::from(bits & mask);
    Ok(format!("{network}/{prefix}"))
}

#[cfg(test)]
mod tests {
    use super::network_cidr_v4;

    #[test]
    fn derives_network_for_slash_24() {
        assert_eq!(network_cidr_v4("10.0.0.1", 24).unwrap(), "10.0.0.0/24");
    }

    #[test]
    fn derives_network_for_slash_16() {
        assert_eq!(network_cidr_v4("172.18.5.9", 16).unwrap(), "172.18.0.0/16");
    }

    #[test]
    fn rejects_bad_gateway() {
        assert!(network_cidr_v4("not-an-ip", 24).is_err());
    }

    #[test]
    fn rejects_bad_prefix() {
        assert!(network_cidr_v4("10.0.0.1", 33).is_err());
    }
}
