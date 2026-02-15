use crate::validate::{validate_cidr, validate_interface_name};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootlessNetConfig {
    pub tap_name: String,
    pub cidr: String,
}

impl RootlessNetConfig {
    /// Validate the rootless network configuration for security (SEC-03)
    pub fn validate(&self) -> Result<(), String> {
        // Validate tap_name using validate module
        validate_interface_name(&self.tap_name)
            .map_err(|e| format!("Invalid tap name: {}", e))?;

        // Validate cidr using validate module
        validate_cidr(&self.cidr)
            .map_err(|e| format!("Invalid CIDR: {}", e))?;

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
        "--cidr".to_string(),
        config.cidr.clone(),
        pid.to_string(),
        config.tap_name.clone(),
    ])
}

#[cfg(test)]
mod tests {
    use super::{RootlessNetConfig, build_slirp4netns_cmd};

    #[test]
    fn builds_slirp4netns_cmd() {
        let config = RootlessNetConfig {
            tap_name: "tap0".to_string(),
            cidr: "10.0.2.0/24".to_string(),
        };
        let cmd = build_slirp4netns_cmd(1234, &config).unwrap();
        assert_eq!(
            cmd,
            vec![
                "slirp4netns", "--configure", "--mtu=65520", "--cidr", "10.0.2.0/24",
                "1234", "tap0"
            ]
        );
    }

    #[test]
    fn builds_slirp4netns_cmd_with_edge_values() {
        let config = RootlessNetConfig {
            tap_name: "tap-long-name1".to_string(),
            cidr: "192.168.0.0/16".to_string(),
        };
        let cmd = build_slirp4netns_cmd(9999, &config).unwrap();
        assert_eq!(
            cmd,
            vec![
                "slirp4netns", "--configure", "--mtu=65520", "--cidr", "192.168.0.0/16",
                "9999", "tap-long-name1"
            ]
        );
    }

    #[test]
    fn rejects_invalid_tap_name() {
        let config = RootlessNetConfig {
            tap_name: "tap@0".to_string(),  // Invalid character
            cidr: "10.0.2.0/24".to_string(),
        };
        assert!(build_slirp4netns_cmd(1234, &config).is_err());
    }

    #[test]
    fn rejects_invalid_cidr() {
        let config = RootlessNetConfig {
            tap_name: "tap0".to_string(),
            cidr: "invalid-cidr".to_string(),  // Invalid CIDR
        };
        assert!(build_slirp4netns_cmd(1234, &config).is_err());
    }
}
