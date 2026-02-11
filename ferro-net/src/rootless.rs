#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootlessNetConfig {
    pub tap_name: String,
    pub cidr: String,
}

pub fn build_slirp4netns_cmd(pid: u32, config: &RootlessNetConfig) -> Vec<String> {
    vec![
        "slirp4netns".to_string(),
        "--configure".to_string(),
        "--mtu=65520".to_string(),
        "--cidr".to_string(),
        config.cidr.clone(),
        pid.to_string(),
        config.tap_name.clone(),
    ]
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
        let cmd = build_slirp4netns_cmd(1234, &config);
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
            tap_name: "tap-long-name-01".to_string(),
            cidr: "".to_string(),
        };
        let cmd = build_slirp4netns_cmd(9999, &config);
        assert_eq!(
            cmd,
            vec![
                "slirp4netns", "--configure", "--mtu=65520", "--cidr", "", "9999",
                "tap-long-name-01"
            ]
        );
    }
}
