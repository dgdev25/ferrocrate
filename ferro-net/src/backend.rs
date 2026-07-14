use std::fmt;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkBackend {
    Ebpf,
    Iptables,
    Nftables,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BackendError {
    #[error("{0}")]
    Unavailable(String),
    #[error("network-backend must be one of: ebpf, iptables, nftables")]
    InvalidBackend,
}

pub trait BackendProbe {
    fn command_exists(&self, command: &str) -> bool;
    fn bpffs_mounted(&self) -> bool;
    fn artifact_available(&self) -> bool;
}

impl NetworkBackend {
    pub fn ensure_available(self, probe: &dyn BackendProbe) -> Result<(), BackendError> {
        match self {
            Self::Ebpf
                if !(probe.command_exists("tc")
                    && probe.bpffs_mounted()
                    && probe.artifact_available()) =>
            {
                Err(BackendError::Unavailable(
                    "eBPF backend unavailable: require tc, bpffs, and verified FerroCrate program"
                        .into(),
                ))
            }
            Self::Iptables if !probe.command_exists("iptables") => Err(BackendError::Unavailable(
                "iptables backend unavailable: command not found".into(),
            )),
            Self::Nftables if !probe.command_exists("nft") => Err(BackendError::Unavailable(
                "nftables backend unavailable: command not found".into(),
            )),
            _ => Ok(()),
        }
    }
}

impl FromStr for NetworkBackend {
    type Err = BackendError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ebpf" => Ok(Self::Ebpf),
            "iptables" => Ok(Self::Iptables),
            "nftables" => Ok(Self::Nftables),
            _ => Err(BackendError::InvalidBackend),
        }
    }
}

impl fmt::Display for NetworkBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ebpf => "ebpf",
            Self::Iptables => "iptables",
            Self::Nftables => "nftables",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{BackendProbe, NetworkBackend};

    struct FakeProbe {
        tc_available: bool,
        bpffs_mounted: bool,
        artifact_available: bool,
    }

    impl FakeProbe {
        fn unavailable() -> Self {
            Self {
                tc_available: false,
                bpffs_mounted: false,
                artifact_available: false,
            }
        }
    }

    impl BackendProbe for FakeProbe {
        fn command_exists(&self, command: &str) -> bool {
            command == "tc" && self.tc_available
        }

        fn bpffs_mounted(&self) -> bool {
            self.bpffs_mounted
        }

        fn artifact_available(&self) -> bool {
            self.artifact_available
        }
    }

    #[test]
    fn ebpf_unavailable_fails_without_fallback() {
        let probe = FakeProbe::unavailable();
        let err = NetworkBackend::Ebpf.ensure_available(&probe).unwrap_err();
        assert!(err.to_string().contains("eBPF backend unavailable"));
    }

    #[test]
    fn explicit_firewall_backends_remain_selected() {
        assert_eq!("iptables".parse(), Ok(NetworkBackend::Iptables));
        assert_eq!("nftables".parse(), Ok(NetworkBackend::Nftables));
    }
}
