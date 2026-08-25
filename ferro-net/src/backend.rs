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
                    && probe.command_exists("bpftool")
                    && probe.bpffs_mounted()
                    && probe.artifact_available()) =>
            {
                Err(BackendError::Unavailable(
                    "eBPF backend unavailable: require tc and bpftool commands, bpffs mounted at \
                     /sys/fs/bpf, and a regular nonempty ELF eBPF program artifact"
                        .into(),
                ))
            }
            Self::Iptables if !probe.command_exists("iptables") => Err(BackendError::Unavailable(
                "iptables backend unavailable: install the iptables package (command not found)"
                    .into(),
            )),
            Self::Nftables if !probe.command_exists("nft") => Err(BackendError::Unavailable(
                "nftables backend unavailable: install the nftables package (command not found)"
                    .into(),
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
        bpftool_available: bool,
        bpffs_mounted: bool,
        artifact_available: bool,
    }

    impl FakeProbe {
        fn unavailable() -> Self {
            Self {
                tc_available: false,
                bpftool_available: false,
                bpffs_mounted: false,
                artifact_available: false,
            }
        }

        fn available() -> Self {
            Self {
                tc_available: true,
                bpftool_available: true,
                bpffs_mounted: true,
                artifact_available: true,
            }
        }
    }

    impl BackendProbe for FakeProbe {
        fn command_exists(&self, command: &str) -> bool {
            match command {
                "tc" => self.tc_available,
                "bpftool" => self.bpftool_available,
                _ => false,
            }
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
    fn ebpf_requires_tc() {
        let mut probe = FakeProbe::available();
        probe.tc_available = false;
        assert!(NetworkBackend::Ebpf.ensure_available(&probe).is_err());
    }

    #[test]
    fn ebpf_requires_bpftool() {
        let mut probe = FakeProbe::available();
        probe.bpftool_available = false;
        assert!(NetworkBackend::Ebpf.ensure_available(&probe).is_err());
    }

    #[test]
    fn ebpf_requires_bpffs() {
        let mut probe = FakeProbe::available();
        probe.bpffs_mounted = false;
        assert!(NetworkBackend::Ebpf.ensure_available(&probe).is_err());
    }

    #[test]
    fn ebpf_requires_valid_artifact() {
        let mut probe = FakeProbe::available();
        probe.artifact_available = false;
        assert!(NetworkBackend::Ebpf.ensure_available(&probe).is_err());
    }

    #[test]
    fn ebpf_accepts_all_task_one_prerequisites() {
        NetworkBackend::Ebpf
            .ensure_available(&FakeProbe::available())
            .expect("all eBPF prerequisites available");
    }

    #[test]
    fn explicit_firewall_backends_remain_selected() {
        assert_eq!("iptables".parse(), Ok(NetworkBackend::Iptables));
        assert_eq!("nftables".parse(), Ok(NetworkBackend::Nftables));
    }

    #[test]
    fn missing_packet_filter_backend_names_the_install_package() {
        let probe = FakeProbe::unavailable();
        assert_eq!(
            NetworkBackend::Iptables
                .ensure_available(&probe)
                .unwrap_err()
                .to_string(),
            "iptables backend unavailable: install the iptables package (command not found)"
        );
        assert_eq!(
            NetworkBackend::Nftables
                .ensure_available(&probe)
                .unwrap_err()
                .to_string(),
            "nftables backend unavailable: install the nftables package (command not found)"
        );
    }
}
