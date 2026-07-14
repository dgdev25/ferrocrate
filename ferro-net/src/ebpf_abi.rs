#![allow(dead_code)]

pub const PROGRAM_ABI_VERSION: u32 = 2;

pub const ENDPOINTS_MAP_NAME: &str = "FERRO_ENDPOINTS";
pub const PORTS_MAP_NAME: &str = "FERRO_PORTS";
pub const CONNTRACK_MAP_NAME: &str = "FERRO_CONNTRACK";
pub const POLICY_MAP_NAME: &str = "FERRO_POLICY";
pub const META_MAP_NAME: &str = "FERRO_META";
pub const COUNTERS_MAP_NAME: &str = "FERRO_COUNTERS";

pub const ENDPOINT_KEY_LEN: usize = 4;
pub const ENDPOINT_VALUE_LEN: usize = 12;
pub const PORT_KEY_LEN: usize = 4;
pub const PORT_VALUE_LEN: usize = 8;
pub const CONNTRACK_KEY_LEN: usize = 16;
pub const CONNTRACK_VALUE_LEN: usize = 16;
pub const POLICY_KEY_LEN: usize = 8;
pub const POLICY_VALUE_LEN: usize = 4;
pub const META_VALUE_LEN: usize = 28;

pub const META_ABI_VERSION_OFFSET: usize = 0;
pub const META_EXTERNAL_IPV4_OFFSET: usize = 4;
pub const META_EXTERNAL_IFINDEX_OFFSET: usize = 8;
pub const META_NEXT_HOP_MAC_OFFSET: usize = 12;
pub const META_SNAT_RANGE_START_OFFSET: usize = 18;
pub const META_SNAT_RANGE_END_OFFSET: usize = 20;
pub const META_FLAGS_OFFSET: usize = 22;
pub const META_LOOPBACK_IFINDEX_OFFSET: usize = 24;
pub const META_FLAG_SNAT_RANGE_RESERVED: u16 = 1;

pub const ENDPOINT_MAX_ENTRIES: u32 = 16_384;
pub const PORT_MAX_ENTRIES: u32 = 16_384;
pub const CONNTRACK_MAX_ENTRIES: u32 = 65_536;
pub const POLICY_MAX_ENTRIES: u32 = 32_768;
pub const META_MAX_ENTRIES: u32 = 1;
pub const COUNTER_MAX_ENTRIES: u32 = 10;

pub const ENDPOINT_ADDRESS_OFFSET: usize = 0;
pub const ENDPOINT_IFINDEX_OFFSET: usize = 0;
pub const ENDPOINT_MAC_OFFSET: usize = 4;
pub const ENDPOINT_FLAGS_OFFSET: usize = 10;
pub const PORT_PROTOCOL_OFFSET: usize = 0;
pub const PORT_NUMBER_OFFSET: usize = 2;
pub const PORT_VALUE_ADDRESS_OFFSET: usize = 0;
pub const PORT_VALUE_NUMBER_OFFSET: usize = 4;
pub const CONNTRACK_PROTOCOL_OFFSET: usize = 0;
pub const CONNTRACK_SOURCE_ADDRESS_OFFSET: usize = 4;
pub const CONNTRACK_DESTINATION_ADDRESS_OFFSET: usize = 8;
pub const CONNTRACK_SOURCE_PORT_OFFSET: usize = 12;
pub const CONNTRACK_DESTINATION_PORT_OFFSET: usize = 14;
pub const CONNTRACK_TRANSLATED_ADDRESS_OFFSET: usize = 0;
pub const CONNTRACK_TRANSLATED_PORT_OFFSET: usize = 4;
pub const CONNTRACK_STATE_OFFSET: usize = 6;
pub const CONNTRACK_LAST_SEEN_OFFSET: usize = 8;
pub const POLICY_ADDRESS_OFFSET: usize = 0;
pub const POLICY_PROTOCOL_OFFSET: usize = 4;
pub const POLICY_DIRECTION_OFFSET: usize = 5;
pub const POLICY_PORT_OFFSET: usize = 6;
pub const POLICY_ACTION_OFFSET: usize = 0;
pub const POLICY_LOG_OFFSET: usize = 1;

const _: () = {
    assert!(ENDPOINT_ADDRESS_OFFSET + 4 == ENDPOINT_KEY_LEN);
    assert!(ENDPOINT_IFINDEX_OFFSET + 4 == ENDPOINT_MAC_OFFSET);
    assert!(ENDPOINT_MAC_OFFSET + 6 == ENDPOINT_FLAGS_OFFSET);
    assert!(ENDPOINT_FLAGS_OFFSET + 2 == ENDPOINT_VALUE_LEN);
    assert!(PORT_PROTOCOL_OFFSET == 0);
    assert!(PORT_NUMBER_OFFSET + 2 == PORT_KEY_LEN);
    assert!(PORT_VALUE_ADDRESS_OFFSET + 4 == PORT_VALUE_NUMBER_OFFSET);
    assert!(PORT_VALUE_NUMBER_OFFSET + 4 == PORT_VALUE_LEN);
    assert!(CONNTRACK_PROTOCOL_OFFSET == 0);
    assert!(CONNTRACK_SOURCE_ADDRESS_OFFSET + 4 == CONNTRACK_DESTINATION_ADDRESS_OFFSET);
    assert!(CONNTRACK_DESTINATION_ADDRESS_OFFSET + 4 == CONNTRACK_SOURCE_PORT_OFFSET);
    assert!(CONNTRACK_SOURCE_PORT_OFFSET + 2 == CONNTRACK_DESTINATION_PORT_OFFSET);
    assert!(CONNTRACK_DESTINATION_PORT_OFFSET + 2 == CONNTRACK_KEY_LEN);
    assert!(CONNTRACK_TRANSLATED_ADDRESS_OFFSET + 4 == CONNTRACK_TRANSLATED_PORT_OFFSET);
    assert!(CONNTRACK_TRANSLATED_PORT_OFFSET + 2 == CONNTRACK_STATE_OFFSET);
    assert!(CONNTRACK_STATE_OFFSET + 2 == CONNTRACK_LAST_SEEN_OFFSET);
    assert!(CONNTRACK_LAST_SEEN_OFFSET + 8 == CONNTRACK_VALUE_LEN);
    assert!(POLICY_ADDRESS_OFFSET + 4 == POLICY_PROTOCOL_OFFSET);
    assert!(POLICY_PROTOCOL_OFFSET + 1 == POLICY_DIRECTION_OFFSET);
    assert!(POLICY_DIRECTION_OFFSET + 1 == POLICY_PORT_OFFSET);
    assert!(POLICY_PORT_OFFSET + 2 == POLICY_KEY_LEN);
    assert!(POLICY_ACTION_OFFSET + 1 == POLICY_LOG_OFFSET);
    assert!(POLICY_LOG_OFFSET + 3 == POLICY_VALUE_LEN);
    assert!(META_ABI_VERSION_OFFSET + 4 == META_EXTERNAL_IPV4_OFFSET);
    assert!(META_EXTERNAL_IPV4_OFFSET + 4 == META_EXTERNAL_IFINDEX_OFFSET);
    assert!(META_EXTERNAL_IFINDEX_OFFSET + 4 == META_NEXT_HOP_MAC_OFFSET);
    assert!(META_NEXT_HOP_MAC_OFFSET + 6 == META_SNAT_RANGE_START_OFFSET);
    assert!(META_SNAT_RANGE_START_OFFSET + 2 == META_SNAT_RANGE_END_OFFSET);
    assert!(META_SNAT_RANGE_END_OFFSET + 2 == META_FLAGS_OFFSET);
    assert!(META_FLAGS_OFFSET + 2 == META_LOOPBACK_IFINDEX_OFFSET);
    assert!(META_LOOPBACK_IFINDEX_OFFSET + 4 == META_VALUE_LEN);
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetaConfig {
    pub abi_version: u32,
    pub external_ipv4: [u8; 4],
    pub external_ifindex: u32,
    pub loopback_ifindex: u32,
    pub next_hop_mac: [u8; 6],
    pub snat_port_start: u16,
    pub snat_port_end: u16,
    pub flags: u16,
}

impl MetaConfig {
    /// Encodes the one coherent metadata value shared by userspace and eBPF.
    ///
    /// Userspace may set `META_FLAG_SNAT_RANGE_RESERVED` only after verifying
    /// the entire inclusive range is present in Linux `ip_local_reserved_ports`.
    /// Task 7 must exercise that binding in privileged integration tests.
    pub fn encode(&self) -> [u8; META_VALUE_LEN] {
        let mut bytes = [0; META_VALUE_LEN];
        bytes[META_ABI_VERSION_OFFSET..META_EXTERNAL_IPV4_OFFSET]
            .copy_from_slice(&self.abi_version.to_be_bytes());
        bytes[META_EXTERNAL_IPV4_OFFSET..META_EXTERNAL_IFINDEX_OFFSET]
            .copy_from_slice(&self.external_ipv4);
        bytes[META_EXTERNAL_IFINDEX_OFFSET..META_NEXT_HOP_MAC_OFFSET]
            .copy_from_slice(&self.external_ifindex.to_be_bytes());
        bytes[META_LOOPBACK_IFINDEX_OFFSET..META_VALUE_LEN]
            .copy_from_slice(&self.loopback_ifindex.to_be_bytes());
        bytes[META_NEXT_HOP_MAC_OFFSET..META_SNAT_RANGE_START_OFFSET]
            .copy_from_slice(&self.next_hop_mac);
        bytes[META_SNAT_RANGE_START_OFFSET..META_SNAT_RANGE_END_OFFSET]
            .copy_from_slice(&self.snat_port_start.to_be_bytes());
        bytes[META_SNAT_RANGE_END_OFFSET..META_FLAGS_OFFSET]
            .copy_from_slice(&self.snat_port_end.to_be_bytes());
        bytes[META_FLAGS_OFFSET..META_VALUE_LEN].copy_from_slice(&self.flags.to_be_bytes());
        bytes
    }

    pub fn decode(bytes: [u8; META_VALUE_LEN]) -> Self {
        Self {
            abi_version: u32::from_be_bytes(
                bytes[META_ABI_VERSION_OFFSET..META_EXTERNAL_IPV4_OFFSET]
                    .try_into()
                    .expect("fixed metadata ABI version range"),
            ),
            external_ipv4: bytes[META_EXTERNAL_IPV4_OFFSET..META_EXTERNAL_IFINDEX_OFFSET]
                .try_into()
                .expect("fixed metadata IPv4 range"),
            external_ifindex: u32::from_be_bytes(
                bytes[META_EXTERNAL_IFINDEX_OFFSET..META_NEXT_HOP_MAC_OFFSET]
                    .try_into()
                    .expect("fixed metadata ifindex range"),
            ),
            loopback_ifindex: u32::from_be_bytes(
                bytes[META_LOOPBACK_IFINDEX_OFFSET..META_VALUE_LEN]
                    .try_into()
                    .expect("fixed metadata loopback ifindex range"),
            ),
            next_hop_mac: bytes[META_NEXT_HOP_MAC_OFFSET..META_SNAT_RANGE_START_OFFSET]
                .try_into()
                .expect("fixed metadata next-hop MAC range"),
            snat_port_start: u16::from_be_bytes(
                bytes[META_SNAT_RANGE_START_OFFSET..META_SNAT_RANGE_END_OFFSET]
                    .try_into()
                    .expect("fixed metadata SNAT start range"),
            ),
            snat_port_end: u16::from_be_bytes(
                bytes[META_SNAT_RANGE_END_OFFSET..META_FLAGS_OFFSET]
                    .try_into()
                    .expect("fixed metadata SNAT end range"),
            ),
            flags: u16::from_be_bytes(
                bytes[META_FLAGS_OFFSET..META_VALUE_LEN]
                    .try_into()
                    .expect("fixed metadata flags range"),
            ),
        }
    }

    pub fn snat_range_reserved(&self) -> bool {
        self.flags & META_FLAG_SNAT_RANGE_RESERVED != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointKey {
    pub address: [u8; 4],
}

impl EndpointKey {
    pub fn encode(&self) -> [u8; ENDPOINT_KEY_LEN] {
        self.address
    }

    pub fn decode(bytes: [u8; ENDPOINT_KEY_LEN]) -> Self {
        Self { address: bytes }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointValue {
    pub ifindex: u32,
    pub mac: [u8; 6],
    pub flags: u8,
}

impl EndpointValue {
    pub fn encode(&self) -> [u8; ENDPOINT_VALUE_LEN] {
        let mut bytes = [0; ENDPOINT_VALUE_LEN];
        bytes[ENDPOINT_IFINDEX_OFFSET..ENDPOINT_MAC_OFFSET]
            .copy_from_slice(&self.ifindex.to_be_bytes());
        bytes[ENDPOINT_MAC_OFFSET..ENDPOINT_FLAGS_OFFSET].copy_from_slice(&self.mac);
        bytes[ENDPOINT_FLAGS_OFFSET] = self.flags;
        bytes
    }

    pub fn decode(bytes: [u8; ENDPOINT_VALUE_LEN]) -> Self {
        Self {
            ifindex: u32::from_be_bytes(
                bytes[ENDPOINT_IFINDEX_OFFSET..ENDPOINT_MAC_OFFSET]
                    .try_into()
                    .expect("fixed endpoint ifindex range"),
            ),
            mac: bytes[ENDPOINT_MAC_OFFSET..ENDPOINT_FLAGS_OFFSET]
                .try_into()
                .expect("fixed endpoint MAC range"),
            flags: bytes[ENDPOINT_FLAGS_OFFSET],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortKey {
    pub protocol: u8,
    pub host_port: u16,
}

impl PortKey {
    pub fn encode(&self) -> [u8; PORT_KEY_LEN] {
        let port = self.host_port.to_be_bytes();
        [self.protocol, 0, port[0], port[1]]
    }

    pub fn decode(bytes: [u8; PORT_KEY_LEN]) -> Self {
        Self {
            protocol: bytes[PORT_PROTOCOL_OFFSET],
            host_port: u16::from_be_bytes(
                bytes[PORT_NUMBER_OFFSET..PORT_KEY_LEN]
                    .try_into()
                    .expect("fixed port key range"),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortValue {
    pub endpoint_address: [u8; 4],
    pub endpoint_port: u16,
}

impl PortValue {
    pub fn encode(&self) -> [u8; PORT_VALUE_LEN] {
        let mut bytes = [0; PORT_VALUE_LEN];
        bytes[PORT_VALUE_ADDRESS_OFFSET..PORT_VALUE_NUMBER_OFFSET]
            .copy_from_slice(&self.endpoint_address);
        bytes[PORT_VALUE_NUMBER_OFFSET..PORT_VALUE_NUMBER_OFFSET + 2]
            .copy_from_slice(&self.endpoint_port.to_be_bytes());
        bytes
    }

    pub fn decode(bytes: [u8; PORT_VALUE_LEN]) -> Self {
        Self {
            endpoint_address: bytes[PORT_VALUE_ADDRESS_OFFSET..PORT_VALUE_NUMBER_OFFSET]
                .try_into()
                .expect("fixed port address range"),
            endpoint_port: u16::from_be_bytes(
                bytes[PORT_VALUE_NUMBER_OFFSET..PORT_VALUE_NUMBER_OFFSET + 2]
                    .try_into()
                    .expect("fixed endpoint port range"),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConntrackKey {
    pub protocol: u8,
    pub source_address: [u8; 4],
    pub destination_address: [u8; 4],
    pub source_port: u16,
    pub destination_port: u16,
}

impl ConntrackKey {
    pub fn encode(&self) -> [u8; CONNTRACK_KEY_LEN] {
        let mut bytes = [0; CONNTRACK_KEY_LEN];
        bytes[CONNTRACK_PROTOCOL_OFFSET] = self.protocol;
        bytes[CONNTRACK_SOURCE_ADDRESS_OFFSET..CONNTRACK_DESTINATION_ADDRESS_OFFSET]
            .copy_from_slice(&self.source_address);
        bytes[CONNTRACK_DESTINATION_ADDRESS_OFFSET..CONNTRACK_SOURCE_PORT_OFFSET]
            .copy_from_slice(&self.destination_address);
        bytes[CONNTRACK_SOURCE_PORT_OFFSET..CONNTRACK_DESTINATION_PORT_OFFSET]
            .copy_from_slice(&self.source_port.to_be_bytes());
        bytes[CONNTRACK_DESTINATION_PORT_OFFSET..CONNTRACK_KEY_LEN]
            .copy_from_slice(&self.destination_port.to_be_bytes());
        bytes
    }

    pub fn decode(bytes: [u8; CONNTRACK_KEY_LEN]) -> Self {
        Self {
            protocol: bytes[CONNTRACK_PROTOCOL_OFFSET],
            source_address: bytes
                [CONNTRACK_SOURCE_ADDRESS_OFFSET..CONNTRACK_DESTINATION_ADDRESS_OFFSET]
                .try_into()
                .expect("fixed conntrack source address range"),
            destination_address: bytes
                [CONNTRACK_DESTINATION_ADDRESS_OFFSET..CONNTRACK_SOURCE_PORT_OFFSET]
                .try_into()
                .expect("fixed conntrack destination address range"),
            source_port: u16::from_be_bytes(
                bytes[CONNTRACK_SOURCE_PORT_OFFSET..CONNTRACK_DESTINATION_PORT_OFFSET]
                    .try_into()
                    .expect("fixed conntrack source port range"),
            ),
            destination_port: u16::from_be_bytes(
                bytes[CONNTRACK_DESTINATION_PORT_OFFSET..CONNTRACK_KEY_LEN]
                    .try_into()
                    .expect("fixed conntrack destination port range"),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConntrackValue {
    pub translated_address: [u8; 4],
    pub translated_port: u16,
    pub state: u8,
    pub last_seen_ns: u64,
}

impl ConntrackValue {
    pub fn encode(&self) -> [u8; CONNTRACK_VALUE_LEN] {
        let mut bytes = [0; CONNTRACK_VALUE_LEN];
        bytes[CONNTRACK_TRANSLATED_ADDRESS_OFFSET..CONNTRACK_TRANSLATED_PORT_OFFSET]
            .copy_from_slice(&self.translated_address);
        bytes[CONNTRACK_TRANSLATED_PORT_OFFSET..CONNTRACK_STATE_OFFSET]
            .copy_from_slice(&self.translated_port.to_be_bytes());
        bytes[CONNTRACK_STATE_OFFSET] = self.state;
        bytes[CONNTRACK_LAST_SEEN_OFFSET..CONNTRACK_VALUE_LEN]
            .copy_from_slice(&self.last_seen_ns.to_be_bytes());
        bytes
    }

    pub fn decode(bytes: [u8; CONNTRACK_VALUE_LEN]) -> Self {
        Self {
            translated_address: bytes
                [CONNTRACK_TRANSLATED_ADDRESS_OFFSET..CONNTRACK_TRANSLATED_PORT_OFFSET]
                .try_into()
                .expect("fixed translated address range"),
            translated_port: u16::from_be_bytes(
                bytes[CONNTRACK_TRANSLATED_PORT_OFFSET..CONNTRACK_STATE_OFFSET]
                    .try_into()
                    .expect("fixed translated port range"),
            ),
            state: bytes[CONNTRACK_STATE_OFFSET],
            last_seen_ns: u64::from_be_bytes(
                bytes[CONNTRACK_LAST_SEEN_OFFSET..CONNTRACK_VALUE_LEN]
                    .try_into()
                    .expect("fixed conntrack timestamp range"),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyKey {
    pub endpoint_address: [u8; 4],
    pub protocol: u8,
    pub direction: u8,
    pub port: u16,
}

impl PolicyKey {
    pub fn encode(&self) -> [u8; POLICY_KEY_LEN] {
        let mut bytes = [0; POLICY_KEY_LEN];
        bytes[POLICY_ADDRESS_OFFSET..POLICY_PROTOCOL_OFFSET]
            .copy_from_slice(&self.endpoint_address);
        bytes[POLICY_PROTOCOL_OFFSET] = self.protocol;
        bytes[POLICY_DIRECTION_OFFSET] = self.direction;
        bytes[POLICY_PORT_OFFSET..POLICY_KEY_LEN].copy_from_slice(&self.port.to_be_bytes());
        bytes
    }

    pub fn decode(bytes: [u8; POLICY_KEY_LEN]) -> Self {
        Self {
            endpoint_address: bytes[POLICY_ADDRESS_OFFSET..POLICY_PROTOCOL_OFFSET]
                .try_into()
                .expect("fixed policy address range"),
            protocol: bytes[POLICY_PROTOCOL_OFFSET],
            direction: bytes[POLICY_DIRECTION_OFFSET],
            port: u16::from_be_bytes(
                bytes[POLICY_PORT_OFFSET..POLICY_KEY_LEN]
                    .try_into()
                    .expect("fixed policy port range"),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyValue {
    pub action: u8,
    pub log: bool,
}

impl PolicyValue {
    pub fn encode(&self) -> [u8; POLICY_VALUE_LEN] {
        let mut bytes = [0; POLICY_VALUE_LEN];
        bytes[POLICY_ACTION_OFFSET] = self.action;
        bytes[POLICY_LOG_OFFSET] = u8::from(self.log);
        bytes
    }

    pub fn decode(bytes: [u8; POLICY_VALUE_LEN]) -> Self {
        Self {
            action: bytes[POLICY_ACTION_OFFSET],
            log: bytes[POLICY_LOG_OFFSET] != 0,
        }
    }
}

#[cfg(test)]
#[path = "../../ferro-net-ebpf/src/abi.rs"]
mod kernel_abi;

#[cfg(test)]
mod ebpf_abi_tests {
    use super::{kernel_abi, PortKey, PROGRAM_ABI_VERSION};

    #[test]
    fn port_key_is_stable_network_byte_order() {
        let key = PortKey {
            protocol: 6,
            host_port: 8080,
        };
        assert_eq!(key.encode(), [6, 0, 0x1f, 0x90]);
    }

    #[test]
    fn abi_version_is_nonzero() {
        assert_eq!(PROGRAM_ABI_VERSION, 1);
    }

    #[test]
    fn build_script_tracks_ebpf_inputs_and_environment() {
        let build_script = include_str!("../build.rs");
        for input in [
            "../ferro-net-ebpf/Cargo.toml",
            "../ferro-net-ebpf/src",
            "../ferro-net-ebpf/src/main.rs",
            "../ferro-net-ebpf/src/abi.rs",
        ] {
            assert!(build_script.contains(input), "missing rerun input {input}");
        }
        for variable in [
            "AYA_BUILD_SKIP",
            "AYA_BPF_TARGET_ARCH",
            "BPF_LINKER",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_HOME",
            "PATH",
            "RUSTC",
            "RUSTC_BOOTSTRAP",
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTFLAGS",
            "RUSTUP_HOME",
            "RUSTUP_TOOLCHAIN",
        ] {
            assert!(
                build_script.contains(variable),
                "missing rerun environment variable {variable}"
            );
        }
    }

    #[test]
    fn userspace_inherits_workspace_lints() {
        let manifest = include_str!("../Cargo.toml");
        assert!(manifest.contains("[lints]\nworkspace = true"));
    }

    #[test]
    fn kernel_offsets_match_userspace_abi() {
        macro_rules! assert_offset {
            ($name:ident) => {
                assert_eq!(super::$name, kernel_abi::$name, stringify!($name));
            };
        }

        assert_offset!(ENDPOINT_ADDRESS_OFFSET);
        assert_offset!(ENDPOINT_IFINDEX_OFFSET);
        assert_offset!(ENDPOINT_MAC_OFFSET);
        assert_offset!(ENDPOINT_FLAGS_OFFSET);
        assert_offset!(PORT_PROTOCOL_OFFSET);
        assert_offset!(PORT_NUMBER_OFFSET);
        assert_offset!(PORT_VALUE_ADDRESS_OFFSET);
        assert_offset!(PORT_VALUE_NUMBER_OFFSET);
        assert_offset!(CONNTRACK_PROTOCOL_OFFSET);
        assert_offset!(CONNTRACK_SOURCE_ADDRESS_OFFSET);
        assert_offset!(CONNTRACK_DESTINATION_ADDRESS_OFFSET);
        assert_offset!(CONNTRACK_SOURCE_PORT_OFFSET);
        assert_offset!(CONNTRACK_DESTINATION_PORT_OFFSET);
        assert_offset!(CONNTRACK_TRANSLATED_ADDRESS_OFFSET);
        assert_offset!(CONNTRACK_TRANSLATED_PORT_OFFSET);
        assert_offset!(CONNTRACK_STATE_OFFSET);
        assert_offset!(CONNTRACK_LAST_SEEN_OFFSET);
        assert_offset!(POLICY_ADDRESS_OFFSET);
        assert_offset!(POLICY_PROTOCOL_OFFSET);
        assert_offset!(POLICY_DIRECTION_OFFSET);
        assert_offset!(POLICY_PORT_OFFSET);
        assert_offset!(POLICY_ACTION_OFFSET);
        assert_offset!(POLICY_LOG_OFFSET);
    }
}
