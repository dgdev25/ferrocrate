#![allow(dead_code)]

pub const PROGRAM_ABI_VERSION: u32 = 1;

pub const ENDPOINTS_MAP_NAME: &str = "FERRO_ENDPOINTS";
pub const PORTS_MAP_NAME: &str = "FERRO_PORTS";
pub const CONNTRACK_MAP_NAME: &str = "FERRO_CONNTRACK";
pub const POLICY_MAP_NAME: &str = "FERRO_POLICY";
pub const META_MAP_NAME: &str = "FERRO_META";

pub const ENDPOINT_KEY_LEN: usize = 4;
pub const ENDPOINT_VALUE_LEN: usize = 12;
pub const PORT_KEY_LEN: usize = 4;
pub const PORT_VALUE_LEN: usize = 8;
pub const CONNTRACK_KEY_LEN: usize = 16;
pub const CONNTRACK_VALUE_LEN: usize = 16;
pub const POLICY_KEY_LEN: usize = 8;
pub const POLICY_VALUE_LEN: usize = 4;
pub const META_KEY_LEN: usize = 4;
pub const META_VALUE_LEN: usize = 4;

const ENDPOINT_ADDRESS_OFFSET: usize = 0;
const ENDPOINT_IFINDEX_OFFSET: usize = 0;
const ENDPOINT_MAC_OFFSET: usize = 4;
const ENDPOINT_FLAGS_OFFSET: usize = 10;
const PORT_PROTOCOL_OFFSET: usize = 0;
const PORT_NUMBER_OFFSET: usize = 2;
const PORT_VALUE_ADDRESS_OFFSET: usize = 0;
const PORT_VALUE_NUMBER_OFFSET: usize = 4;
const CONNTRACK_PROTOCOL_OFFSET: usize = 0;
const CONNTRACK_SOURCE_ADDRESS_OFFSET: usize = 4;
const CONNTRACK_DESTINATION_ADDRESS_OFFSET: usize = 8;
const CONNTRACK_SOURCE_PORT_OFFSET: usize = 12;
const CONNTRACK_DESTINATION_PORT_OFFSET: usize = 14;
const CONNTRACK_TRANSLATED_ADDRESS_OFFSET: usize = 0;
const CONNTRACK_TRANSLATED_PORT_OFFSET: usize = 4;
const CONNTRACK_STATE_OFFSET: usize = 6;
const CONNTRACK_LAST_SEEN_OFFSET: usize = 8;
const POLICY_ADDRESS_OFFSET: usize = 0;
const POLICY_PROTOCOL_OFFSET: usize = 4;
const POLICY_DIRECTION_OFFSET: usize = 5;
const POLICY_PORT_OFFSET: usize = 6;
const POLICY_ACTION_OFFSET: usize = 0;
const POLICY_LOG_OFFSET: usize = 1;

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
mod ebpf_abi_tests {
    use super::{PortKey, PROGRAM_ABI_VERSION};

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
}
