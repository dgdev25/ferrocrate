pub const PROGRAM_ABI_VERSION: u32 = 3;

pub const ENDPOINT_KEY_LEN: usize = 4;
pub const ENDPOINT_VALUE_LEN: usize = 12;
pub const PORT_KEY_LEN: usize = 4;
pub const PORT_VALUE_LEN: usize = 8;
pub const CONNTRACK_KEY_LEN: usize = 16;
pub const CONNTRACK_VALUE_LEN: usize = 16;
pub const POLICY_KEY_LEN: usize = 8;
pub const POLICY_VALUE_LEN: usize = 4;
pub const META_VALUE_LEN: usize = 32;

pub const META_ABI_VERSION_OFFSET: usize = 0;
pub const META_EXTERNAL_IPV4_OFFSET: usize = 4;
pub const META_EXTERNAL_IFINDEX_OFFSET: usize = 8;
pub const META_NEXT_HOP_MAC_OFFSET: usize = 12;
pub const META_SNAT_RANGE_START_OFFSET: usize = 18;
pub const META_SNAT_RANGE_END_OFFSET: usize = 20;
pub const META_FLAGS_OFFSET: usize = 22;
pub const META_LOOPBACK_IFINDEX_OFFSET: usize = 24;
pub const META_BRIDGE_GATEWAY_OFFSET: usize = 28;
pub const META_FLAG_SNAT_RANGE_RESERVED: u16 = 1;

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
    assert!(META_LOOPBACK_IFINDEX_OFFSET + 4 == META_BRIDGE_GATEWAY_OFFSET);
    assert!(META_BRIDGE_GATEWAY_OFFSET + 4 == META_VALUE_LEN);
};

pub const ENDPOINT_MAX_ENTRIES: u32 = 16_384;
pub const PORT_MAX_ENTRIES: u32 = 16_384;
pub const CONNTRACK_MAX_ENTRIES: u32 = 65_536;
pub const POLICY_MAX_ENTRIES: u32 = 32_768;
pub const META_MAX_ENTRIES: u32 = 1;
pub const COUNTER_MAX_ENTRIES: u32 = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetaConfig {
    pub abi_version: u32,
    pub external_ipv4: [u8; 4],
    pub external_ifindex: u32,
    pub loopback_ifindex: u32,
    pub bridge_gateway: [u8; 4],
    pub next_hop_mac: [u8; 6],
    pub snat_port_start: u16,
    pub snat_port_end: u16,
    pub flags: u16,
}

impl MetaConfig {
    pub const fn encode(self) -> [u8; META_VALUE_LEN] {
        let mut bytes = [0; META_VALUE_LEN];
        let abi_version = self.abi_version.to_be_bytes();
        bytes[META_ABI_VERSION_OFFSET] = abi_version[0];
        bytes[META_ABI_VERSION_OFFSET + 1] = abi_version[1];
        bytes[META_ABI_VERSION_OFFSET + 2] = abi_version[2];
        bytes[META_ABI_VERSION_OFFSET + 3] = abi_version[3];
        bytes[META_EXTERNAL_IPV4_OFFSET] = self.external_ipv4[0];
        bytes[META_EXTERNAL_IPV4_OFFSET + 1] = self.external_ipv4[1];
        bytes[META_EXTERNAL_IPV4_OFFSET + 2] = self.external_ipv4[2];
        bytes[META_EXTERNAL_IPV4_OFFSET + 3] = self.external_ipv4[3];
        let external_ifindex = self.external_ifindex.to_be_bytes();
        bytes[META_EXTERNAL_IFINDEX_OFFSET] = external_ifindex[0];
        bytes[META_EXTERNAL_IFINDEX_OFFSET + 1] = external_ifindex[1];
        bytes[META_EXTERNAL_IFINDEX_OFFSET + 2] = external_ifindex[2];
        bytes[META_EXTERNAL_IFINDEX_OFFSET + 3] = external_ifindex[3];
        let loopback_ifindex = self.loopback_ifindex.to_be_bytes();
        bytes[META_LOOPBACK_IFINDEX_OFFSET] = loopback_ifindex[0];
        bytes[META_LOOPBACK_IFINDEX_OFFSET + 1] = loopback_ifindex[1];
        bytes[META_LOOPBACK_IFINDEX_OFFSET + 2] = loopback_ifindex[2];
        bytes[META_LOOPBACK_IFINDEX_OFFSET + 3] = loopback_ifindex[3];
        bytes[META_BRIDGE_GATEWAY_OFFSET] = self.bridge_gateway[0];
        bytes[META_BRIDGE_GATEWAY_OFFSET + 1] = self.bridge_gateway[1];
        bytes[META_BRIDGE_GATEWAY_OFFSET + 2] = self.bridge_gateway[2];
        bytes[META_BRIDGE_GATEWAY_OFFSET + 3] = self.bridge_gateway[3];
        bytes[META_NEXT_HOP_MAC_OFFSET] = self.next_hop_mac[0];
        bytes[META_NEXT_HOP_MAC_OFFSET + 1] = self.next_hop_mac[1];
        bytes[META_NEXT_HOP_MAC_OFFSET + 2] = self.next_hop_mac[2];
        bytes[META_NEXT_HOP_MAC_OFFSET + 3] = self.next_hop_mac[3];
        bytes[META_NEXT_HOP_MAC_OFFSET + 4] = self.next_hop_mac[4];
        bytes[META_NEXT_HOP_MAC_OFFSET + 5] = self.next_hop_mac[5];
        let snat_port_start = self.snat_port_start.to_be_bytes();
        bytes[META_SNAT_RANGE_START_OFFSET] = snat_port_start[0];
        bytes[META_SNAT_RANGE_START_OFFSET + 1] = snat_port_start[1];
        let snat_port_end = self.snat_port_end.to_be_bytes();
        bytes[META_SNAT_RANGE_END_OFFSET] = snat_port_end[0];
        bytes[META_SNAT_RANGE_END_OFFSET + 1] = snat_port_end[1];
        let flags = self.flags.to_be_bytes();
        bytes[META_FLAGS_OFFSET] = flags[0];
        bytes[META_FLAGS_OFFSET + 1] = flags[1];
        bytes
    }

    pub const fn decode(bytes: [u8; META_VALUE_LEN]) -> Self {
        Self {
            abi_version: u32::from_be_bytes([
                bytes[META_ABI_VERSION_OFFSET],
                bytes[META_ABI_VERSION_OFFSET + 1],
                bytes[META_ABI_VERSION_OFFSET + 2],
                bytes[META_ABI_VERSION_OFFSET + 3],
            ]),
            external_ipv4: [
                bytes[META_EXTERNAL_IPV4_OFFSET],
                bytes[META_EXTERNAL_IPV4_OFFSET + 1],
                bytes[META_EXTERNAL_IPV4_OFFSET + 2],
                bytes[META_EXTERNAL_IPV4_OFFSET + 3],
            ],
            external_ifindex: u32::from_be_bytes([
                bytes[META_EXTERNAL_IFINDEX_OFFSET],
                bytes[META_EXTERNAL_IFINDEX_OFFSET + 1],
                bytes[META_EXTERNAL_IFINDEX_OFFSET + 2],
                bytes[META_EXTERNAL_IFINDEX_OFFSET + 3],
            ]),
            loopback_ifindex: u32::from_be_bytes([
                bytes[META_LOOPBACK_IFINDEX_OFFSET],
                bytes[META_LOOPBACK_IFINDEX_OFFSET + 1],
                bytes[META_LOOPBACK_IFINDEX_OFFSET + 2],
                bytes[META_LOOPBACK_IFINDEX_OFFSET + 3],
            ]),
            bridge_gateway: [
                bytes[META_BRIDGE_GATEWAY_OFFSET],
                bytes[META_BRIDGE_GATEWAY_OFFSET + 1],
                bytes[META_BRIDGE_GATEWAY_OFFSET + 2],
                bytes[META_BRIDGE_GATEWAY_OFFSET + 3],
            ],
            next_hop_mac: [
                bytes[META_NEXT_HOP_MAC_OFFSET],
                bytes[META_NEXT_HOP_MAC_OFFSET + 1],
                bytes[META_NEXT_HOP_MAC_OFFSET + 2],
                bytes[META_NEXT_HOP_MAC_OFFSET + 3],
                bytes[META_NEXT_HOP_MAC_OFFSET + 4],
                bytes[META_NEXT_HOP_MAC_OFFSET + 5],
            ],
            snat_port_start: u16::from_be_bytes([
                bytes[META_SNAT_RANGE_START_OFFSET],
                bytes[META_SNAT_RANGE_START_OFFSET + 1],
            ]),
            snat_port_end: u16::from_be_bytes([
                bytes[META_SNAT_RANGE_END_OFFSET],
                bytes[META_SNAT_RANGE_END_OFFSET + 1],
            ]),
            flags: u16::from_be_bytes([bytes[META_FLAGS_OFFSET], bytes[META_FLAGS_OFFSET + 1]]),
        }
    }

    pub const fn snat_range_reserved(self) -> bool {
        self.flags & META_FLAG_SNAT_RANGE_RESERVED != 0
    }
}
