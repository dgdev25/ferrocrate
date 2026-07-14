use aya_ebpf::{
    macros::map,
    maps::{Array, HashMap, LruHashMap, PerCpuArray},
};

use crate::{
    abi::{
        CONNTRACK_KEY_LEN, CONNTRACK_LAST_SEEN_OFFSET, CONNTRACK_STATE_OFFSET,
        CONNTRACK_TRANSLATED_ADDRESS_OFFSET, CONNTRACK_TRANSLATED_PORT_OFFSET,
        CONNTRACK_VALUE_LEN, ENDPOINT_FLAGS_OFFSET, ENDPOINT_IFINDEX_OFFSET, ENDPOINT_KEY_LEN,
        ENDPOINT_MAC_OFFSET, ENDPOINT_VALUE_LEN, META_VALUE_LEN, POLICY_ACTION_OFFSET,
        POLICY_KEY_LEN, POLICY_VALUE_LEN, PORT_KEY_LEN, PORT_VALUE_ADDRESS_OFFSET,
        PORT_VALUE_LEN, PORT_VALUE_NUMBER_OFFSET,
    },
    datapath::{
        ConntrackRecord, Counter, DatapathState, Endpoint, FlowKey, NatTarget, PolicyAction,
        PolicyKey, PortTarget, CONNTRACK_MAX_ENTRIES, CONNTRACK_STATE_ESTABLISHED,
        COUNTER_MAX_ENTRIES, ENDPOINT_MAX_ENTRIES, META_MAX_ENTRIES, POLICY_ACTION_ALLOW,
        POLICY_MAX_ENTRIES, PORT_MAX_ENTRIES,
    },
};

#[map]
pub static FERRO_ENDPOINTS: HashMap<[u8; ENDPOINT_KEY_LEN], [u8; ENDPOINT_VALUE_LEN]> =
    HashMap::with_max_entries(ENDPOINT_MAX_ENTRIES, 0);

#[map]
pub static FERRO_PORTS: HashMap<[u8; PORT_KEY_LEN], [u8; PORT_VALUE_LEN]> =
    HashMap::with_max_entries(PORT_MAX_ENTRIES, 0);

#[map]
pub static FERRO_CONNTRACK: LruHashMap<[u8; CONNTRACK_KEY_LEN], [u8; CONNTRACK_VALUE_LEN]> =
    LruHashMap::with_max_entries(CONNTRACK_MAX_ENTRIES, 0);

#[map]
pub static FERRO_POLICY: HashMap<[u8; POLICY_KEY_LEN], [u8; POLICY_VALUE_LEN]> =
    HashMap::with_max_entries(POLICY_MAX_ENTRIES, 0);

#[map]
pub static FERRO_COUNTERS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(COUNTER_MAX_ENTRIES, 0);

#[map]
pub static FERRO_META: Array<[u8; META_VALUE_LEN]> =
    Array::with_max_entries(META_MAX_ENTRIES, 0);

pub struct KernelState;

fn copied_map_value<const N: usize>(pointer: Option<*const [u8; N]>) -> Option<[u8; N]> {
    let pointer = pointer?;
    // SAFETY: Aya returned a pointer to a fixed-size map value of exactly N bytes.
    // The value is copied immediately, before this program performs another
    // operation on the same map, so no map-backed reference escapes the lookup.
    Some(unsafe { pointer.read_unaligned() })
}

impl DatapathState for KernelState {
    fn policy(&self, key: PolicyKey) -> Option<PolicyAction> {
        let value = copied_map_value(FERRO_POLICY.get_ptr(key.encode()))?;
        if value[POLICY_ACTION_OFFSET] == POLICY_ACTION_ALLOW {
            Some(PolicyAction::Allow)
        } else {
            Some(PolicyAction::Deny)
        }
    }

    fn conntrack(&self, key: FlowKey) -> Option<NatTarget> {
        let value = copied_map_value(FERRO_CONNTRACK.get_ptr(key.encode()))?;
        if value[CONNTRACK_STATE_OFFSET] != CONNTRACK_STATE_ESTABLISHED {
            return None;
        }
        Some(NatTarget {
            address: [
                value[CONNTRACK_TRANSLATED_ADDRESS_OFFSET],
                value[CONNTRACK_TRANSLATED_ADDRESS_OFFSET + 1],
                value[CONNTRACK_TRANSLATED_ADDRESS_OFFSET + 2],
                value[CONNTRACK_TRANSLATED_ADDRESS_OFFSET + 3],
            ],
            port: u16::from_be_bytes([
                value[CONNTRACK_TRANSLATED_PORT_OFFSET],
                value[CONNTRACK_TRANSLATED_PORT_OFFSET + 1],
            ]),
        })
    }

    fn published_port(&self, protocol: u8, host_port: u16) -> Option<PortTarget> {
        let port = host_port.to_be_bytes();
        let key = [protocol, 0, port[0], port[1]];
        let value = copied_map_value(FERRO_PORTS.get_ptr(key))?;
        Some(PortTarget {
            address: [
                value[PORT_VALUE_ADDRESS_OFFSET],
                value[PORT_VALUE_ADDRESS_OFFSET + 1],
                value[PORT_VALUE_ADDRESS_OFFSET + 2],
                value[PORT_VALUE_ADDRESS_OFFSET + 3],
            ],
            port: u16::from_be_bytes([
                value[PORT_VALUE_NUMBER_OFFSET],
                value[PORT_VALUE_NUMBER_OFFSET + 1],
            ]),
        })
    }

    fn endpoint(&self, address: [u8; 4]) -> Option<Endpoint> {
        let value = copied_map_value(FERRO_ENDPOINTS.get_ptr(address))?;
        Some(Endpoint {
            ifindex: u32::from_be_bytes([
                value[ENDPOINT_IFINDEX_OFFSET],
                value[ENDPOINT_IFINDEX_OFFSET + 1],
                value[ENDPOINT_IFINDEX_OFFSET + 2],
                value[ENDPOINT_IFINDEX_OFFSET + 3],
            ]),
            mac: [
                value[ENDPOINT_MAC_OFFSET],
                value[ENDPOINT_MAC_OFFSET + 1],
                value[ENDPOINT_MAC_OFFSET + 2],
                value[ENDPOINT_MAC_OFFSET + 3],
                value[ENDPOINT_MAC_OFFSET + 4],
                value[ENDPOINT_MAC_OFFSET + 5],
            ],
            flags: value[ENDPOINT_FLAGS_OFFSET],
        })
    }
}

pub fn insert_reverse_conntrack(record: ConntrackRecord, last_seen_ns: u64) -> Result<(), i32> {
    let mut value = [0; CONNTRACK_VALUE_LEN];
    value[CONNTRACK_TRANSLATED_ADDRESS_OFFSET..CONNTRACK_TRANSLATED_ADDRESS_OFFSET + 4]
        .copy_from_slice(&record.target.address);
    value[CONNTRACK_TRANSLATED_PORT_OFFSET..CONNTRACK_TRANSLATED_PORT_OFFSET + 2]
        .copy_from_slice(&record.target.port.to_be_bytes());
    value[CONNTRACK_STATE_OFFSET] = CONNTRACK_STATE_ESTABLISHED;
    value[CONNTRACK_LAST_SEEN_OFFSET..CONNTRACK_LAST_SEEN_OFFSET + 8]
        .copy_from_slice(&last_seen_ns.to_be_bytes());
    FERRO_CONNTRACK.insert(record.key.encode(), value, 0)
}

pub fn increment(counter: Counter) {
    let index = counter.index();
    if index >= COUNTER_MAX_ENTRIES {
        return;
    }
    if let Some(pointer) = FERRO_COUNTERS.get_ptr_mut(index) {
        // SAFETY: the checked index is inside the PerCpuArray's explicit maximum,
        // and Aya returned the current CPU's unique, aligned u64 value pointer.
        // Per-CPU storage requires no cross-CPU atomic operation; wrapping avoids
        // debug/release divergence when a long-lived counter reaches u64::MAX.
        unsafe {
            pointer.write(pointer.read().wrapping_add(1));
        }
    }
}
