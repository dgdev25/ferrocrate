use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::map,
    maps::{HashMap, LruHashMap, PerCpuArray},
};

use crate::{
    abi::{
        CONNTRACK_KEY_LEN, CONNTRACK_LAST_SEEN_OFFSET, CONNTRACK_MAX_ENTRIES,
        CONNTRACK_STATE_OFFSET, CONNTRACK_TRANSLATED_ADDRESS_OFFSET,
        CONNTRACK_TRANSLATED_PORT_OFFSET, CONNTRACK_VALUE_LEN, COUNTER_MAX_ENTRIES,
        ENDPOINT_FLAGS_OFFSET, ENDPOINT_IFINDEX_OFFSET, ENDPOINT_KEY_LEN, ENDPOINT_MAC_OFFSET,
        ENDPOINT_MAX_ENTRIES, ENDPOINT_VALUE_LEN, META_KEY_ABI_VERSION,
        META_KEY_EXTERNAL_IFINDEX, META_KEY_EXTERNAL_IPV4, META_KEY_LEN,
        META_KEY_NEXT_HOP_MAC, META_MAX_ENTRIES, META_VALUE_LEN, POLICY_ACTION_OFFSET,
        POLICY_KEY_LEN, POLICY_MAX_ENTRIES, POLICY_VALUE_LEN, PORT_KEY_LEN, PORT_MAX_ENTRIES,
        PORT_VALUE_ADDRESS_OFFSET, PORT_VALUE_LEN, PORT_VALUE_NUMBER_OFFSET, PROGRAM_ABI_VERSION,
    },
    datapath::{
        ConntrackPair, ConntrackRecord, ConntrackReservation, Counter, DatapathState, Endpoint,
        ExternalNetwork, FlowKey, NatTarget, PolicyAction, PolicyKey, PortTarget,
        CONNTRACK_STATE_ESTABLISHED, POLICY_ACTION_ALLOW,
    },
};

const BPF_ANY: u64 = 0;
const BPF_NOEXIST: u64 = 1;
const EEXIST: i32 = -17;

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
pub static FERRO_META: HashMap<[u8; META_KEY_LEN], [u8; META_VALUE_LEN]> =
    HashMap::with_max_entries(META_MAX_ENTRIES, 0);

pub struct KernelState;

fn copied_map_value<const N: usize>(pointer: Option<*const [u8; N]>) -> Option<[u8; N]> {
    let pointer = pointer?;
    // SAFETY: Aya returned a pointer to a fixed-size map value of exactly N bytes.
    // It is copied before another operation on the same map, so no map reference escapes.
    Some(unsafe { pointer.read_unaligned() })
}

fn metadata_value(key: u32) -> Option<[u8; META_VALUE_LEN]> {
    copied_map_value(FERRO_META.get_ptr(key.to_be_bytes()))
}

fn conntrack_value(record: ConntrackRecord, last_seen_ns: u64) -> [u8; CONNTRACK_VALUE_LEN] {
    let mut value = [0; CONNTRACK_VALUE_LEN];
    value[CONNTRACK_TRANSLATED_ADDRESS_OFFSET..CONNTRACK_TRANSLATED_ADDRESS_OFFSET + 4]
        .copy_from_slice(&record.target.address);
    value[CONNTRACK_TRANSLATED_PORT_OFFSET..CONNTRACK_TRANSLATED_PORT_OFFSET + 2]
        .copy_from_slice(&record.target.port.to_be_bytes());
    value[CONNTRACK_STATE_OFFSET] = CONNTRACK_STATE_ESTABLISHED;
    value[CONNTRACK_LAST_SEEN_OFFSET..CONNTRACK_LAST_SEEN_OFFSET + 8]
        .copy_from_slice(&last_seen_ns.to_be_bytes());
    value
}

fn insert_record(record: ConntrackRecord, flags: u64) -> Result<(), i32> {
    // SAFETY: bpf_ktime_get_ns takes no pointers and returns a scalar monotonic timestamp.
    let now = unsafe { bpf_ktime_get_ns() };
    FERRO_CONNTRACK.insert(record.key.encode(), conntrack_value(record, now), flags)
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
        let value = copied_map_value(FERRO_PORTS.get_ptr([protocol, 0, port[0], port[1]]))?;
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

    fn external_network(&self) -> Option<ExternalNetwork> {
        let version = metadata_value(META_KEY_ABI_VERSION)?;
        if u32::from_be_bytes([version[0], version[1], version[2], version[3]])
            != PROGRAM_ABI_VERSION
        {
            return None;
        }
        let address = metadata_value(META_KEY_EXTERNAL_IPV4)?;
        let ifindex = metadata_value(META_KEY_EXTERNAL_IFINDEX)?;
        let mac = metadata_value(META_KEY_NEXT_HOP_MAC)?;
        Some(ExternalNetwork {
            address: [address[0], address[1], address[2], address[3]],
            ifindex: u32::from_be_bytes([ifindex[0], ifindex[1], ifindex[2], ifindex[3]]),
            next_hop_mac: [mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]],
        })
    }

    fn reserve_conntrack(&self, record: ConntrackRecord) -> ConntrackReservation {
        match insert_record(record, BPF_NOEXIST) {
            Ok(()) => ConntrackReservation::Reserved,
            Err(EEXIST) => ConntrackReservation::Occupied,
            Err(_) => ConntrackReservation::Failed,
        }
    }

    fn insert_conntrack(&self, record: ConntrackRecord) -> Result<(), ()> {
        insert_record(record, BPF_NOEXIST).map_err(|_| ())
    }

    fn remove_conntrack(&self, key: FlowKey) {
        let _ = FERRO_CONNTRACK.remove(key.encode());
    }
}

pub fn insert_reverse_conntrack(record: ConntrackRecord) -> Result<(), i32> {
    insert_record(record, BPF_ANY)
}

pub fn rollback_pair(pair: ConntrackPair) {
    let _ = FERRO_CONNTRACK.remove(pair.forward.key.encode());
    let _ = FERRO_CONNTRACK.remove(pair.reverse.key.encode());
}

pub fn increment(counter: Counter) {
    let index = counter.index();
    if index >= COUNTER_MAX_ENTRIES {
        return;
    }
    if let Some(pointer) = FERRO_COUNTERS.get_ptr_mut(index) {
        // SAFETY: index is bounded by the PerCpuArray maximum and Aya returned
        // the current CPU's aligned u64 slot. Wrapping keeps behavior uniform.
        unsafe {
            pointer.write(pointer.read().wrapping_add(1));
        }
    }
}
