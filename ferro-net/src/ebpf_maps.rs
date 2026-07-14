use crate::ebpf_abi::{
    CONNTRACK_KEY_LEN, CONNTRACK_MAP_NAME, CONNTRACK_MAX_ENTRIES, CONNTRACK_VALUE_LEN,
    COUNTERS_MAP_NAME, COUNTER_MAX_ENTRIES, ENDPOINTS_MAP_NAME, ENDPOINT_KEY_LEN,
    ENDPOINT_MAX_ENTRIES, ENDPOINT_VALUE_LEN, META_MAP_NAME, META_MAX_ENTRIES, META_VALUE_LEN,
    POLICY_KEY_LEN, POLICY_MAP_NAME, POLICY_MAX_ENTRIES, POLICY_VALUE_LEN, PORTS_MAP_NAME,
    PORT_KEY_LEN, PORT_MAX_ENTRIES, PORT_VALUE_LEN,
};
use crate::ebpf_loader::{MapKind, MapMetadata};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfMap {
    pub name: String,
    pub map_type: String,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

pub fn build_bpftool_map_create_cmd(map: &EbpfMap, pin_path: &str) -> Vec<String> {
    vec![
        "bpftool".into(),
        "map".into(),
        "create".into(),
        pin_path.into(),
        "type".into(),
        map.map_type.clone(),
        "key".into(),
        map.key_size.to_string(),
        "value".into(),
        map.value_size.to_string(),
        "entries".into(),
        map.max_entries.to_string(),
        "name".into(),
        map.name.clone(),
    ]
}

pub fn build_bpftool_map_pin_cmd(map_id: u32, pin_path: &str) -> Vec<String> {
    vec![
        "bpftool".into(),
        "map".into(),
        "pin".into(),
        "id".into(),
        map_id.to_string(),
        pin_path.into(),
    ]
}

pub(crate) fn expected_map_metadata() -> Vec<MapMetadata> {
    vec![
        metadata(
            ENDPOINTS_MAP_NAME,
            MapKind::Hash,
            ENDPOINT_KEY_LEN,
            ENDPOINT_VALUE_LEN,
            ENDPOINT_MAX_ENTRIES,
        ),
        metadata(
            PORTS_MAP_NAME,
            MapKind::Hash,
            PORT_KEY_LEN,
            PORT_VALUE_LEN,
            PORT_MAX_ENTRIES,
        ),
        metadata(
            CONNTRACK_MAP_NAME,
            MapKind::LruHash,
            CONNTRACK_KEY_LEN,
            CONNTRACK_VALUE_LEN,
            CONNTRACK_MAX_ENTRIES,
        ),
        metadata(
            POLICY_MAP_NAME,
            MapKind::Hash,
            POLICY_KEY_LEN,
            POLICY_VALUE_LEN,
            POLICY_MAX_ENTRIES,
        ),
        metadata(
            COUNTERS_MAP_NAME,
            MapKind::PerCpuArray,
            size_of::<u32>(),
            size_of::<u64>(),
            COUNTER_MAX_ENTRIES,
        ),
        metadata(
            META_MAP_NAME,
            MapKind::Array,
            size_of::<u32>(),
            META_VALUE_LEN,
            META_MAX_ENTRIES,
        ),
    ]
}

fn metadata(
    name: &str,
    kind: MapKind,
    key_size: usize,
    value_size: usize,
    max_entries: u32,
) -> MapMetadata {
    MapMetadata {
        name: name.to_string(),
        kind,
        key_size: key_size as u32,
        value_size: value_size as u32,
        max_entries,
        map_flags: 0,
        pinning: 0,
        map_id: 0,
    }
}
