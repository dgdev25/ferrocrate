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

#[cfg(test)]
mod tests {
    use super::{EbpfMap, build_bpftool_map_create_cmd, build_bpftool_map_pin_cmd};

    #[test]
    fn builds_map_commands() {
        let map = EbpfMap {
            name: "conntrack".to_string(),
            map_type: "hash".to_string(),
            key_size: 16,
            value_size: 8,
            max_entries: 1024,
        };

        assert_eq!(
            build_bpftool_map_create_cmd(&map, "/sys/fs/bpf/ferro/conntrack"),
            vec![
                "bpftool", "map", "create", "/sys/fs/bpf/ferro/conntrack", "type", "hash",
                "key", "16", "value", "8", "entries", "1024", "name", "conntrack"
            ]
        );

        assert_eq!(
            build_bpftool_map_pin_cmd(42, "/sys/fs/bpf/ferro/conntrack"),
            vec!["bpftool", "map", "pin", "id", "42", "/sys/fs/bpf/ferro/conntrack"]
        );
    }
}
