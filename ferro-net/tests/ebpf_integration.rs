#![cfg(target_os = "linux")]

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::{env, net::Ipv4Addr};

use ferro_net::ebpf::{
    embedded_object_abi, embedded_object_sha256, EbpfError, EbpfMetrics, EbpfNetwork,
    EbpfNetworkConfig,
};
use ferro_net::ebpf_abi::{
    EndpointKey, EndpointValue, MetaConfig, PolicyKey, PolicyValue, PortKey, PortValue,
    CONNTRACK_KEY_LEN, CONNTRACK_MAP_NAME, CONNTRACK_MAX_ENTRIES, CONNTRACK_VALUE_LEN,
    COUNTERS_MAP_NAME, COUNTER_MAX_ENTRIES, ENDPOINTS_MAP_NAME, ENDPOINT_KEY_LEN,
    ENDPOINT_MAX_ENTRIES, ENDPOINT_VALUE_LEN, META_FLAG_SNAT_RANGE_RESERVED, META_MAP_NAME,
    META_MAX_ENTRIES, META_VALUE_LEN, POLICY_KEY_LEN, POLICY_MAP_NAME, POLICY_MAX_ENTRIES,
    POLICY_VALUE_LEN, PORTS_MAP_NAME, PORT_KEY_LEN, PORT_MAX_ENTRIES, PORT_VALUE_LEN,
    PROGRAM_ABI_VERSION,
};
use ferro_net::ebpf_loader::{
    KernelAdapter, KernelLoadPlan, KernelPreflight, MapKind, MapMetadata, ObjectMetadata,
};

const INGRESS: &str = "ferro_ingress";
const EGRESS: &str = "ferro_egress";

#[derive(Debug, Default)]
struct FakeState {
    events: Vec<String>,
    metadata: Option<[u8; META_VALUE_LEN]>,
    inserts: Vec<(String, Vec<u8>, Vec<u8>)>,
    removals: Vec<(String, Vec<u8>)>,
    attached: Vec<String>,
    rollback_count: usize,
    detach_count: usize,
}

struct FakeKernel {
    state: Arc<Mutex<FakeState>>,
    reserved_ports: String,
    metadata: ObjectMetadata,
    fail_egress_attach: bool,
    capacity_map: Option<&'static str>,
}

impl FakeKernel {
    fn valid() -> (Self, Arc<Mutex<FakeState>>) {
        let state = Arc::new(Mutex::new(FakeState::default()));
        (
            Self {
                state: Arc::clone(&state),
                reserved_ports: "1-1024,40000,50000-50031,61000-62000\n".to_string(),
                metadata: valid_object_metadata(),
                fail_egress_attach: false,
                capacity_map: None,
            },
            state,
        )
    }

    fn with_program_abi(version: u32) -> (Self, Arc<Mutex<FakeState>>) {
        let (mut kernel, state) = Self::valid();
        kernel.metadata.program_abi = version;
        (kernel, state)
    }
}

impl KernelAdapter for FakeKernel {
    fn reserved_ports(&mut self) -> Result<String, EbpfError> {
        self.state
            .lock()
            .unwrap()
            .events
            .push("read-reserved-ports".to_string());
        Ok(self.reserved_ports.clone())
    }

    fn preflight(
        &mut self,
        request: &KernelPreflight<'_>,
    ) -> Result<ObjectMetadata, EbpfError> {
        assert!(!request.object.is_empty());
        assert_eq!(request.interface, "eth-test0");
        assert_eq!(request.external_ifindex, 17);
        assert_eq!(
            request.pin_path,
            Path::new("/sys/fs/bpf/ferro/networks/test-network")
        );
        self.state
            .lock()
            .unwrap()
            .events
            .push("preflight".to_string());
        Ok(self.metadata.clone())
    }

    fn commit(&mut self, plan: &KernelLoadPlan<'_>) -> Result<(), EbpfError> {
        let mut state = self.state.lock().unwrap();
        state.events.push(format!("create:{}", plan.pin_path.display()));
        state.metadata = Some(plan.metadata);
        state.events.push(format!("attach:{INGRESS}:ingress"));
        state.attached.push(INGRESS.to_string());
        if self.fail_egress_attach {
            return Err(EbpfError::Attach {
                classifier: EGRESS.to_string(),
                reason: "injected egress failure".to_string(),
            });
        }
        state.events.push(format!("attach:{EGRESS}:egress"));
        state.attached.push(EGRESS.to_string());
        Ok(())
    }

    fn map_insert(
        &mut self,
        map: &'static str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), EbpfError> {
        if self.capacity_map == Some(map) {
            return Err(EbpfError::MapCapacity { map });
        }
        self.state.lock().unwrap().inserts.push((
            map.to_string(),
            key.to_vec(),
            value.to_vec(),
        ));
        Ok(())
    }

    fn map_remove(&mut self, map: &'static str, key: &[u8]) -> Result<(), EbpfError> {
        self.state
            .lock()
            .unwrap()
            .removals
            .push((map.to_string(), key.to_vec()));
        Ok(())
    }

    fn counters(&mut self) -> Result<[u64; COUNTER_MAX_ENTRIES as usize], EbpfError> {
        Ok([11, 12, 3, 4, 5, 6, 7, 8, 9, 10])
    }

    fn rollback(&mut self) -> Result<(), EbpfError> {
        let mut state = self.state.lock().unwrap();
        state.events.push("rollback".to_string());
        state.attached.clear();
        state.rollback_count += 1;
        Ok(())
    }

    fn detach(&mut self) -> Result<(), EbpfError> {
        let mut state = self.state.lock().unwrap();
        state.events.push("detach".to_string());
        state.attached.clear();
        state.detach_count += 1;
        Ok(())
    }
}

fn config() -> EbpfNetworkConfig {
    EbpfNetworkConfig {
        network_id: "test-network".to_string(),
        interface: "eth-test0".to_string(),
        external_ipv4: [203, 0, 113, 8],
        external_ifindex: 17,
        next_hop_mac: [2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        snat_port_start: 50_000,
        snat_port_end: 50_031,
        expected_object_sha256: embedded_object_sha256(),
    }
}

fn valid_object_metadata() -> ObjectMetadata {
    ObjectMetadata {
        program_abi: PROGRAM_ABI_VERSION,
        maps: vec![
            map(
                ENDPOINTS_MAP_NAME,
                MapKind::Hash,
                ENDPOINT_KEY_LEN,
                ENDPOINT_VALUE_LEN,
                ENDPOINT_MAX_ENTRIES,
            ),
            map(
                PORTS_MAP_NAME,
                MapKind::Hash,
                PORT_KEY_LEN,
                PORT_VALUE_LEN,
                PORT_MAX_ENTRIES,
            ),
            map(
                CONNTRACK_MAP_NAME,
                MapKind::LruHash,
                CONNTRACK_KEY_LEN,
                CONNTRACK_VALUE_LEN,
                CONNTRACK_MAX_ENTRIES,
            ),
            map(
                POLICY_MAP_NAME,
                MapKind::Hash,
                POLICY_KEY_LEN,
                POLICY_VALUE_LEN,
                POLICY_MAX_ENTRIES,
            ),
            map(
                COUNTERS_MAP_NAME,
                MapKind::PerCpuArray,
                4,
                8,
                COUNTER_MAX_ENTRIES,
            ),
            map(
                META_MAP_NAME,
                MapKind::Array,
                4,
                META_VALUE_LEN,
                META_MAX_ENTRIES,
            ),
        ],
        classifiers: vec![INGRESS.to_string(), EGRESS.to_string()],
    }
}

fn map(name: &str, kind: MapKind, key: usize, value: usize, max_entries: u32) -> MapMetadata {
    MapMetadata {
        name: name.to_string(),
        kind,
        key_size: key as u32,
        value_size: value as u32,
        max_entries,
    }
}

#[test]
fn successful_load_commits_coherent_metadata_and_typed_map_updates() {
    let (kernel, state) = FakeKernel::valid();
    let mut network = EbpfNetwork::load_with(kernel, config()).unwrap();

    let metadata = MetaConfig::decode(state.lock().unwrap().metadata.unwrap());
    assert_eq!(metadata.abi_version, PROGRAM_ABI_VERSION);
    assert_eq!(metadata.external_ipv4, [203, 0, 113, 8]);
    assert_eq!(metadata.external_ifindex, 17);
    assert_eq!(metadata.next_hop_mac, [2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    assert_eq!((metadata.snat_port_start, metadata.snat_port_end), (50_000, 50_031));
    assert_eq!(metadata.flags, META_FLAG_SNAT_RANGE_RESERVED);

    let endpoint_key = EndpointKey {
        address: [10, 44, 1, 2],
    };
    let endpoint_value = EndpointValue {
        ifindex: 23,
        mac: [2, 0, 0, 0, 0, 23],
        flags: 1,
    };
    network
        .install_endpoint(endpoint_key, endpoint_value)
        .unwrap();

    let port_key = PortKey {
        protocol: 6,
        host_port: 8080,
    };
    let port_value = PortValue {
        endpoint_address: [10, 44, 1, 2],
        endpoint_port: 80,
    };
    network.install_port(port_key, port_value).unwrap();

    let policy_key = PolicyKey {
        endpoint_address: [10, 44, 1, 2],
        protocol: 6,
        direction: 1,
        port: 443,
    };
    let policy_value = PolicyValue {
        action: 1,
        log: true,
    };
    network.set_policy(policy_key, policy_value).unwrap();
    network.remove_endpoint(endpoint_key).unwrap();
    network.remove_port(port_key).unwrap();

    let locked = state.lock().unwrap();
    assert_eq!(
        locked.inserts,
        vec![
            (
                ENDPOINTS_MAP_NAME.to_string(),
                endpoint_key.encode().to_vec(),
                endpoint_value.encode().to_vec(),
            ),
            (
                PORTS_MAP_NAME.to_string(),
                port_key.encode().to_vec(),
                port_value.encode().to_vec(),
            ),
            (
                POLICY_MAP_NAME.to_string(),
                policy_key.encode().to_vec(),
                policy_value.encode().to_vec(),
            ),
        ]
    );
    assert_eq!(
        locked.removals,
        vec![
            (ENDPOINTS_MAP_NAME.to_string(), endpoint_key.encode().to_vec()),
            (PORTS_MAP_NAME.to_string(), port_key.encode().to_vec()),
        ]
    );
}

#[test]
fn abi_mismatch_rolls_back_without_attach() {
    let (kernel, state) = FakeKernel::with_program_abi(PROGRAM_ABI_VERSION + 1);

    let err = EbpfNetwork::load_with(kernel, config()).unwrap_err();

    assert!(matches!(
        err,
        EbpfError::AbiMismatch {
            expected: PROGRAM_ABI_VERSION,
            actual
        } if actual == PROGRAM_ABI_VERSION + 1
    ));
    let locked = state.lock().unwrap();
    assert_eq!(locked.rollback_count, 1);
    assert!(!locked.events.iter().any(|event| event.starts_with("attach:")));
}

#[test]
fn missing_map_rolls_back_before_attach() {
    let (mut kernel, state) = FakeKernel::valid();
    kernel
        .metadata
        .maps
        .retain(|metadata| metadata.name != POLICY_MAP_NAME);

    let err = EbpfNetwork::load_with(kernel, config()).unwrap_err();

    assert!(matches!(err, EbpfError::MissingMap { map: POLICY_MAP_NAME }));
    let locked = state.lock().unwrap();
    assert_eq!(locked.rollback_count, 1);
    assert!(!locked.events.iter().any(|event| event.starts_with("attach:")));
}

#[test]
fn wrong_map_schema_and_unexpected_classifier_fail_closed() {
    let (mut wrong_map, map_state) = FakeKernel::valid();
    wrong_map.metadata.maps[0].value_size += 1;
    let map_error = EbpfNetwork::load_with(wrong_map, config()).unwrap_err();
    assert!(matches!(map_error, EbpfError::MapSchemaMismatch { .. }));
    assert_eq!(map_state.lock().unwrap().rollback_count, 1);

    let (mut wrong_program, program_state) = FakeKernel::valid();
    wrong_program.metadata.classifiers.push("foreign_classifier".to_string());
    let program_error = EbpfNetwork::load_with(wrong_program, config()).unwrap_err();
    assert!(matches!(
        program_error,
        EbpfError::UnexpectedClassifier { ref classifier }
            if classifier == "foreign_classifier"
    ));
    assert_eq!(program_state.lock().unwrap().rollback_count, 1);
}

#[test]
fn incomplete_reserved_range_fails_before_kernel_preflight_or_network_mutation() {
    for reserved in ["", "50000-50015", "50000-50015,50017-50031", "not-a-port"] {
        let (mut kernel, state) = FakeKernel::valid();
        kernel.reserved_ports = reserved.to_string();

        let error = EbpfNetwork::load_with(kernel, config()).unwrap_err();

        assert!(matches!(
            error,
            EbpfError::SnatRangeNotReserved { .. } | EbpfError::ReservedPortsInvalid { .. }
        ));
        let locked = state.lock().unwrap();
        assert!(!locked.events.iter().any(|event| event == "preflight"));
        assert!(!locked.events.iter().any(|event| event.starts_with("create:")));
        assert_eq!(locked.rollback_count, 0);
    }
}

#[test]
fn adjacent_reserved_intervals_prove_the_complete_inclusive_range() {
    let (mut kernel, state) = FakeKernel::valid();
    kernel.reserved_ports = "49999-50007,50008-50020,50021-50031".to_string();

    let mut network = EbpfNetwork::load_with(kernel, config()).unwrap();

    assert!(state.lock().unwrap().metadata.is_some());
    network.detach().unwrap();
}

#[test]
fn object_hash_and_network_path_are_validated_before_kernel_preflight() {
    let (kernel, state) = FakeKernel::valid();
    let mut wrong_hash = config();
    wrong_hash.expected_object_sha256[0] ^= 0xff;
    let hash_error = EbpfNetwork::load_with(kernel, wrong_hash).unwrap_err();
    assert!(matches!(hash_error, EbpfError::ObjectHashMismatch { .. }));
    assert!(!state.lock().unwrap().events.iter().any(|event| event == "preflight"));

    let (kernel, state) = FakeKernel::valid();
    let mut traversal = config();
    traversal.network_id = "../other-network".to_string();
    let path_error = EbpfNetwork::load_with(kernel, traversal).unwrap_err();
    assert!(matches!(path_error, EbpfError::InvalidNetworkId { .. }));
    assert!(state.lock().unwrap().events.is_empty());
}

#[test]
fn failed_second_attach_rolls_back_first_attach_and_created_paths() {
    let (mut kernel, state) = FakeKernel::valid();
    kernel.fail_egress_attach = true;

    let error = EbpfNetwork::load_with(kernel, config()).unwrap_err();

    assert!(matches!(
        error,
        EbpfError::Attach { ref classifier, .. } if classifier == EGRESS
    ));
    let locked = state.lock().unwrap();
    assert_eq!(locked.rollback_count, 1);
    assert!(locked.attached.is_empty());
    assert!(locked.events.iter().any(|event| event == "rollback"));
}

#[test]
fn detach_is_idempotent() {
    let (kernel, state) = FakeKernel::valid();
    let mut network = EbpfNetwork::load_with(kernel, config()).unwrap();

    network.detach().unwrap();
    network.detach().unwrap();

    assert_eq!(state.lock().unwrap().detach_count, 1);
}

#[test]
fn map_capacity_errors_are_operation_specific() {
    let (mut kernel, _state) = FakeKernel::valid();
    kernel.capacity_map = Some(ENDPOINTS_MAP_NAME);
    let mut network = EbpfNetwork::load_with(kernel, config()).unwrap();

    let error = network
        .install_endpoint(
            EndpointKey { address: [10, 44, 1, 2] },
            EndpointValue {
                ifindex: 23,
                mac: [2, 0, 0, 0, 0, 23],
                flags: 0,
            },
        )
        .unwrap_err();

    assert!(matches!(
        error,
        EbpfError::MapCapacity {
            map: ENDPOINTS_MAP_NAME
        }
    ));
}

#[test]
fn metrics_are_named_and_aggregated_by_the_loader() {
    let (kernel, _state) = FakeKernel::valid();
    let mut network = EbpfNetwork::load_with(kernel, config()).unwrap();

    assert_eq!(
        network.metrics().unwrap(),
        EbpfMetrics {
            ingress_packets: 11,
            egress_packets: 12,
            redirects: 3,
            passes: 4,
            drops: 5,
            nat_translations: 6,
            policy_denials: 7,
            map_errors: 8,
            snat_exhaustions: 9,
            snat_config_errors: 10,
        }
    );
}

#[test]
fn embedded_elf_exposes_the_actual_program_abi() {
    assert_eq!(embedded_object_abi().unwrap(), PROGRAM_ABI_VERSION);
}

#[test]
#[ignore = "requires root, BPF/NET_ADMIN capabilities, bpffs, tc, and a reserved SNAT range"]
fn aya_loader_verifies_and_rolls_back_the_real_object() {
    let interface = env::var("FERRO_EBPF_TEST_INTERFACE").expect("test interface");
    let external_ifindex = env::var("FERRO_EBPF_TEST_IFINDEX")
        .expect("test ifindex")
        .parse()
        .expect("numeric test ifindex");
    let external_ipv4 = env::var("FERRO_EBPF_TEST_EXTERNAL_IPV4")
        .expect("test external IPv4")
        .parse::<Ipv4Addr>()
        .expect("valid test external IPv4")
        .octets();
    let next_hop_mac = parse_mac(
        &env::var("FERRO_EBPF_TEST_NEXT_HOP_MAC").expect("test next-hop MAC"),
    );
    let snat_port_start = env::var("FERRO_EBPF_TEST_SNAT_START")
        .expect("test SNAT start")
        .parse()
        .expect("numeric test SNAT start");
    let snat_port_end = env::var("FERRO_EBPF_TEST_SNAT_END")
        .expect("test SNAT end")
        .parse()
        .expect("numeric test SNAT end");
    let mut network = EbpfNetwork::load(EbpfNetworkConfig {
        network_id: format!("loader-smoke-{}", std::process::id()),
        interface,
        external_ipv4,
        external_ifindex,
        next_hop_mac,
        snat_port_start,
        snat_port_end,
        expected_object_sha256: embedded_object_sha256(),
    })
    .expect("real Aya loader path");

    network.detach().expect("transactional real detach");
    network.detach().expect("idempotent real detach");
}

fn parse_mac(value: &str) -> [u8; 6] {
    let bytes = value
        .split(':')
        .map(|byte| u8::from_str_radix(byte, 16).expect("hex MAC byte"))
        .collect::<Vec<_>>();
    bytes.try_into().expect("six-byte MAC")
}
