#![cfg(target_os = "linux")]

#[path = "../../ferro-net-ebpf/src/datapath.rs"]
mod datapath;

use std::{cell::RefCell, fs};

use datapath::{
    action_for_parse_failure, decide_egress, decide_ingress, Action, ConntrackRecord, Counter,
    DatapathState, DecisionError, Direction, Endpoint, FlowKey, NatTarget, Packet, ParseFailure,
    PolicyAction, PolicyKey, PortTarget, Translation, CONNTRACK_MAX_ENTRIES,
    COUNTER_MAX_ENTRIES, ENDPOINT_MAX_ENTRIES, META_MAX_ENTRIES, POLICY_MAX_ENTRIES,
    PORT_MAX_ENTRIES,
};
use ferro_net::ebpf::{build_bpftool_load_cmd, EbpfProgram};

#[derive(Default)]
struct FixtureState {
    policies: Vec<(PolicyKey, PolicyAction)>,
    conntrack: Vec<(FlowKey, NatTarget)>,
    ports: Vec<((u8, u16), PortTarget)>,
    endpoints: Vec<([u8; 4], Endpoint)>,
    calls: RefCell<Vec<&'static str>>,
}

impl DatapathState for FixtureState {
    fn policy(&self, key: PolicyKey) -> Option<PolicyAction> {
        self.calls.borrow_mut().push("policy");
        self.policies
            .iter()
            .find(|(candidate, _)| *candidate == key)
            .map(|(_, action)| *action)
    }

    fn conntrack(&self, key: FlowKey) -> Option<NatTarget> {
        self.calls.borrow_mut().push("conntrack");
        self.conntrack
            .iter()
            .find(|(candidate, _)| *candidate == key)
            .map(|(_, target)| *target)
    }

    fn published_port(&self, protocol: u8, host_port: u16) -> Option<PortTarget> {
        self.calls.borrow_mut().push("port");
        self.ports
            .iter()
            .find(|((candidate_protocol, candidate_port), _)| {
                *candidate_protocol == protocol && *candidate_port == host_port
            })
            .map(|(_, target)| *target)
    }

    fn endpoint(&self, address: [u8; 4]) -> Option<Endpoint> {
        self.calls.borrow_mut().push("endpoint");
        self.endpoints
            .iter()
            .find(|(candidate, _)| *candidate == address)
            .map(|(_, endpoint)| *endpoint)
    }
}

fn tcp_packet(
    source: [u8; 4],
    source_port: u16,
    destination: [u8; 4],
    destination_port: u16,
) -> Packet {
    Packet::tcp(source, source_port, destination, destination_port)
}

#[test]
fn ebpf_program_builder_is_deterministic() {
    let prog = EbpfProgram {
        name: "xdp_prog".to_string(),
        object_path: "/opt/ferro/xdp.o".to_string(),
        section: "xdp".to_string(),
    };
    let cmd = build_bpftool_load_cmd(&prog, "/sys/fs/bpf/ferro/xdp");
    assert_eq!(
        cmd,
        vec![
            "bpftool",
            "prog",
            "load",
            "/opt/ferro/xdp.o",
            "/sys/fs/bpf/ferro/xdp",
            "type",
            "xdp"
        ]
    );
}

#[test]
fn maps_are_bounded_and_use_the_required_kernel_types() {
    assert_eq!(CONNTRACK_MAX_ENTRIES, 65_536);
    assert_eq!(ENDPOINT_MAX_ENTRIES, 16_384);
    assert_eq!(PORT_MAX_ENTRIES, 16_384);
    assert_eq!(POLICY_MAX_ENTRIES, 32_768);
    assert_eq!(META_MAX_ENTRIES, 1);
    assert_eq!(COUNTER_MAX_ENTRIES, 8);

    let source = fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../ferro-net-ebpf/src/maps.rs"
    ))
    .expect("Task 4 must define the kernel maps module");
    assert!(source.contains("FERRO_CONNTRACK: LruHashMap"));
    assert!(source.contains("FERRO_ENDPOINTS: HashMap"));
    assert!(source.contains("FERRO_PORTS: HashMap"));
    assert!(source.contains("FERRO_POLICY: HashMap"));
    assert!(source.contains("FERRO_COUNTERS: PerCpuArray"));
    assert!(source.contains("FERRO_META: Array"));
}

#[test]
fn ingress_decision_dnat_precedes_endpoint_lookup() {
    let remote = [192, 0, 2, 10];
    let host = [203, 0, 113, 8];
    let endpoint_address = [10, 44, 1, 2];
    let packet = tcp_packet(remote, 51_000, host, 8080);
    let mut state = FixtureState::default();
    state.ports.push((
        (packet.protocol, 8080),
        PortTarget {
            address: endpoint_address,
            port: 80,
        },
    ));
    state.endpoints.push((
        endpoint_address,
        Endpoint {
            ifindex: 17,
            mac: [2, 0, 0, 0, 0, 17],
            flags: 0,
        },
    ));

    let decision = decide_ingress(&packet, &state).unwrap();

    assert_eq!(decision.destination.address, endpoint_address);
    assert_eq!(decision.destination.port, 80);
    assert_eq!(decision.action, Action::Redirect);
    assert_eq!(decision.ifindex, Some(17));
    assert_eq!(decision.translation, Translation::Destination);
    assert_eq!(
        state.calls.into_inner(),
        vec!["policy", "conntrack", "port", "endpoint"]
    );
}

#[test]
fn ingress_policy_denial_short_circuits_all_translation_lookups() {
    let packet = tcp_packet([192, 0, 2, 10], 51_000, [203, 0, 113, 8], 8080);
    let mut state = FixtureState::default();
    state.policies.push((
        PolicyKey::for_packet(&packet, Direction::Ingress),
        PolicyAction::Deny,
    ));

    assert_eq!(
        decide_ingress(&packet, &state),
        Err(DecisionError::PolicyDenied)
    );
    assert_eq!(state.calls.into_inner(), vec!["policy"]);
}

#[test]
fn ingress_conntrack_precedes_published_port_lookup() {
    let packet = tcp_packet([192, 0, 2, 10], 51_000, [203, 0, 113, 8], 8080);
    let endpoint_address = [10, 44, 1, 9];
    let mut state = FixtureState::default();
    state.conntrack.push((
        FlowKey::from_packet(&packet),
        NatTarget {
            address: endpoint_address,
            port: 8081,
        },
    ));
    state.endpoints.push((
        endpoint_address,
        Endpoint {
            ifindex: 23,
            mac: [2, 0, 0, 0, 0, 23],
            flags: 0,
        },
    ));

    let decision = decide_ingress(&packet, &state).unwrap();

    assert_eq!(decision.destination.address, endpoint_address);
    assert_eq!(decision.destination.port, 8081);
    assert_eq!(
        state.calls.into_inner(),
        vec!["policy", "conntrack", "endpoint"]
    );
}

#[test]
fn port_dnat_records_an_exact_reverse_flow_for_egress_snat() {
    let remote = [192, 0, 2, 10];
    let host = [203, 0, 113, 8];
    let endpoint_address = [10, 44, 1, 2];
    let ingress_packet = tcp_packet(remote, 51_000, host, 8080);
    let mut ingress_state = FixtureState::default();
    ingress_state.ports.push((
        (ingress_packet.protocol, 8080),
        PortTarget {
            address: endpoint_address,
            port: 80,
        },
    ));
    ingress_state.endpoints.push((
        endpoint_address,
        Endpoint {
            ifindex: 17,
            mac: [2, 0, 0, 0, 0, 17],
            flags: 0,
        },
    ));
    let ingress = decide_ingress(&ingress_packet, &ingress_state).unwrap();
    let reverse = ingress
        .reverse_conntrack
        .expect("published-port DNAT must record reverse conntrack");

    assert_eq!(
        reverse,
        ConntrackRecord {
            key: FlowKey {
                protocol: ingress_packet.protocol,
                source: endpoint_address,
                destination: remote,
                source_port: 80,
                destination_port: 51_000,
            },
            target: NatTarget {
                address: host,
                port: 8080,
            },
        }
    );

    let reply = tcp_packet(endpoint_address, 80, remote, 51_000);
    let mut egress_state = FixtureState::default();
    egress_state.conntrack.push((reverse.key, reverse.target));
    let egress = decide_egress(&reply, &egress_state).unwrap();

    assert_eq!(egress.source.address, host);
    assert_eq!(egress.source.port, 8080);
    assert_eq!(egress.destination.address, remote);
    assert_eq!(egress.destination.port, 51_000);
    assert_eq!(egress.translation, Translation::Source);
    assert_eq!(egress.action, Action::Pass);
}

#[test]
fn egress_reverse_translation_still_redirects_an_internal_destination() {
    let packet = tcp_packet([10, 44, 1, 2], 80, [10, 44, 1, 3], 30_000);
    let mut state = FixtureState::default();
    state.conntrack.push((
        FlowKey::from_packet(&packet),
        NatTarget {
            address: [203, 0, 113, 8],
            port: 8080,
        },
    ));
    state.endpoints.push((
        packet.destination.address,
        Endpoint {
            ifindex: 19,
            mac: [2, 0, 0, 0, 0, 19],
            flags: 0,
        },
    ));

    let decision = decide_egress(&packet, &state).unwrap();

    assert_eq!(decision.action, Action::Redirect);
    assert_eq!(decision.ifindex, Some(19));
    assert_eq!(
        state.calls.into_inner(),
        vec!["policy", "conntrack", "endpoint"]
    );
}

#[test]
fn non_ferro_traffic_passes_without_translation() {
    let ingress_packet = tcp_packet([192, 0, 2, 10], 51_000, [198, 51, 100, 20], 443);
    let ingress_state = FixtureState::default();
    let ingress = decide_ingress(&ingress_packet, &ingress_state).unwrap();
    assert_eq!(ingress.action, Action::Pass);
    assert_eq!(ingress.translation, Translation::None);

    let egress_packet = tcp_packet([198, 51, 100, 20], 443, [192, 0, 2, 10], 51_000);
    let egress_state = FixtureState::default();
    let egress = decide_egress(&egress_packet, &egress_state).unwrap();
    assert_eq!(egress.action, Action::Pass);
    assert_eq!(egress.translation, Translation::None);
}

#[test]
fn owned_port_with_no_endpoint_fails_closed() {
    let packet = tcp_packet([192, 0, 2, 10], 51_000, [203, 0, 113, 8], 8080);
    let mut state = FixtureState::default();
    state.ports.push((
        (packet.protocol, 8080),
        PortTarget {
            address: [10, 44, 1, 2],
            port: 80,
        },
    ));

    assert_eq!(
        decide_ingress(&packet, &state),
        Err(DecisionError::EndpointMissing)
    );
    assert_eq!(Action::Drop.counter(), Counter::Drops);
}

#[test]
fn unsupported_packets_pass_but_invalid_owned_packets_drop() {
    assert_eq!(
        action_for_parse_failure(ParseFailure::Unsupported, true),
        Action::Pass
    );
    assert_eq!(
        action_for_parse_failure(ParseFailure::Invalid, false),
        Action::Pass
    );
    assert_eq!(
        action_for_parse_failure(ParseFailure::Invalid, true),
        Action::Drop
    );
}

#[test]
fn decisions_expose_the_same_counter_semantics_used_by_classifiers() {
    let packet = tcp_packet([192, 0, 2, 10], 51_000, [198, 51, 100, 20], 443);
    let decision = decide_ingress(&packet, &FixtureState::default()).unwrap();
    let metrics = decision.metrics(Direction::Ingress);

    assert_eq!(metrics.packet, Counter::IngressPackets);
    assert_eq!(metrics.outcome, Counter::Passes);
    assert!(!metrics.translated);
    assert_eq!(Action::Redirect.counter(), Counter::Redirects);
    assert_eq!(Action::Drop.counter(), Counter::Drops);
}
