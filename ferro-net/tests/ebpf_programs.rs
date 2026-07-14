#![cfg(target_os = "linux")]

#[path = "../../ferro-net-ebpf/src/abi.rs"]
#[allow(dead_code)]
mod abi;
#[path = "../../ferro-net-ebpf/src/packet.rs"]
mod packet;
#[path = "../../ferro-net-ebpf/src/datapath.rs"]
mod datapath;
#[path = "../src/ebpf_abi.rs"]
mod host_abi;

use std::{
    cell::{Cell, RefCell},
    vec::Vec,
};

use datapath::{
    action_for_parse_failure, actual_disposition, apply_decision, decide_egress, decide_ingress,
    snat_candidate, Action, ConntrackPair, ConntrackRecord, ConntrackReservation, Counter,
    DatapathState, DecisionError, Direction, Endpoint, ExternalNetwork, FlowKey, NatTarget,
    Packet, ParseFailure, PolicyAction, PolicyKey, PortTarget, Socket, Translation,
    IP_PROTOCOL_TCP, IP_PROTOCOL_UDP, SNAT_PROBE_LIMIT,
};
use ferro_net::ebpf::{build_bpftool_load_cmd, EbpfProgram};

#[derive(Default)]
struct FixtureState {
    policies: Vec<(PolicyKey, PolicyAction)>,
    conntrack: RefCell<Vec<(FlowKey, NatTarget)>>,
    ports: Vec<((u8, u16), PortTarget)>,
    endpoints: Vec<([u8; 4], Endpoint)>,
    external: Option<ExternalNetwork>,
    reserve_attempts: RefCell<Vec<FlowKey>>,
    fail_forward_insert: Cell<bool>,
}

impl FixtureState {
    fn with_external_endpoint(internal: [u8; 4]) -> Self {
        Self {
            endpoints: vec![(
                internal,
                Endpoint {
                    ifindex: 17,
                    mac: [2, 0, 0, 0, 0, 17],
                    flags: 0,
                },
            )],
            external: Some(ExternalNetwork {
                address: [203, 0, 113, 8],
                ifindex: 9,
                next_hop_mac: [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
            }),
            ..Self::default()
        }
    }

    fn insert_existing(&self, key: FlowKey, target: NatTarget) {
        self.conntrack.borrow_mut().push((key, target));
    }

    fn contains_record(&self, record: ConntrackRecord) -> bool {
        self.conntrack
            .borrow()
            .iter()
            .any(|entry| *entry == (record.key, record.target))
    }
}

impl DatapathState for FixtureState {
    fn policy(&self, key: PolicyKey) -> Option<PolicyAction> {
        self.policies
            .iter()
            .find(|(candidate, _)| *candidate == key)
            .map(|(_, action)| *action)
    }

    fn conntrack(&self, key: FlowKey) -> Option<NatTarget> {
        self.conntrack
            .borrow()
            .iter()
            .find(|(candidate, _)| *candidate == key)
            .map(|(_, target)| *target)
    }

    fn published_port(&self, protocol: u8, host_port: u16) -> Option<PortTarget> {
        self.ports
            .iter()
            .find(|((candidate_protocol, candidate_port), _)| {
                *candidate_protocol == protocol && *candidate_port == host_port
            })
            .map(|(_, target)| *target)
    }

    fn endpoint(&self, address: [u8; 4]) -> Option<Endpoint> {
        self.endpoints
            .iter()
            .find(|(candidate, _)| *candidate == address)
            .map(|(_, endpoint)| *endpoint)
    }

    fn external_network(&self) -> Option<ExternalNetwork> {
        self.external
    }

    fn reserve_conntrack(&self, record: ConntrackRecord) -> ConntrackReservation {
        self.reserve_attempts.borrow_mut().push(record.key);
        if self
            .conntrack
            .borrow()
            .iter()
            .any(|(candidate, _)| *candidate == record.key)
        {
            return ConntrackReservation::Occupied;
        }
        self.conntrack
            .borrow_mut()
            .push((record.key, record.target));
        ConntrackReservation::Reserved
    }

    fn insert_conntrack(&self, record: ConntrackRecord) -> Result<(), ()> {
        if self.fail_forward_insert.get()
            || self
                .conntrack
                .borrow()
                .iter()
                .any(|(candidate, _)| *candidate == record.key)
        {
            return Err(());
        }
        self.conntrack
            .borrow_mut()
            .push((record.key, record.target));
        Ok(())
    }

    fn remove_conntrack(&self, key: FlowKey) {
        self.conntrack
            .borrow_mut()
            .retain(|(candidate, _)| *candidate != key);
    }
}

fn packet(
    protocol: u8,
    source: [u8; 4],
    source_port: u16,
    destination: [u8; 4],
    destination_port: u16,
) -> Packet {
    Packet {
        protocol,
        source: Socket {
            address: source,
            port: source_port,
        },
        destination: Socket {
            address: destination,
            port: destination_port,
        },
    }
}

fn tcp_packet(
    source: [u8; 4],
    source_port: u16,
    destination: [u8; 4],
    destination_port: u16,
) -> Packet {
    packet(
        IP_PROTOCOL_TCP,
        source,
        source_port,
        destination,
        destination_port,
    )
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += u32::from(word);
        sum = (sum & 0xffff) + (sum >> 16);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn write_checksums(frame: &mut [u8], preserve_udp_zero: bool) {
    frame[24] = 0;
    frame[25] = 0;
    let ipv4 = checksum(&frame[14..34]);
    frame[24..26].copy_from_slice(&ipv4.to_be_bytes());

    let checksum_offset = if frame[23] == IP_PROTOCOL_TCP { 50 } else { 40 };
    if preserve_udp_zero && frame[23] == IP_PROTOCOL_UDP {
        frame[checksum_offset] = 0;
        frame[checksum_offset + 1] = 0;
        return;
    }
    frame[checksum_offset] = 0;
    frame[checksum_offset + 1] = 0;
    let transport_len = frame.len() - 34;
    let mut pseudo = Vec::with_capacity(12 + transport_len);
    pseudo.extend_from_slice(&frame[26..34]);
    pseudo.push(0);
    pseudo.push(frame[23]);
    pseudo.extend_from_slice(&(transport_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&frame[34..]);
    let mut transport = checksum(&pseudo);
    if frame[23] == IP_PROTOCOL_UDP && transport == 0 {
        transport = u16::MAX;
    }
    frame[checksum_offset..checksum_offset + 2].copy_from_slice(&transport.to_be_bytes());
}

fn frame_for(packet: &Packet, payload: &[u8], udp_zero_checksum: bool) -> Vec<u8> {
    let transport_len = if packet.protocol == IP_PROTOCOL_TCP {
        20
    } else {
        8
    };
    let mut frame = vec![0; 14 + 20 + transport_len + payload.len()];
    frame[..6].copy_from_slice(&[0x10, 0x11, 0x12, 0x13, 0x14, 0x15]);
    frame[6..12].copy_from_slice(&[0x20, 0x21, 0x22, 0x23, 0x24, 0x25]);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    frame[14] = 0x45;
    let ipv4_len = (frame.len() - 14) as u16;
    frame[16..18].copy_from_slice(&ipv4_len.to_be_bytes());
    frame[22] = 64;
    frame[23] = packet.protocol;
    frame[26..30].copy_from_slice(&packet.source.address);
    frame[30..34].copy_from_slice(&packet.destination.address);
    frame[34..36].copy_from_slice(&packet.source.port.to_be_bytes());
    frame[36..38].copy_from_slice(&packet.destination.port.to_be_bytes());
    if packet.protocol == IP_PROTOCOL_TCP {
        frame[46] = 0x50;
        frame[47] = 0x18;
        frame[54..].copy_from_slice(payload);
    } else {
        frame[38..40].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        frame[42..].copy_from_slice(payload);
    }
    write_checksums(&mut frame, udp_zero_checksum);
    frame
}

fn independently_translate(frame: &[u8], decision: &datapath::Decision) -> Vec<u8> {
    let mut expected = frame.to_vec();
    let udp_zero = expected[23] == IP_PROTOCOL_UDP && expected[40..42] == [0, 0];
    if let Some(mac) = decision.destination_mac {
        expected[..6].copy_from_slice(&mac);
    }
    match decision.translation {
        Translation::None => {}
        Translation::Source => {
            expected[26..30].copy_from_slice(&decision.source.address);
            expected[34..36].copy_from_slice(&decision.source.port.to_be_bytes());
        }
        Translation::Destination => {
            expected[30..34].copy_from_slice(&decision.destination.address);
            expected[36..38].copy_from_slice(&decision.destination.port.to_be_bytes());
        }
    }
    write_checksums(&mut expected, udp_zero);
    expected
}

fn assert_checksums_are_valid(frame: &[u8]) {
    assert_eq!(checksum(&frame[14..34]), 0);
    if frame[23] == IP_PROTOCOL_UDP && frame[40..42] == [0, 0] {
        return;
    }
    let transport_len = frame.len() - 34;
    let mut pseudo = Vec::with_capacity(12 + transport_len);
    pseudo.extend_from_slice(&frame[26..34]);
    pseudo.push(0);
    pseudo.push(frame[23]);
    pseudo.extend_from_slice(&(transport_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&frame[34..]);
    assert_eq!(checksum(&pseudo), 0);
}

#[test]
fn ebpf_program_builder_is_deterministic() {
    let prog = EbpfProgram {
        name: "xdp_prog".to_string(),
        object_path: "/opt/ferro/xdp.o".to_string(),
        section: "xdp".to_string(),
    };
    assert_eq!(
        build_bpftool_load_cmd(&prog, "/sys/fs/bpf/ferro/xdp"),
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
fn mirrored_metadata_abi_uses_keyed_network_order_entries() {
    assert_eq!(host_abi::ENDPOINT_MAX_ENTRIES, 16_384);
    assert_eq!(host_abi::PORT_MAX_ENTRIES, 16_384);
    assert_eq!(host_abi::CONNTRACK_MAX_ENTRIES, 65_536);
    assert_eq!(host_abi::POLICY_MAX_ENTRIES, 32_768);
    assert_eq!(host_abi::META_MAX_ENTRIES, 4);
    assert_eq!(host_abi::META_MAX_ENTRIES, abi::META_MAX_ENTRIES);
    assert_eq!(host_abi::META_VALUE_LEN, abi::META_VALUE_LEN);
    assert_eq!(host_abi::META_KEY_ABI_VERSION, 0);
    assert_eq!(host_abi::META_KEY_EXTERNAL_IPV4, 1);
    assert_eq!(host_abi::META_KEY_EXTERNAL_IFINDEX, 2);
    assert_eq!(host_abi::META_KEY_NEXT_HOP_MAC, 3);

    let key = host_abi::MetaKey {
        entry: host_abi::META_KEY_EXTERNAL_IFINDEX,
    };
    assert_eq!(key.encode(), [0, 0, 0, 2]);
    assert_eq!(host_abi::MetaKey::decode(key.encode()), key);

    let address = host_abi::MetaValue::from_ipv4([203, 0, 113, 8]);
    assert_eq!(address.as_ipv4(), [203, 0, 113, 8]);
    assert_eq!(host_abi::MetaValue::decode(address.encode()), address);
    let ifindex = host_abi::MetaValue::from_u32(0x0102_0304);
    assert_eq!(&ifindex.encode()[..4], &[1, 2, 3, 4]);
    assert_eq!(ifindex.as_u32(), 0x0102_0304);
    let mac = host_abi::MetaValue::from_mac([2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    assert_eq!(mac.as_mac(), [2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
}

#[test]
fn conntrack_abi_and_kernel_flow_key_have_identical_network_order() {
    let host = host_abi::ConntrackKey {
        protocol: IP_PROTOCOL_TCP,
        source_address: [10, 44, 1, 2],
        destination_address: [192, 0, 2, 10],
        source_port: 0x1234,
        destination_port: 0xabcd,
    };
    let expected = [
        6, 0, 0, 0, 10, 44, 1, 2, 192, 0, 2, 10, 0x12, 0x34, 0xab, 0xcd,
    ];
    assert_eq!(host.encode(), expected);
    assert_eq!(host_abi::ConntrackKey::decode(expected), host);
    assert_eq!(
        FlowKey {
            protocol: host.protocol,
            source: host.source_address,
            destination: host.destination_address,
            source_port: host.source_port,
            destination_port: host.destination_port,
        }
        .encode(),
        expected
    );

    let value = host_abi::ConntrackValue {
        translated_address: [203, 0, 113, 8],
        translated_port: 0xc001,
        state: 1,
        last_seen_ns: 0x0102_0304_0506_0708,
    };
    assert_eq!(
        value.encode(),
        [
            203, 0, 113, 8, 0xc0, 0x01, 1, 0, 1, 2, 3, 4, 5, 6, 7, 8,
        ]
    );
    assert_eq!(host_abi::ConntrackValue::decode(value.encode()), value);
}

#[test]
fn generic_snat_and_reverse_restore_mutate_complete_tcp_packets() {
    let internal = [10, 44, 1, 2];
    let remote = [192, 0, 2, 10];
    let outbound = tcp_packet(internal, 32_000, remote, 443);
    let state = FixtureState::with_external_endpoint(internal);

    let egress = decide_egress(&outbound, &state).unwrap();

    assert_eq!(egress.action, Action::Redirect);
    assert_eq!(egress.ifindex, Some(9));
    assert_eq!(egress.destination_mac, Some([2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]));
    assert_eq!(egress.source.address, [203, 0, 113, 8]);
    assert!((49_152..=65_535).contains(&egress.source.port));
    assert_eq!(egress.translation, Translation::Source);
    let pair = egress
        .installed_conntrack
        .expect("generic SNAT installs a symmetric conntrack pair");
    assert!(state.contains_record(pair.forward));
    assert!(state.contains_record(pair.reverse));

    let mut outbound_frame = frame_for(&outbound, b"odd-len", false);
    let expected_outbound = independently_translate(&outbound_frame, &egress);
    apply_decision(&mut outbound_frame, &outbound, &egress).unwrap();
    assert_eq!(outbound_frame, expected_outbound);
    assert_checksums_are_valid(&outbound_frame);

    let reply = tcp_packet(remote, 443, egress.source.address, egress.source.port);
    let ingress = decide_ingress(&reply, &state).unwrap();
    assert_eq!(ingress.destination, outbound.source);
    assert_eq!(ingress.action, Action::Redirect);
    assert_eq!(ingress.destination_mac, Some([2, 0, 0, 0, 0, 17]));

    let mut reply_frame = frame_for(&reply, b"response!", false);
    let expected_reply = independently_translate(&reply_frame, &ingress);
    apply_decision(&mut reply_frame, &reply, &ingress).unwrap();
    assert_eq!(reply_frame, expected_reply);
    assert_checksums_are_valid(&reply_frame);
}

#[test]
fn snat_collision_probing_uses_noexist_and_selects_the_next_port() {
    let internal = [10, 44, 1, 2];
    let outbound = tcp_packet(internal, 32_000, [192, 0, 2, 10], 443);
    let state = FixtureState::with_external_endpoint(internal);
    let external = state.external.unwrap();
    let first = snat_candidate(&outbound, 0);
    state.insert_existing(
        FlowKey {
            protocol: outbound.protocol,
            source: outbound.destination.address,
            destination: external.address,
            source_port: outbound.destination.port,
            destination_port: first,
        },
        NatTarget {
            address: [10, 44, 9, 9],
            port: 9,
        },
    );

    let decision = decide_egress(&outbound, &state).unwrap();

    assert_eq!(decision.source.port, snat_candidate(&outbound, 1));
    let attempts = state.reserve_attempts.borrow();
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].destination_port, first);
    assert_eq!(attempts[1].destination_port, decision.source.port);
}

#[test]
fn snat_probe_exhaustion_drops_without_overwriting_collisions() {
    let internal = [10, 44, 1, 2];
    let outbound = tcp_packet(internal, 32_000, [192, 0, 2, 10], 443);
    let state = FixtureState::with_external_endpoint(internal);
    let external = state.external.unwrap();
    for probe in 0..SNAT_PROBE_LIMIT {
        state.insert_existing(
            FlowKey {
                protocol: outbound.protocol,
                source: outbound.destination.address,
                destination: external.address,
                source_port: outbound.destination.port,
                destination_port: snat_candidate(&outbound, probe),
            },
            NatTarget {
                address: [10, 44, 9, probe as u8],
                port: probe as u16 + 1,
            },
        );
    }
    let before = state.conntrack.borrow().clone();

    assert_eq!(
        decide_egress(&outbound, &state),
        Err(DecisionError::SnatExhausted)
    );
    assert_eq!(state.reserve_attempts.borrow().len(), SNAT_PROBE_LIMIT as usize);
    assert_eq!(*state.conntrack.borrow(), before);
}

#[test]
fn failed_forward_insert_rolls_back_the_reserved_reverse_entry() {
    let internal = [10, 44, 1, 2];
    let outbound = tcp_packet(internal, 32_000, [192, 0, 2, 10], 443);
    let state = FixtureState::with_external_endpoint(internal);
    state.fail_forward_insert.set(true);

    assert_eq!(
        decide_egress(&outbound, &state),
        Err(DecisionError::ConntrackInsertFailed)
    );
    assert!(state.conntrack.borrow().is_empty());
}

#[test]
fn generic_udp_snat_preserves_zero_checksum_and_rewrites_next_hop_mac() {
    let internal = [10, 44, 1, 2];
    let outbound = packet(IP_PROTOCOL_UDP, internal, 53_000, [192, 0, 2, 53], 53);
    let state = FixtureState::with_external_endpoint(internal);
    let decision = decide_egress(&outbound, &state).unwrap();
    let mut frame = frame_for(&outbound, b"dns", true);

    apply_decision(&mut frame, &outbound, &decision).unwrap();

    assert_eq!(&frame[..6], &[2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    assert_eq!(&frame[40..42], &[0, 0]);
    assert_eq!(&frame[26..30], &[203, 0, 113, 8]);
    assert_checksums_are_valid(&frame);
}

#[test]
fn checked_destination_mac_mutation_rejects_malformed_packets_without_changes() {
    let valid_packet = tcp_packet([10, 44, 1, 2], 32_000, [192, 0, 2, 10], 443);
    let mut valid = frame_for(&valid_packet, b"x", false);
    packet::rewrite_ethernet_destination(&mut valid, [2, 1, 2, 3, 4, 5]).unwrap();
    assert_eq!(&valid[..6], &[2, 1, 2, 3, 4, 5]);

    let mut malformed = vec![0u8; 13];
    let before = malformed.clone();
    assert!(packet::rewrite_ethernet_destination(&mut malformed, [2; 6]).is_err());
    assert_eq!(malformed, before);
    assert_eq!(
        action_for_parse_failure(ParseFailure::Invalid, true),
        Action::Drop
    );
}

#[test]
fn helper_result_controls_outcome_and_nat_counters() {
    let internal = [10, 44, 1, 2];
    let outbound = tcp_packet(internal, 32_000, [192, 0, 2, 10], 443);
    let state = FixtureState::with_external_endpoint(internal);
    let decision = decide_egress(&outbound, &state).unwrap();

    let failed = actual_disposition(&decision, false);
    assert_eq!(failed, Action::Drop);
    let failed_metrics = decision.metrics(Direction::Egress, failed);
    assert_eq!(failed_metrics.outcome, Counter::Drops);
    assert!(!failed_metrics.translated);

    let successful = actual_disposition(&decision, true);
    assert_eq!(successful, Action::Redirect);
    let successful_metrics = decision.metrics(Direction::Egress, successful);
    assert_eq!(successful_metrics.outcome, Counter::Redirects);
    assert!(successful_metrics.translated);

    let mut zero_ifindex = decision;
    zero_ifindex.ifindex = Some(0);
    assert_eq!(actual_disposition(&zero_ifindex, true), Action::Drop);
}

#[test]
fn published_port_dnat_carries_endpoint_mac_and_reverse_tuple() {
    let remote = [192, 0, 2, 10];
    let host = [203, 0, 113, 8];
    let endpoint_address = [10, 44, 1, 2];
    let ingress_packet = tcp_packet(remote, 51_000, host, 8080);
    let mut state = FixtureState::default();
    state.ports.push((
        (ingress_packet.protocol, 8080),
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

    let decision = decide_ingress(&ingress_packet, &state).unwrap();

    assert_eq!(decision.destination, Socket { address: endpoint_address, port: 80 });
    assert_eq!(decision.destination_mac, Some([2, 0, 0, 0, 0, 17]));
    assert_eq!(
        decision.reverse_conntrack,
        Some(ConntrackRecord {
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
        })
    );
}

#[test]
fn conntrack_pair_type_is_symmetric_by_construction() {
    let pair = ConntrackPair {
        forward: ConntrackRecord {
            key: FlowKey {
                protocol: 6,
                source: [10, 44, 1, 2],
                destination: [192, 0, 2, 10],
                source_port: 32_000,
                destination_port: 443,
            },
            target: NatTarget {
                address: [203, 0, 113, 8],
                port: 50_000,
            },
        },
        reverse: ConntrackRecord {
            key: FlowKey {
                protocol: 6,
                source: [192, 0, 2, 10],
                destination: [203, 0, 113, 8],
                source_port: 443,
                destination_port: 50_000,
            },
            target: NatTarget {
                address: [10, 44, 1, 2],
                port: 32_000,
            },
        },
    };
    assert_eq!(pair.forward.key.source, pair.reverse.target.address);
    assert_eq!(pair.forward.key.source_port, pair.reverse.target.port);
    assert_eq!(pair.forward.target.address, pair.reverse.key.destination);
    assert_eq!(pair.forward.target.port, pair.reverse.key.destination_port);
}
