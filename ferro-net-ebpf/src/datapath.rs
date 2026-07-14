#![cfg_attr(not(target_arch = "bpf"), allow(dead_code))]

use crate::packet::{
    rewrite_ethernet_destination, rewrite_ipv4_destination, rewrite_ipv4_source,
    rewrite_transport_port, PacketError, PortField,
};

pub const IP_PROTOCOL_TCP: u8 = 6;
pub const IP_PROTOCOL_UDP: u8 = 17;
pub const CONNTRACK_STATE_ESTABLISHED: u8 = 1;
pub const POLICY_ACTION_ALLOW: u8 = 1;
pub const SNAT_PORT_BASE: u16 = 49_152;
pub const SNAT_PORT_COUNT: u32 = 16_384;
pub const SNAT_PROBE_LIMIT: u8 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    Ingress,
    Egress,
}

impl Direction {
    pub const fn abi_value(self) -> u8 {
        match self {
            Self::Ingress => 0,
            Self::Egress => 1,
        }
    }

    pub const fn packet_counter(self) -> Counter {
        match self {
            Self::Ingress => Counter::IngressPackets,
            Self::Egress => Counter::EgressPackets,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Pass,
    Drop,
    Redirect,
}

impl Action {
    pub const fn counter(self) -> Counter {
        match self {
            Self::Pass => Counter::Passes,
            Self::Drop => Counter::Drops,
            Self::Redirect => Counter::Redirects,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Counter {
    IngressPackets = 0,
    EgressPackets = 1,
    Redirects = 2,
    Passes = 3,
    Drops = 4,
    NatTranslations = 5,
    PolicyDenials = 6,
    MapErrors = 7,
    SnatExhaustions = 8,
}

impl Counter {
    pub const fn index(self) -> u32 {
        self as u32
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Socket {
    pub address: [u8; 4],
    pub port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Packet {
    pub protocol: u8,
    pub source: Socket,
    pub destination: Socket,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowKey {
    pub protocol: u8,
    pub source: [u8; 4],
    pub destination: [u8; 4],
    pub source_port: u16,
    pub destination_port: u16,
}

impl FlowKey {
    pub const fn from_packet(packet: &Packet) -> Self {
        Self {
            protocol: packet.protocol,
            source: packet.source.address,
            destination: packet.destination.address,
            source_port: packet.source.port,
            destination_port: packet.destination.port,
        }
    }

    #[inline(always)]
    pub fn encode(self) -> [u8; 16] {
        let mut bytes = [0; 16];
        bytes[0] = self.protocol;
        bytes[4..8].copy_from_slice(&self.source);
        bytes[8..12].copy_from_slice(&self.destination);
        bytes[12..14].copy_from_slice(&self.source_port.to_be_bytes());
        bytes[14..16].copy_from_slice(&self.destination_port.to_be_bytes());
        bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyKey {
    pub endpoint: [u8; 4],
    pub protocol: u8,
    pub direction: Direction,
    pub port: u16,
}

impl PolicyKey {
    pub const fn for_packet(packet: &Packet, direction: Direction) -> Self {
        let endpoint = match direction {
            Direction::Ingress => packet.destination.address,
            Direction::Egress => packet.source.address,
        };
        Self {
            endpoint,
            protocol: packet.protocol,
            direction,
            port: packet.destination.port,
        }
    }

    #[inline(always)]
    pub fn encode(self) -> [u8; 8] {
        let mut bytes = [0; 8];
        bytes[..4].copy_from_slice(&self.endpoint);
        bytes[4] = self.protocol;
        bytes[5] = self.direction.abi_value();
        bytes[6..8].copy_from_slice(&self.port.to_be_bytes());
        bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyAction {
    Allow,
    Deny,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NatTarget {
    pub address: [u8; 4],
    pub port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PortTarget {
    pub address: [u8; 4],
    pub port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Endpoint {
    pub ifindex: u32,
    pub mac: [u8; 6],
    pub flags: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExternalNetwork {
    pub address: [u8; 4],
    pub ifindex: u32,
    pub next_hop_mac: [u8; 6],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConntrackRecord {
    pub key: FlowKey,
    pub target: NatTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConntrackPair {
    pub forward: ConntrackRecord,
    pub reverse: ConntrackRecord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConntrackReservation {
    Reserved,
    Occupied,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Translation {
    None,
    Source,
    Destination,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Decision {
    pub action: Action,
    pub source: Socket,
    pub destination: Socket,
    pub ifindex: Option<u32>,
    pub destination_mac: Option<[u8; 6]>,
    pub translation: Translation,
    pub reverse_conntrack: Option<ConntrackRecord>,
    pub installed_conntrack: Option<ConntrackPair>,
}

impl Decision {
    fn pass(packet: &Packet) -> Self {
        Self {
            action: Action::Pass,
            source: packet.source,
            destination: packet.destination,
            ifindex: None,
            destination_mac: None,
            translation: Translation::None,
            reverse_conntrack: None,
            installed_conntrack: None,
        }
    }

    pub fn metrics(self, direction: Direction, actual: Action) -> DecisionMetrics {
        DecisionMetrics {
            packet: direction.packet_counter(),
            outcome: actual.counter(),
            translated: actual != Action::Drop
                && !matches!(self.translation, Translation::None),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecisionMetrics {
    pub packet: Counter,
    pub outcome: Counter,
    pub translated: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecisionError {
    PolicyDenied,
    EndpointMissing,
    InvalidTranslation,
    MetadataMissing,
    SnatExhausted,
    ConntrackInsertFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseFailure {
    Unsupported,
    Invalid,
}

pub const fn action_for_parse_failure(failure: ParseFailure, owned: bool) -> Action {
    match failure {
        ParseFailure::Unsupported => Action::Pass,
        ParseFailure::Invalid if owned => Action::Drop,
        ParseFailure::Invalid => Action::Pass,
    }
}

pub const fn actual_disposition(decision: &Decision, redirect_succeeded: bool) -> Action {
    match decision.action {
        Action::Redirect => match decision.ifindex {
            Some(ifindex) if ifindex != 0 && redirect_succeeded => Action::Redirect,
            _ => Action::Drop,
        },
        action => action,
    }
}

pub trait DatapathState {
    fn policy(&self, key: PolicyKey) -> Option<PolicyAction>;
    fn conntrack(&self, key: FlowKey) -> Option<NatTarget>;
    fn published_port(&self, protocol: u8, host_port: u16) -> Option<PortTarget>;
    fn endpoint(&self, address: [u8; 4]) -> Option<Endpoint>;
    fn external_network(&self) -> Option<ExternalNetwork> {
        None
    }
    fn reserve_conntrack(&self, _record: ConntrackRecord) -> ConntrackReservation {
        ConntrackReservation::Failed
    }
    fn insert_conntrack(&self, _record: ConntrackRecord) -> Result<(), ()> {
        Err(())
    }
    fn remove_conntrack(&self, _key: FlowKey) {}
}

fn enforce_policy<S: DatapathState>(
    packet: &Packet,
    direction: Direction,
    state: &S,
) -> Result<(), DecisionError> {
    match state.policy(PolicyKey::for_packet(packet, direction)) {
        Some(PolicyAction::Deny) => Err(DecisionError::PolicyDenied),
        Some(PolicyAction::Allow) | None => Ok(()),
    }
}

fn valid_target(address: [u8; 4], port: u16) -> bool {
    address != [0; 4] && port != 0
}

fn valid_external(external: ExternalNetwork) -> bool {
    external.address != [0; 4]
        && external.ifindex != 0
        && external.next_hop_mac != [0; 6]
}

#[inline(always)]
pub fn snat_candidate(packet: &Packet, probe: u8) -> u16 {
    let bytes = FlowKey::from_packet(packet).encode();
    let mut hash = 2_166_136_261u32;
    let mut index = 0usize;
    while index < bytes.len() {
        hash ^= u32::from(bytes[index]);
        hash = hash.wrapping_mul(16_777_619);
        index += 1;
    }
    SNAT_PORT_BASE + ((hash.wrapping_add(u32::from(probe))) % SNAT_PORT_COUNT) as u16
}

fn conntrack_pair(packet: &Packet, external: ExternalNetwork, port: u16) -> ConntrackPair {
    ConntrackPair {
        forward: ConntrackRecord {
            key: FlowKey::from_packet(packet),
            target: NatTarget {
                address: external.address,
                port,
            },
        },
        reverse: ConntrackRecord {
            key: FlowKey {
                protocol: packet.protocol,
                source: packet.destination.address,
                destination: external.address,
                source_port: packet.destination.port,
                destination_port: port,
            },
            target: NatTarget {
                address: packet.source.address,
                port: packet.source.port,
            },
        },
    }
}

fn install_generic_snat<S: DatapathState>(
    packet: &Packet,
    external: ExternalNetwork,
    state: &S,
) -> Result<ConntrackPair, DecisionError> {
    let mut probe = 0u8;
    while probe < SNAT_PROBE_LIMIT {
        let pair = conntrack_pair(packet, external, snat_candidate(packet, probe));
        match state.reserve_conntrack(pair.reverse) {
            ConntrackReservation::Occupied => {
                probe += 1;
            }
            ConntrackReservation::Failed => return Err(DecisionError::ConntrackInsertFailed),
            ConntrackReservation::Reserved => {
                if state.insert_conntrack(pair.forward).is_err() {
                    state.remove_conntrack(pair.reverse.key);
                    return Err(DecisionError::ConntrackInsertFailed);
                }
                return Ok(pair);
            }
        }
    }
    Err(DecisionError::SnatExhausted)
}

pub fn decide_ingress<S: DatapathState>(
    packet: &Packet,
    state: &S,
) -> Result<Decision, DecisionError> {
    enforce_policy(packet, Direction::Ingress, state)?;
    let mut decision = Decision::pass(packet);

    if let Some(target) = state.conntrack(FlowKey::from_packet(packet)) {
        if !valid_target(target.address, target.port) {
            return Err(DecisionError::InvalidTranslation);
        }
        decision.destination = Socket {
            address: target.address,
            port: target.port,
        };
        decision.translation = Translation::Destination;
    } else if let Some(target) = state.published_port(packet.protocol, packet.destination.port) {
        if !valid_target(target.address, target.port) {
            return Err(DecisionError::InvalidTranslation);
        }
        decision.destination = Socket {
            address: target.address,
            port: target.port,
        };
        decision.translation = Translation::Destination;
        decision.reverse_conntrack = Some(ConntrackRecord {
            key: FlowKey {
                protocol: packet.protocol,
                source: target.address,
                destination: packet.source.address,
                source_port: target.port,
                destination_port: packet.source.port,
            },
            target: NatTarget {
                address: packet.destination.address,
                port: packet.destination.port,
            },
        });
    }

    match state.endpoint(decision.destination.address) {
        Some(endpoint) if endpoint.ifindex != 0 && endpoint.mac != [0; 6] => {
            decision.action = Action::Redirect;
            decision.ifindex = Some(endpoint.ifindex);
            decision.destination_mac = Some(endpoint.mac);
            Ok(decision)
        }
        Some(_) => Err(DecisionError::EndpointMissing),
        None if decision.translation != Translation::None => Err(DecisionError::EndpointMissing),
        None => Ok(decision),
    }
}

pub fn decide_egress<S: DatapathState>(
    packet: &Packet,
    state: &S,
) -> Result<Decision, DecisionError> {
    enforce_policy(packet, Direction::Egress, state)?;
    let mut decision = Decision::pass(packet);

    if let Some(target) = state.conntrack(FlowKey::from_packet(packet)) {
        if !valid_target(target.address, target.port) {
            return Err(DecisionError::InvalidTranslation);
        }
        decision.source = Socket {
            address: target.address,
            port: target.port,
        };
        decision.translation = Translation::Source;
    }

    if let Some(endpoint) = state.endpoint(decision.destination.address) {
        if endpoint.ifindex == 0 || endpoint.mac == [0; 6] {
            return Err(DecisionError::EndpointMissing);
        }
        decision.action = Action::Redirect;
        decision.ifindex = Some(endpoint.ifindex);
        decision.destination_mac = Some(endpoint.mac);
        return Ok(decision);
    }

    if state.endpoint(packet.source.address).is_none() {
        return Ok(decision);
    }
    let external = state
        .external_network()
        .filter(|metadata| valid_external(*metadata))
        .ok_or(DecisionError::MetadataMissing)?;
    if decision.translation == Translation::None {
        let pair = install_generic_snat(packet, external, state)?;
        decision.source = Socket {
            address: pair.forward.target.address,
            port: pair.forward.target.port,
        };
        decision.translation = Translation::Source;
        decision.installed_conntrack = Some(pair);
    }
    decision.action = Action::Redirect;
    decision.ifindex = Some(external.ifindex);
    decision.destination_mac = Some(external.next_hop_mac);
    Ok(decision)
}

pub fn apply_decision(
    bytes: &mut [u8],
    packet: &Packet,
    decision: &Decision,
) -> Result<(), PacketError> {
    match decision.translation {
        Translation::None => {}
        Translation::Source => {
            if packet.source.address != decision.source.address {
                rewrite_ipv4_source(bytes, decision.source.address)?;
            }
            if packet.source.port != decision.source.port {
                rewrite_transport_port(bytes, PortField::Source, decision.source.port)?;
            }
        }
        Translation::Destination => {
            if packet.destination.address != decision.destination.address {
                rewrite_ipv4_destination(bytes, decision.destination.address)?;
            }
            if packet.destination.port != decision.destination.port {
                rewrite_transport_port(bytes, PortField::Destination, decision.destination.port)?;
            }
        }
    }
    if let Some(mac) = decision.destination_mac {
        rewrite_ethernet_destination(bytes, mac)?;
    }
    Ok(())
}
