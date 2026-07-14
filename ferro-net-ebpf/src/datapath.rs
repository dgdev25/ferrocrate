#![cfg_attr(not(target_arch = "bpf"), allow(dead_code))]

pub const ENDPOINT_MAX_ENTRIES: u32 = 16_384;
pub const PORT_MAX_ENTRIES: u32 = 16_384;
pub const CONNTRACK_MAX_ENTRIES: u32 = 65_536;
pub const POLICY_MAX_ENTRIES: u32 = 32_768;
pub const META_MAX_ENTRIES: u32 = 1;
pub const COUNTER_MAX_ENTRIES: u32 = 8;

pub const IP_PROTOCOL_TCP: u8 = 6;
pub const IP_PROTOCOL_UDP: u8 = 17;
pub const CONNTRACK_STATE_ESTABLISHED: u8 = 1;
pub const POLICY_ACTION_ALLOW: u8 = 1;

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

impl Packet {
    #[cfg(not(target_arch = "bpf"))]
    pub const fn tcp(
        source: [u8; 4],
        source_port: u16,
        destination: [u8; 4],
        destination_port: u16,
    ) -> Self {
        Self {
            protocol: IP_PROTOCOL_TCP,
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
pub struct ConntrackRecord {
    pub key: FlowKey,
    pub target: NatTarget,
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
    pub translation: Translation,
    pub reverse_conntrack: Option<ConntrackRecord>,
}

impl Decision {
    fn pass(packet: &Packet) -> Self {
        Self {
            action: Action::Pass,
            source: packet.source,
            destination: packet.destination,
            ifindex: None,
            translation: Translation::None,
            reverse_conntrack: None,
        }
    }

    pub const fn metrics(self, direction: Direction) -> DecisionMetrics {
        DecisionMetrics {
            packet: direction.packet_counter(),
            outcome: self.action.counter(),
            translated: !matches!(self.translation, Translation::None),
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

pub trait DatapathState {
    fn policy(&self, key: PolicyKey) -> Option<PolicyAction>;
    fn conntrack(&self, key: FlowKey) -> Option<NatTarget>;
    fn published_port(&self, protocol: u8, host_port: u16) -> Option<PortTarget>;
    fn endpoint(&self, address: [u8; 4]) -> Option<Endpoint>;
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
        Some(endpoint) if endpoint.ifindex != 0 => {
            decision.action = Action::Redirect;
            decision.ifindex = Some(endpoint.ifindex);
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

    match state.endpoint(decision.destination.address) {
        Some(endpoint) if endpoint.ifindex != 0 => {
            decision.action = Action::Redirect;
            decision.ifindex = Some(endpoint.ifindex);
            Ok(decision)
        }
        Some(_) => Err(DecisionError::EndpointMissing),
        None => Ok(decision),
    }
}
