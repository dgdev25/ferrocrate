#![no_std]
#![no_main]
#![deny(clippy::undocumented_unsafe_blocks)]

#[allow(dead_code)]
mod abi;
mod datapath;
mod maps;
mod packet;

use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_REDIRECT, TC_ACT_SHOT},
    helpers::bpf_redirect,
    macros::classifier,
    programs::TcContext,
};
use core::panic::PanicInfo;

use datapath::{
    action_for_parse_failure, actual_disposition, decide_egress, decide_ingress,
    decision_error_counter, Action, Counter, DatapathState, Decision, Direction, Packet,
    ParseFailure, IP_PROTOCOL_TCP, IP_PROTOCOL_UDP,
};
use maps::KernelState;
use packet::{PacketError, PacketView, TransportProtocol};

#[used]
static ABI_VERSION: u32 = abi::PROGRAM_ABI_VERSION;

#[classifier]
pub fn ferro_ingress(ctx: TcContext) -> i32 {
    classify(ctx, Direction::Ingress)
}

#[classifier]
pub fn ferro_egress(ctx: TcContext) -> i32 {
    classify(ctx, Direction::Egress)
}

fn classify(ctx: TcContext, direction: Direction) -> i32 {
    maps::increment(direction.packet_counter());
    if ctx.pull_data(0).is_err() {
        return finish_without_decision(Action::Drop);
    }

    let parsed = PacketView::parse(&ctx);
    let state = KernelState;
    let view = match parsed {
        Ok(view) => view,
        Err(error) => {
            let failure = match error {
                PacketError::UnsupportedNetwork | PacketError::UnsupportedTransport => {
                    ParseFailure::Unsupported
                }
                PacketError::Truncated
                | PacketError::InvalidIpv4Header
                | PacketError::InvalidTransportHeader
                | PacketError::Fragmented => ParseFailure::Invalid,
            };
            let owned = invalid_packet_is_owned_context(&ctx, direction, &state);
            return finish_without_decision(action_for_parse_failure(failure, owned));
        }
    };
    let packet = match packet_from_context(&ctx, view) {
        Ok(packet) => packet,
        Err(_) => return finish_without_decision(Action::Drop),
    };

    let decision = match direction {
        Direction::Ingress => decide_ingress(&packet, &state),
        Direction::Egress => decide_egress(&packet, &state),
    };
    let decision = match decision {
        Ok(decision) => decision,
        Err(error) => {
            if let Some(counter) = decision_error_counter(error) {
                maps::increment(counter);
            }
            return finish_without_decision(Action::Drop);
        }
    };

    if let Some(record) = decision.reverse_conntrack {
        if maps::insert_reverse_conntrack(record).is_err() {
            maps::increment(Counter::MapErrors);
            return finish_without_decision(Action::Drop);
        }
    }
    if packet::apply_decision_context(&ctx, view, &packet, &decision).is_err() {
        return finish_without_decision(Action::Drop);
    }

    let (actual, tc_result) = disposition(&decision);
    let metrics = decision.metrics(direction, actual);
    maps::increment(metrics.outcome);
    if metrics.translated {
        maps::increment(Counter::NatTranslations);
    }
    tc_result
}

fn disposition(decision: &Decision) -> (Action, i32) {
    match decision.action {
        Action::Pass => (Action::Pass, TC_ACT_OK),
        Action::Drop => (Action::Drop, TC_ACT_SHOT),
        Action::Redirect => {
            let redirect_result = match decision.ifindex {
                Some(ifindex) if ifindex != 0 => {
                    // SAFETY: bpf_redirect consumes only the validated ifindex
                    // scalar and zero flags; it dereferences no Rust pointer.
                    unsafe { bpf_redirect(ifindex, 0) as i32 }
                }
                _ => TC_ACT_SHOT,
            };
            let actual = actual_disposition(decision, redirect_result == TC_ACT_REDIRECT);
            let result = if actual == Action::Redirect {
                redirect_result
            } else {
                TC_ACT_SHOT
            };
            (actual, result)
        }
    }
}

fn packet_from_context(ctx: &TcContext, view: PacketView) -> Result<Packet, PacketError> {
    let source = load_address(ctx, view.ipv4_offset + 12)?;
    let destination = load_address(ctx, view.ipv4_offset + 16)?;
    let (source_port, destination_port) = transport_port_offsets(view)
        .map(|(source, destination)| (load_u16(ctx, source), load_u16(ctx, destination)))
        .ok_or(PacketError::Truncated)?;
    let source_port = source_port?;
    let destination_port = destination_port?;
    let protocol = match view.transport {
        TransportProtocol::Tcp => IP_PROTOCOL_TCP,
        TransportProtocol::Udp => IP_PROTOCOL_UDP,
    };
    Ok(Packet {
        protocol,
        source: datapath::Socket {
            address: source,
            port: source_port,
        },
        destination: datapath::Socket {
            address: destination,
            port: destination_port,
        },
    })
}

fn transport_port_offsets(view: PacketView) -> Option<(usize, usize)> {
    match view.transport_offset {
        20 => Some((20, 22)),
        24 => Some((24, 26)),
        28 => Some((28, 30)),
        32 => Some((32, 34)),
        36 => Some((36, 38)),
        40 => Some((40, 42)),
        44 => Some((44, 46)),
        48 => Some((48, 50)),
        52 => Some((52, 54)),
        56 => Some((56, 58)),
        60 => Some((60, 62)),
        34 => Some((34, 36)),
        38 => Some((38, 40)),
        42 => Some((42, 44)),
        46 => Some((46, 48)),
        50 => Some((50, 52)),
        54 => Some((54, 56)),
        58 => Some((58, 60)),
        62 => Some((62, 64)),
        66 => Some((66, 68)),
        70 => Some((70, 72)),
        74 => Some((74, 76)),
        _ => None,
    }
}

fn load_address(ctx: &TcContext, offset: usize) -> Result<[u8; 4], PacketError> {
    Ok([
        load_byte(ctx, offset)?,
        load_byte(ctx, offset + 1)?,
        load_byte(ctx, offset + 2)?,
        load_byte(ctx, offset + 3)?,
    ])
}

fn load_byte(ctx: &TcContext, offset: usize) -> Result<u8, PacketError> {
    ctx.load::<u8>(offset).map_err(|_| PacketError::Truncated)
}

fn load_u16(ctx: &TcContext, offset: usize) -> Result<u16, PacketError> {
    let high = load_byte(ctx, offset)?;
    let low = load_byte(ctx, offset + 1)?;
    Ok(u16::from_be_bytes([high, low]))
}

fn invalid_packet_is_owned_context<S: DatapathState>(
    ctx: &TcContext,
    direction: Direction,
    state: &S,
) -> bool {
    let ethernet = load_u16(ctx, 12) == Ok(0x0800);
    let ipv4_offset = if ethernet { 14 } else { 0 };
    let address_offset = match direction {
        Direction::Ingress => ipv4_offset + 16,
        Direction::Egress => ipv4_offset + 12,
    };
    if let Ok(address) = load_address(ctx, address_offset) {
        if state.endpoint(address).is_some() {
            return true;
        }
    }
    if direction != Direction::Ingress {
        return false;
    }
    let version_ihl = match load_byte(ctx, ipv4_offset) {
        Ok(value) if value >> 4 == 4 => value,
        _ => return false,
    };
    let protocol = match load_byte(ctx, ipv4_offset + 9) {
        Ok(value) if value == IP_PROTOCOL_TCP || value == IP_PROTOCOL_UDP => value,
        _ => return false,
    };
    let destination_offset = match (ipv4_offset, version_ihl & 0x0f) {
        (0, 5) => 22,
        (0, 6) => 26,
        (0, 7) => 30,
        (0, 8) => 34,
        (0, 9) => 38,
        (0, 10) => 42,
        (0, 11) => 46,
        (0, 12) => 50,
        (0, 13) => 54,
        (0, 14) => 58,
        (0, 15) => 62,
        (14, 5) => 36,
        (14, 6) => 40,
        (14, 7) => 44,
        (14, 8) => 48,
        (14, 9) => 52,
        (14, 10) => 56,
        (14, 11) => 60,
        (14, 12) => 64,
        (14, 13) => 68,
        (14, 14) => 72,
        (14, 15) => 76,
        _ => return false,
    };
    let destination_port = load_u16(ctx, destination_offset);
    match destination_port {
        Ok(port) => state.published_port(protocol, port).is_some(),
        Err(_) => false,
    }
}

fn finish_without_decision(action: Action) -> i32 {
    maps::increment(action.counter());
    match action {
        Action::Pass => TC_ACT_OK,
        Action::Drop | Action::Redirect => TC_ACT_SHOT,
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
