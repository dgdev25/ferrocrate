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
    let source = load_address(ctx, 26)?;
    let destination = load_address(ctx, 30)?;
    let (source_port, destination_port) = match view.transport_offset {
        34 => (load_u16(ctx, 34)?, load_u16(ctx, 36)?),
        38 => (load_u16(ctx, 38)?, load_u16(ctx, 40)?),
        42 => (load_u16(ctx, 42)?, load_u16(ctx, 44)?),
        46 => (load_u16(ctx, 46)?, load_u16(ctx, 48)?),
        50 => (load_u16(ctx, 50)?, load_u16(ctx, 52)?),
        54 => (load_u16(ctx, 54)?, load_u16(ctx, 56)?),
        58 => (load_u16(ctx, 58)?, load_u16(ctx, 60)?),
        62 => (load_u16(ctx, 62)?, load_u16(ctx, 64)?),
        66 => (load_u16(ctx, 66)?, load_u16(ctx, 68)?),
        70 => (load_u16(ctx, 70)?, load_u16(ctx, 72)?),
        74 => (load_u16(ctx, 74)?, load_u16(ctx, 76)?),
        _ => return Err(PacketError::Truncated),
    };
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
    if load_u16(ctx, 12) != Ok(0x0800) {
        return false;
    }
    let address_offset = match direction {
        Direction::Ingress => 30,
        Direction::Egress => 26,
    };
    if let Ok(address) = load_address(ctx, address_offset) {
        if state.endpoint(address).is_some() {
            return true;
        }
    }
    if direction != Direction::Ingress {
        return false;
    }
    let version_ihl = match load_byte(ctx, 14) {
        Ok(value) if value >> 4 == 4 => value,
        _ => return false,
    };
    let protocol = match load_byte(ctx, 23) {
        Ok(value) if value == IP_PROTOCOL_TCP || value == IP_PROTOCOL_UDP => value,
        _ => return false,
    };
    let destination_port = match version_ihl & 0x0f {
        5 => load_u16(ctx, 36),
        6 => load_u16(ctx, 40),
        7 => load_u16(ctx, 44),
        8 => load_u16(ctx, 48),
        9 => load_u16(ctx, 52),
        10 => load_u16(ctx, 56),
        11 => load_u16(ctx, 60),
        12 => load_u16(ctx, 64),
        13 => load_u16(ctx, 68),
        14 => load_u16(ctx, 72),
        15 => load_u16(ctx, 76),
        _ => return false,
    };
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
