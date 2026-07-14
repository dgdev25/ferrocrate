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
use core::{panic::PanicInfo, slice};

use datapath::{
    action_for_parse_failure, actual_disposition, apply_decision, decide_egress, decide_ingress,
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
    // SAFETY: this classifier owns the context, pull_data made the skb linear,
    // and exactly one mutable slice is created from the checked data bounds.
    let bytes = match unsafe { packet_bytes(&ctx) } {
        Ok(bytes) => bytes,
        Err(_) => return finish_without_decision(Action::Drop),
    };
    let state = KernelState;
    let packet = match parsed {
        Ok(view) => match packet_from_view(bytes, view) {
            Ok(packet) => packet,
            Err(_) => return finish_without_decision(Action::Drop),
        },
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
            let owned = invalid_packet_is_owned(bytes, direction, &state);
            return finish_without_decision(action_for_parse_failure(failure, owned));
        }
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
    if apply_decision(bytes, &packet, &decision).is_err() {
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

unsafe fn packet_bytes<'a>(ctx: &'a TcContext) -> Result<&'a mut [u8], PacketError> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = end.checked_sub(start).ok_or(PacketError::Truncated)?;
    // SAFETY: data/data_end are verifier-provided ordered skb bounds. The caller
    // owns the context and creates no alias or skb-reallocating helper while live.
    Ok(unsafe { slice::from_raw_parts_mut(start as *mut u8, len) })
}

fn packet_from_view(bytes: &[u8], view: PacketView) -> Result<Packet, PacketError> {
    let source = read_address(bytes, view.ipv4_offset + 12)?;
    let destination = read_address(bytes, view.ipv4_offset + 16)?;
    let source_port = read_u16(bytes, view.transport_offset)?;
    let destination_port = read_u16(bytes, view.transport_offset + 2)?;
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

fn read_address(bytes: &[u8], offset: usize) -> Result<[u8; 4], PacketError> {
    let end = offset.checked_add(4).ok_or(PacketError::Truncated)?;
    let address = bytes.get(offset..end).ok_or(PacketError::Truncated)?;
    Ok([address[0], address[1], address[2], address[3]])
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, PacketError> {
    let end = offset.checked_add(2).ok_or(PacketError::Truncated)?;
    let value = bytes.get(offset..end).ok_or(PacketError::Truncated)?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn invalid_packet_is_owned<S: DatapathState>(
    bytes: &[u8],
    direction: Direction,
    state: &S,
) -> bool {
    if read_u16(bytes, 12) != Ok(0x0800) {
        return false;
    }
    let address_offset = match direction {
        Direction::Ingress => 14 + 16,
        Direction::Egress => 14 + 12,
    };
    if let Ok(address) = read_address(bytes, address_offset) {
        if state.endpoint(address).is_some() {
            return true;
        }
    }
    if direction != Direction::Ingress {
        return false;
    }
    let version_ihl = match bytes.get(14) {
        Some(value) if value >> 4 == 4 => *value,
        _ => return false,
    };
    let transport_offset = 14 + usize::from(version_ihl & 0x0f) * 4;
    let protocol = match bytes.get(14 + 9) {
        Some(value) if *value == IP_PROTOCOL_TCP || *value == IP_PROTOCOL_UDP => *value,
        _ => return false,
    };
    let destination_port = match read_u16(bytes, transport_offset + 2) {
        Ok(port) => port,
        Err(_) => return false,
    };
    state.published_port(protocol, destination_port).is_some()
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
