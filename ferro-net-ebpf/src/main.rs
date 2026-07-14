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
    helpers::{bpf_ktime_get_ns, bpf_redirect},
    macros::classifier,
    programs::TcContext,
};
use core::{panic::PanicInfo, slice};

use datapath::{
    action_for_parse_failure, decide_egress, decide_ingress, Action, Counter, DatapathState,
    Decision, Direction, Packet, ParseFailure, Translation, IP_PROTOCOL_TCP, IP_PROTOCOL_UDP,
};
use maps::KernelState;
use packet::{
    rewrite_ipv4_destination, rewrite_ipv4_source, rewrite_transport_port, PacketError,
    PacketView, PortField, TransportProtocol,
};

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
        return finish(Action::Drop, None, false);
    }

    let parsed = PacketView::parse(&ctx);
    // SAFETY: this classifier owns the TcContext for the duration of the call,
    // pull_data has just made the skb linear, and this is the only packet slice
    // created from the verifier-provided data/data_end range.
    let bytes = match unsafe { packet_bytes(&ctx) } {
        Ok(bytes) => bytes,
        Err(_) => return finish(Action::Drop, None, false),
    };
    let state = KernelState;
    let packet = match parsed {
        Ok(view) => match packet_from_view(bytes, view) {
            Ok(packet) => packet,
            Err(_) => return finish(Action::Drop, None, false),
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
            return finish(action_for_parse_failure(failure, owned), None, false);
        }
    };

    let decision = match direction {
        Direction::Ingress => decide_ingress(&packet, &state),
        Direction::Egress => decide_egress(&packet, &state),
    };
    let decision = match decision {
        Ok(decision) => decision,
        Err(datapath::DecisionError::PolicyDenied) => {
            maps::increment(Counter::PolicyDenials);
            return finish(Action::Drop, None, false);
        }
        Err(_) => {
            maps::increment(Counter::MapErrors);
            return finish(Action::Drop, None, false);
        }
    };

    if let Some(record) = decision.reverse_conntrack {
        // SAFETY: bpf_ktime_get_ns takes no pointers and returns the kernel's
        // monotonic nanosecond scalar for the current classifier invocation.
        let now = unsafe { bpf_ktime_get_ns() };
        if maps::insert_reverse_conntrack(record, now).is_err() {
            maps::increment(Counter::MapErrors);
            return finish(Action::Drop, None, false);
        }
    }

    if apply_translation(bytes, &packet, &decision).is_err() {
        return finish(Action::Drop, None, false);
    }

    let metrics = decision.metrics(direction);
    debug_assert_eq!(metrics.packet, direction.packet_counter());
    maps::increment(metrics.outcome);
    if metrics.translated {
        maps::increment(Counter::NatTranslations);
    }
    tc_action(decision.action, decision.ifindex)
}

unsafe fn packet_bytes<'a>(ctx: &'a TcContext) -> Result<&'a mut [u8], PacketError> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = end.checked_sub(start).ok_or(PacketError::Truncated)?;
    // SAFETY: data and data_end are verifier-provided skb bounds, checked above
    // to be ordered. The caller owns the context and guarantees that exactly one
    // mutable slice exists for this range and no skb-reallocating helper runs
    // while the slice is live.
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

fn apply_translation(
    bytes: &mut [u8],
    packet: &Packet,
    decision: &Decision,
) -> Result<(), PacketError> {
    match decision.translation {
        Translation::None => Ok(()),
        Translation::Source => {
            if packet.source.address != decision.source.address {
                rewrite_ipv4_source(bytes, decision.source.address)?;
            }
            if packet.source.port != decision.source.port {
                rewrite_transport_port(bytes, PortField::Source, decision.source.port)?;
            }
            Ok(())
        }
        Translation::Destination => {
            if packet.destination.address != decision.destination.address {
                rewrite_ipv4_destination(bytes, decision.destination.address)?;
            }
            if packet.destination.port != decision.destination.port {
                rewrite_transport_port(bytes, PortField::Destination, decision.destination.port)?;
            }
            Ok(())
        }
    }
}

fn finish(action: Action, ifindex: Option<u32>, translated: bool) -> i32 {
    maps::increment(action.counter());
    if translated {
        maps::increment(Counter::NatTranslations);
    }
    tc_action(action, ifindex)
}

fn tc_action(action: Action, ifindex: Option<u32>) -> i32 {
    match action {
        Action::Pass => TC_ACT_OK,
        Action::Drop => TC_ACT_SHOT,
        Action::Redirect => match ifindex {
            Some(ifindex) if ifindex != 0 => {
                // SAFETY: bpf_redirect consumes only the validated endpoint
                // ifindex scalar and zero flags; it dereferences no Rust pointer.
                let result = unsafe { bpf_redirect(ifindex, 0) as i32 };
                if result == TC_ACT_REDIRECT {
                    result
                } else {
                    TC_ACT_SHOT
                }
            }
            _ => TC_ACT_SHOT,
        },
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
