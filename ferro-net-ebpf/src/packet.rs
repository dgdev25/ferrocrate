const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const ETHERTYPE_IPV4: u16 = 0x0800;
const IP_PROTOCOL_TCP: u8 = 6;
const IP_PROTOCOL_UDP: u8 = 17;
// `bpf_skb_store_bytes` accepts BPF_F_RECOMPUTE_CSUM for mutations that may
// invalidate skb checksum/offload metadata.  Redirected veth packets can
// carry CHECKSUM_PARTIAL state into loopback, where no NIC completes it.
#[allow(dead_code)]
const BPF_F_RECOMPUTE_CSUM: u64 = 1;
// Loopback-originated packets have no real Ethernet source address. A
// redirect from loopback to a bridge/veth must synthesize a stable local
// unicast source or the bridge rejects the frame before it reaches the
// container endpoint.
#[allow(dead_code)]
pub const SYNTHETIC_REDIRECT_SOURCE_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketError {
    Truncated,
    UnsupportedNetwork,
    UnsupportedTransport,
    InvalidIpv4Header,
    InvalidTransportHeader,
    Fragmented,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

#[cfg(not(target_arch = "bpf"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PortField {
    Source,
    Destination,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PacketView {
    pub ipv4_offset: usize,
    pub ipv4_header_len: usize,
    pub transport_offset: usize,
    pub transport: TransportProtocol,
    pub packet_end: usize,
}

fn checked_end(offset: usize, size: usize) -> Result<usize, PacketError> {
    offset.checked_add(size).ok_or(PacketError::Truncated)
}

fn require_bytes(packet_len: usize, offset: usize, size: usize) -> Result<(), PacketError> {
    if checked_end(offset, size)? <= packet_len {
        Ok(())
    } else {
        Err(PacketError::Truncated)
    }
}

fn read_be_u16<F>(read_byte: &mut F, offset: usize) -> Result<u16, PacketError>
where
    F: FnMut(usize) -> Result<u8, PacketError>,
{
    let high = read_byte(offset)?;
    let low = read_byte(checked_end(offset, 1)?)?;
    Ok(u16::from_be_bytes([high, low]))
}

#[cfg(not(target_arch = "bpf"))]
fn parse_with<F>(packet_len: usize, read_byte: F) -> Result<PacketView, PacketError>
where
    F: FnMut(usize) -> Result<u8, PacketError>,
{
    parse_with_link(packet_len, ETHERNET_HEADER_LEN, true, read_byte)
}

fn parse_with_link<F>(
    packet_len: usize,
    ipv4_offset: usize,
    ethernet: bool,
    mut read_byte: F,
) -> Result<PacketView, PacketError>
where
    F: FnMut(usize) -> Result<u8, PacketError>,
{
    if ethernet {
        // Classify a short Ethernet frame as truncated before inspecting its
        // type. This keeps malformed partial IPv4 frames fail-closed and
        // deterministic instead of reporting an unrelated network type.
        require_bytes(packet_len, 0, ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)?;
        if read_be_u16(&mut read_byte, ipv4_offset - 2)? != ETHERTYPE_IPV4 {
            return Err(PacketError::UnsupportedNetwork);
        }
    }
    require_bytes(packet_len, ipv4_offset, IPV4_HEADER_LEN)?;

    let version_ihl = read_byte(ipv4_offset)?;
    if version_ihl >> 4 != 4 {
        return Err(PacketError::InvalidIpv4Header);
    }
    let ipv4_header_len = usize::from(version_ihl & 0x0f) * 4;
    if ipv4_header_len < IPV4_HEADER_LEN {
        return Err(PacketError::InvalidIpv4Header);
    }
    require_bytes(packet_len, ipv4_offset, ipv4_header_len)?;

    let total_len = usize::from(read_be_u16(&mut read_byte, ipv4_offset + 2)?);
    if total_len < ipv4_header_len {
        return Err(PacketError::InvalidIpv4Header);
    }
    let packet_end = checked_end(ipv4_offset, total_len)?;
    require_bytes(packet_len, ipv4_offset, total_len)?;

    let fragments = read_be_u16(&mut read_byte, ipv4_offset + 6)?;
    if fragments & 0x3fff != 0 {
        return Err(PacketError::Fragmented);
    }

    let transport_offset = checked_end(ipv4_offset, ipv4_header_len)?;
    let transport = match read_byte(ipv4_offset + 9)? {
        IP_PROTOCOL_TCP => {
            require_bytes(packet_end, transport_offset, TCP_HEADER_LEN)?;
            let data_offset = usize::from(read_byte(transport_offset + 12)? >> 4) * 4;
            if data_offset < TCP_HEADER_LEN {
                return Err(PacketError::InvalidTransportHeader);
            }
            require_bytes(packet_end, transport_offset, data_offset)?;
            TransportProtocol::Tcp
        }
        IP_PROTOCOL_UDP => {
            require_bytes(packet_end, transport_offset, UDP_HEADER_LEN)?;
            let udp_len = usize::from(read_be_u16(&mut read_byte, transport_offset + 4)?);
            if udp_len < UDP_HEADER_LEN {
                return Err(PacketError::InvalidTransportHeader);
            }
            require_bytes(packet_end, transport_offset, udp_len)?;
            TransportProtocol::Udp
        }
        _ => return Err(PacketError::UnsupportedTransport),
    };

    Ok(PacketView {
        ipv4_offset,
        ipv4_header_len,
        transport_offset,
        transport,
        packet_end,
    })
}

#[cfg(not(target_arch = "bpf"))]
pub fn parse_packet_bytes(packet: &[u8]) -> Result<PacketView, PacketError> {
    parse_with(packet.len(), |offset| {
        packet.get(offset).copied().ok_or(PacketError::Truncated)
    })
}

#[allow(dead_code)]
#[cfg(not(target_arch = "bpf"))]
pub fn rewrite_ethernet_destination(
    packet: &mut [u8],
    destination_mac: [u8; 6],
) -> Result<(), PacketError> {
    parse_packet_bytes(packet)?;
    let destination = packet.get_mut(..6).ok_or(PacketError::Truncated)?;
    destination.copy_from_slice(&destination_mac);
    Ok(())
}

#[allow(dead_code)]
#[cfg(not(target_arch = "bpf"))]
pub fn rewrite_ethernet_source(packet: &mut [u8], source_mac: [u8; 6]) -> Result<(), PacketError> {
    parse_packet_bytes(packet)?;
    let source = packet.get_mut(6..12).ok_or(PacketError::Truncated)?;
    source.copy_from_slice(&source_mac);
    Ok(())
}

fn update_checksum_word(checksum: u16, old: u16, new: u16) -> u16 {
    let sum = u32::from(!checksum) + u32::from(!old) + u32::from(new);
    let sum = (sum & 0xffff) + (sum >> 16);
    let sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

pub fn update_ipv4_checksum(checksum: u16, old: [u8; 4], new: [u8; 4]) -> u16 {
    let checksum = update_checksum_word(
        checksum,
        u16::from_be_bytes([old[0], old[1]]),
        u16::from_be_bytes([new[0], new[1]]),
    );
    update_checksum_word(
        checksum,
        u16::from_be_bytes([old[2], old[3]]),
        u16::from_be_bytes([new[2], new[3]]),
    )
}

pub fn update_transport_checksum(checksum: u16, old: [u8; 4], new: [u8; 4]) -> u16 {
    update_ipv4_checksum(checksum, old, new)
}

#[cfg(not(target_arch = "bpf"))]
fn read_slice_u16(packet: &[u8], offset: usize) -> Result<u16, PacketError> {
    let bytes = packet
        .get(offset..checked_end(offset, 2)?)
        .ok_or(PacketError::Truncated)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

#[cfg(not(target_arch = "bpf"))]
fn write_slice_u16(packet: &mut [u8], offset: usize, value: u16) -> Result<(), PacketError> {
    let end = checked_end(offset, 2)?;
    let bytes = packet.get_mut(offset..end).ok_or(PacketError::Truncated)?;
    bytes.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

#[cfg(not(target_arch = "bpf"))]
fn transport_checksum_offset(view: PacketView) -> usize {
    view.transport_offset
        + match view.transport {
            TransportProtocol::Tcp => 16,
            TransportProtocol::Udp => 6,
        }
}

fn normalize_udp_checksum(protocol: TransportProtocol, checksum: u16) -> u16 {
    if protocol == TransportProtocol::Udp && checksum == 0 {
        u16::MAX
    } else {
        checksum
    }
}

#[cfg(not(target_arch = "bpf"))]
fn rewrite_ipv4_address(
    packet: &mut [u8],
    address_offset: usize,
    new_address: [u8; 4],
) -> Result<(), PacketError> {
    let view = parse_packet_bytes(packet)?;
    let address_offset = checked_end(view.ipv4_offset, address_offset)?;
    let address_end = checked_end(address_offset, 4)?;
    let old_bytes = packet
        .get(address_offset..address_end)
        .ok_or(PacketError::Truncated)?;
    let old_address = [old_bytes[0], old_bytes[1], old_bytes[2], old_bytes[3]];

    let ipv4_checksum_offset = view.ipv4_offset + 10;
    let old_ipv4_checksum = read_slice_u16(packet, ipv4_checksum_offset)?;
    let new_ipv4_checksum = update_ipv4_checksum(old_ipv4_checksum, old_address, new_address);

    let transport_checksum_offset = transport_checksum_offset(view);
    let old_transport_checksum = read_slice_u16(packet, transport_checksum_offset)?;
    let new_transport_checksum =
        if view.transport == TransportProtocol::Udp && old_transport_checksum == 0 {
            0
        } else {
            normalize_udp_checksum(
                view.transport,
                update_transport_checksum(old_transport_checksum, old_address, new_address),
            )
        };

    packet[address_offset..address_end].copy_from_slice(&new_address);
    write_slice_u16(packet, ipv4_checksum_offset, new_ipv4_checksum)?;
    write_slice_u16(packet, transport_checksum_offset, new_transport_checksum)
}

#[cfg(not(target_arch = "bpf"))]
pub fn rewrite_ipv4_destination(
    packet: &mut [u8],
    new_address: [u8; 4],
) -> Result<(), PacketError> {
    rewrite_ipv4_address(packet, 16, new_address)
}

#[cfg(not(target_arch = "bpf"))]
pub fn rewrite_ipv4_source(packet: &mut [u8], new_address: [u8; 4]) -> Result<(), PacketError> {
    rewrite_ipv4_address(packet, 12, new_address)
}

#[cfg(not(target_arch = "bpf"))]
pub fn rewrite_transport_port(
    packet: &mut [u8],
    field: PortField,
    new_port: u16,
) -> Result<(), PacketError> {
    let view = parse_packet_bytes(packet)?;
    let port_offset = view.transport_offset
        + match field {
            PortField::Source => 0,
            PortField::Destination => 2,
        };
    let old_port = read_slice_u16(packet, port_offset)?;
    let checksum_offset = transport_checksum_offset(view);
    let old_checksum = read_slice_u16(packet, checksum_offset)?;
    let new_checksum = if view.transport == TransportProtocol::Udp && old_checksum == 0 {
        0
    } else {
        normalize_udp_checksum(
            view.transport,
            update_checksum_word(old_checksum, old_port, new_port),
        )
    };

    write_slice_u16(packet, port_offset, new_port)?;
    write_slice_u16(packet, checksum_offset, new_checksum)
}

#[cfg(target_arch = "bpf")]
mod tc {
    use super::{
        parse_with_link, PacketError, PacketView, ETHERTYPE_IPV4, SYNTHETIC_REDIRECT_SOURCE_MAC,
    };
    use crate::datapath::{Decision, Packet, Translation};
    use aya_ebpf::programs::TcContext;
    use core::mem;
    use network_types::{eth::EthHdr, ip::Ipv4Hdr, tcp::TcpHdr, udp::UdpHdr};

    unsafe fn header_at<T>(ctx: &TcContext, offset: usize) -> Result<*mut T, PacketError> {
        let start = ctx.data();
        let end = ctx.data_end();
        let size = mem::size_of::<T>();
        let header_end = start
            .checked_add(offset)
            .and_then(|address| address.checked_add(size))
            .filter(|address| *address <= end)
            .ok_or(PacketError::Truncated)?;
        let _typed_bounds_proof = header_end;
        Ok((start + offset) as *mut T)
    }

    fn byte_at(ctx: &TcContext, offset: usize) -> Result<u8, PacketError> {
        ctx.load::<u8>(offset).map_err(|_| PacketError::Truncated)
    }

    impl PacketView {
        pub fn parse(ctx: &TcContext) -> Result<Self, PacketError> {
            let packet_len = ctx
                .data_end()
                .checked_sub(ctx.data())
                .ok_or(PacketError::Truncated)?;

            let ethernet = ctx.load::<u8>(12).ok() == Some((ETHERTYPE_IPV4 >> 8) as u8)
                && ctx.load::<u8>(13).ok() == Some(ETHERTYPE_IPV4 as u8);
            let ipv4_offset = if ethernet { 14 } else { 0 };
            if ethernet {
                // SAFETY: header_at proves the complete network-types Ethernet layout is
                // within the verifier-provided packet bounds before returning its pointer.
                unsafe { header_at::<EthHdr>(ctx, 0)? };
            }
            let view = parse_with_link(packet_len, ipv4_offset, ethernet, |offset| {
                byte_at(ctx, offset)
            })?;
            // SAFETY: parse_with checked the dynamic IPv4 offset and header length;
            // header_at additionally proves the fixed network-types layout is in bounds.
            unsafe { header_at::<Ipv4Hdr>(ctx, view.ipv4_offset)? };
            match view.transport {
                super::TransportProtocol::Tcp => {
                    // SAFETY: parse_with accepted TCP only after proving its minimum
                    // header lies before packet_end; header_at repeats that typed proof.
                    unsafe { header_at::<TcpHdr>(ctx, view.transport_offset)? };
                }
                super::TransportProtocol::Udp => {
                    // SAFETY: parse_with accepted UDP only after proving its complete
                    // fixed header lies before packet_end; header_at repeats that proof.
                    unsafe { header_at::<UdpHdr>(ctx, view.transport_offset)? };
                }
            }
            Ok(view)
        }
    }

    pub fn apply_decision_context(
        ctx: &TcContext,
        view: PacketView,
        packet: &Packet,
        decision: &Decision,
    ) -> Result<(), PacketError> {
        match decision.translation {
            Translation::None => {}
            Translation::Source => {
                if packet.source.address != decision.source.address {
                    rewrite_ipv4_address_context(
                        ctx,
                        view.ipv4_offset + 12,
                        packet.source.address,
                        decision.source.address,
                        view,
                    )?;
                }
                if packet.source.port != decision.source.port {
                    rewrite_transport_port_context(
                        ctx,
                        view,
                        packet.source.port,
                        decision.source.port,
                        false,
                    )?;
                }
            }
            Translation::Destination => {
                if packet.destination.address != decision.destination.address {
                    rewrite_ipv4_address_context(
                        ctx,
                        view.ipv4_offset + 16,
                        packet.destination.address,
                        decision.destination.address,
                        view,
                    )?;
                }
                if packet.destination.port != decision.destination.port {
                    rewrite_transport_port_context(
                        ctx,
                        view,
                        packet.destination.port,
                        decision.destination.port,
                        true,
                    )?;
                }
            }
            Translation::SourceAndDestination => {
                if packet.source.address != decision.source.address {
                    rewrite_ipv4_address_context(
                        ctx,
                        view.ipv4_offset + 12,
                        packet.source.address,
                        decision.source.address,
                        view,
                    )?;
                }
                if packet.source.port != decision.source.port {
                    rewrite_transport_port_context(
                        ctx,
                        view,
                        packet.source.port,
                        decision.source.port,
                        false,
                    )?;
                }
                if packet.destination.address != decision.destination.address {
                    rewrite_ipv4_address_context(
                        ctx,
                        view.ipv4_offset + 16,
                        packet.destination.address,
                        decision.destination.address,
                        view,
                    )?;
                }
                if packet.destination.port != decision.destination.port {
                    rewrite_transport_port_context(
                        ctx,
                        view,
                        packet.destination.port,
                        decision.destination.port,
                        true,
                    )?;
                }
            }
        }
        if view.ipv4_offset == 14 {
            if let Some(mac) = decision.destination_mac {
                for (offset, value) in [
                    (0, mac[0]),
                    (1, mac[1]),
                    (2, mac[2]),
                    (3, mac[3]),
                    (4, mac[4]),
                    (5, mac[5]),
                ] {
                    ctx.store(offset, &value, 0)
                        .map_err(|_| PacketError::Truncated)?;
                }
                let mut source_is_zero = true;
                let mut offset = 6;
                while offset < 12 {
                    if ctx.load::<u8>(offset).map_err(|_| PacketError::Truncated)? != 0 {
                        source_is_zero = false;
                    }
                    offset += 1;
                }
                if source_is_zero {
                    let mut offset = 6;
                    while offset < 12 {
                        let value = SYNTHETIC_REDIRECT_SOURCE_MAC[offset - 6];
                        ctx.store(offset, &value, 0)
                            .map_err(|_| PacketError::Truncated)?;
                        offset += 1;
                    }
                }
            }
        }
        Ok(())
    }

    fn load_byte(ctx: &TcContext, offset: usize) -> Result<u8, PacketError> {
        ctx.load::<u8>(offset).map_err(|_| PacketError::Truncated)
    }

    fn load_u16(ctx: &TcContext, offset: usize) -> Result<u16, PacketError> {
        Ok(u16::from_be_bytes([
            load_byte(ctx, offset)?,
            load_byte(ctx, offset + 1)?,
        ]))
    }

    fn store_byte(ctx: &TcContext, offset: usize, value: u8) -> Result<(), PacketError> {
        ctx.store(offset, &value, 0)
            .map_err(|_| PacketError::Truncated)
    }

    fn store_byte_recompute(ctx: &TcContext, offset: usize, value: u8) -> Result<(), PacketError> {
        ctx.store(offset, &value, super::BPF_F_RECOMPUTE_CSUM)
            .map_err(|_| PacketError::Truncated)
    }

    fn store_u16_recompute(ctx: &TcContext, offset: usize, value: u16) -> Result<(), PacketError> {
        let bytes = value.to_be_bytes();
        store_byte_recompute(ctx, offset, bytes[0])?;
        store_byte_recompute(ctx, offset + 1, bytes[1])
    }

    fn store_u16(ctx: &TcContext, offset: usize, value: u16) -> Result<(), PacketError> {
        let bytes = value.to_be_bytes();
        store_byte(ctx, offset, bytes[0])?;
        store_byte(ctx, offset + 1, bytes[1])
    }

    fn transport_offsets(view: PacketView, destination: bool) -> Option<(usize, usize)> {
        let port_delta = if destination { 2 } else { 0 };
        let checksum_delta = match view.transport {
            super::TransportProtocol::Tcp => 16,
            super::TransportProtocol::Udp => 6,
        };
        match view.transport_offset {
            20 => Some((20 + port_delta, 20 + checksum_delta)),
            24 => Some((24 + port_delta, 24 + checksum_delta)),
            28 => Some((28 + port_delta, 28 + checksum_delta)),
            32 => Some((32 + port_delta, 32 + checksum_delta)),
            36 => Some((36 + port_delta, 36 + checksum_delta)),
            40 => Some((40 + port_delta, 40 + checksum_delta)),
            44 => Some((44 + port_delta, 44 + checksum_delta)),
            48 => Some((48 + port_delta, 48 + checksum_delta)),
            52 => Some((52 + port_delta, 52 + checksum_delta)),
            56 => Some((56 + port_delta, 56 + checksum_delta)),
            60 => Some((60 + port_delta, 60 + checksum_delta)),
            34 => Some((34 + port_delta, 34 + checksum_delta)),
            38 => Some((38 + port_delta, 38 + checksum_delta)),
            42 => Some((42 + port_delta, 42 + checksum_delta)),
            46 => Some((46 + port_delta, 46 + checksum_delta)),
            50 => Some((50 + port_delta, 50 + checksum_delta)),
            54 => Some((54 + port_delta, 54 + checksum_delta)),
            58 => Some((58 + port_delta, 58 + checksum_delta)),
            62 => Some((62 + port_delta, 62 + checksum_delta)),
            66 => Some((66 + port_delta, 66 + checksum_delta)),
            70 => Some((70 + port_delta, 70 + checksum_delta)),
            74 => Some((74 + port_delta, 74 + checksum_delta)),
            _ => None,
        }
    }

    fn rewrite_ipv4_address_context(
        ctx: &TcContext,
        address_offset: usize,
        old_address: [u8; 4],
        new_address: [u8; 4],
        view: PacketView,
    ) -> Result<(), PacketError> {
        let (_, transport_checksum_offset) =
            transport_offsets(view, false).ok_or(PacketError::Truncated)?;
        let old_checksum = load_u16(ctx, view.ipv4_offset + 10)?;
        let new_checksum = super::update_ipv4_checksum(old_checksum, old_address, new_address);
        let old_transport_checksum = load_u16(ctx, transport_checksum_offset)?;
        let new_transport_checksum = if view.transport == super::TransportProtocol::Udp
            && old_transport_checksum == 0
        {
            0
        } else {
            super::normalize_udp_checksum(
                view.transport,
                super::update_transport_checksum(old_transport_checksum, old_address, new_address),
            )
        };
        store_byte_recompute(ctx, address_offset, new_address[0])?;
        store_byte_recompute(ctx, address_offset + 1, new_address[1])?;
        store_byte_recompute(ctx, address_offset + 2, new_address[2])?;
        store_byte_recompute(ctx, address_offset + 3, new_address[3])?;
        store_u16(ctx, view.ipv4_offset + 10, new_checksum)?;
        store_u16(ctx, transport_checksum_offset, new_transport_checksum)
    }

    fn rewrite_transport_port_context(
        ctx: &TcContext,
        view: PacketView,
        old_port: u16,
        new_port: u16,
        destination: bool,
    ) -> Result<(), PacketError> {
        let (port_offset, checksum_offset) =
            transport_offsets(view, destination).ok_or(PacketError::Truncated)?;
        let old_checksum = load_u16(ctx, checksum_offset)?;
        let new_checksum = if view.transport == super::TransportProtocol::Udp && old_checksum == 0 {
            0
        } else {
            super::normalize_udp_checksum(
                view.transport,
                super::update_checksum_word(old_checksum, old_port, new_port),
            )
        };
        store_u16_recompute(ctx, port_offset, new_port)?;
        store_u16(ctx, checksum_offset, new_checksum)
    }
}

#[cfg(target_arch = "bpf")]
pub use tc::apply_decision_context;
