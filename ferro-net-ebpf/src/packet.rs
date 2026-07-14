const ETHERNET_HEADER_LEN: usize = 14;
const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const ETHERTYPE_IPV4: u16 = 0x0800;
const IP_PROTOCOL_TCP: u8 = 6;
const IP_PROTOCOL_UDP: u8 = 17;

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

fn parse_with<F>(packet_len: usize, mut read_byte: F) -> Result<PacketView, PacketError>
where
    F: FnMut(usize) -> Result<u8, PacketError>,
{
    require_bytes(packet_len, 0, ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)?;

    if read_be_u16(&mut read_byte, 12)? != ETHERTYPE_IPV4 {
        return Err(PacketError::UnsupportedNetwork);
    }

    let version_ihl = read_byte(ETHERNET_HEADER_LEN)?;
    if version_ihl >> 4 != 4 {
        return Err(PacketError::InvalidIpv4Header);
    }
    let ipv4_header_len = usize::from(version_ihl & 0x0f) * 4;
    if ipv4_header_len < IPV4_HEADER_LEN {
        return Err(PacketError::InvalidIpv4Header);
    }
    require_bytes(packet_len, ETHERNET_HEADER_LEN, ipv4_header_len)?;

    let total_len = usize::from(read_be_u16(
        &mut read_byte,
        ETHERNET_HEADER_LEN + 2,
    )?);
    if total_len < ipv4_header_len {
        return Err(PacketError::InvalidIpv4Header);
    }
    let packet_end = checked_end(ETHERNET_HEADER_LEN, total_len)?;
    require_bytes(packet_len, ETHERNET_HEADER_LEN, total_len)?;

    let fragments = read_be_u16(&mut read_byte, ETHERNET_HEADER_LEN + 6)?;
    if fragments & 0x3fff != 0 {
        return Err(PacketError::Fragmented);
    }

    let transport_offset = checked_end(ETHERNET_HEADER_LEN, ipv4_header_len)?;
    let transport = match read_byte(ETHERNET_HEADER_LEN + 9)? {
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
        ipv4_offset: ETHERNET_HEADER_LEN,
        ipv4_header_len,
        transport_offset,
        transport,
        packet_end,
    })
}

pub fn parse_packet_bytes(packet: &[u8]) -> Result<PacketView, PacketError> {
    parse_with(packet.len(), |offset| {
        packet.get(offset).copied().ok_or(PacketError::Truncated)
    })
}

#[allow(dead_code)]
pub fn rewrite_ethernet_destination(
    packet: &mut [u8],
    destination_mac: [u8; 6],
) -> Result<(), PacketError> {
    parse_packet_bytes(packet)?;
    let destination = packet.get_mut(..6).ok_or(PacketError::Truncated)?;
    destination.copy_from_slice(&destination_mac);
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

fn read_slice_u16(packet: &[u8], offset: usize) -> Result<u16, PacketError> {
    let bytes = packet
        .get(offset..checked_end(offset, 2)?)
        .ok_or(PacketError::Truncated)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn write_slice_u16(packet: &mut [u8], offset: usize, value: u16) -> Result<(), PacketError> {
    let end = checked_end(offset, 2)?;
    let bytes = packet
        .get_mut(offset..end)
        .ok_or(PacketError::Truncated)?;
    bytes.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

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
    let new_ipv4_checksum =
        update_ipv4_checksum(old_ipv4_checksum, old_address, new_address);

    let transport_checksum_offset = transport_checksum_offset(view);
    let old_transport_checksum = read_slice_u16(packet, transport_checksum_offset)?;
    let new_transport_checksum = if view.transport == TransportProtocol::Udp
        && old_transport_checksum == 0
    {
        0
    } else {
        normalize_udp_checksum(
            view.transport,
            update_transport_checksum(old_transport_checksum, old_address, new_address),
        )
    };

    packet[address_offset..address_end].copy_from_slice(&new_address);
    write_slice_u16(packet, ipv4_checksum_offset, new_ipv4_checksum)?;
    write_slice_u16(
        packet,
        transport_checksum_offset,
        new_transport_checksum,
    )
}

pub fn rewrite_ipv4_destination(
    packet: &mut [u8],
    new_address: [u8; 4],
) -> Result<(), PacketError> {
    rewrite_ipv4_address(packet, 16, new_address)
}

pub fn rewrite_ipv4_source(
    packet: &mut [u8],
    new_address: [u8; 4],
) -> Result<(), PacketError> {
    rewrite_ipv4_address(packet, 12, new_address)
}

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
    use super::{parse_with, PacketError, PacketView};
    use aya_ebpf::programs::TcContext;
    use core::{mem, ptr};
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
        // SAFETY: header_at proves `data + offset + size_of::<u8>() <= data_end`
        // with checked arithmetic before producing the packet pointer.
        let byte = unsafe { header_at::<u8>(ctx, offset)? };
        // SAFETY: the typed u8 bounds proof above covers the complete read and u8
        // has alignment one; read_unaligned also avoids stronger alignment assumptions.
        Ok(unsafe { ptr::read_unaligned(byte) })
    }

    impl PacketView {
        pub fn parse(ctx: &TcContext) -> Result<Self, PacketError> {
            let packet_len = ctx
                .data_end()
                .checked_sub(ctx.data())
                .ok_or(PacketError::Truncated)?;

            // SAFETY: header_at proves the complete network-types Ethernet layout is
            // within the verifier-provided packet bounds before returning its pointer.
            unsafe { header_at::<EthHdr>(ctx, 0)? };
            let view = parse_with(packet_len, |offset| byte_at(ctx, offset))?;
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
}
