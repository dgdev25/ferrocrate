#[path = "../../ferro-net-ebpf/src/packet.rs"]
mod packet;

use packet::{
    parse_packet_bytes, rewrite_ipv4_destination, rewrite_ipv4_source, rewrite_transport_port,
    PacketError, PortField, TransportProtocol,
};

fn tcp_packet() -> Vec<u8> {
    vec![
        // Ethernet: destination, source, EtherType IPv4.
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
        // IPv4: 192.0.2.1 -> 198.51.100.2, 40 bytes, TCP, checksum 0x3c65.
        0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x3c, 0x65, 0xc0, 0x00,
        0x02, 0x01, 0xc6, 0x33, 0x64, 0x02,
        // TCP: 12345 -> 8080, SYN, checksum 0x2fdc.
        0x30, 0x39, 0x1f, 0x90, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
        0x40, 0x00, 0x2f, 0xdc, 0x00, 0x00,
    ]
}

fn udp_packet() -> Vec<u8> {
    vec![
        // Ethernet: destination, source, EtherType IPv4.
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
        // IPv4: 10.1.2.3 -> 10.9.8.7, 28 bytes, UDP, checksum 0x9dce.
        0x45, 0x00, 0x00, 0x1c, 0xbe, 0xef, 0x00, 0x00, 0x40, 0x11, 0x9d, 0xce, 0x0a, 0x01,
        0x02, 0x03, 0x0a, 0x09, 0x08, 0x07,
        // UDP: 5353 -> 53, eight-byte datagram, checksum 0xccac.
        0x14, 0xe9, 0x00, 0x35, 0x00, 0x08, 0xcc, 0xac,
    ]
}

#[test]
fn truncated_ethernet_is_rejected() {
    assert_eq!(
        parse_packet_bytes(&[0u8; 13]),
        Err(PacketError::Truncated)
    );
}

#[test]
fn truncated_ipv4_is_rejected() {
    assert_eq!(
        parse_packet_bytes(&[0u8; 20]),
        Err(PacketError::Truncated)
    );
}

#[test]
fn invalid_ihl_is_rejected() {
    let mut packet = tcp_packet();
    packet[14] = 0x44;
    assert_eq!(
        parse_packet_bytes(&packet),
        Err(PacketError::InvalidIpv4Header)
    );
}

#[test]
fn overflowing_ipv4_options_are_rejected() {
    let mut packet = tcp_packet();
    packet[14] = 0x4f;
    assert_eq!(
        parse_packet_bytes(&packet),
        Err(PacketError::Truncated)
    );
}

#[test]
fn ipv4_more_fragments_is_rejected() {
    let mut packet = tcp_packet();
    packet[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
    assert_eq!(
        parse_packet_bytes(&packet),
        Err(PacketError::Fragmented)
    );
}

#[test]
fn ipv4_fragment_offset_is_rejected() {
    let mut packet = tcp_packet();
    packet[20..22].copy_from_slice(&1u16.to_be_bytes());
    assert_eq!(
        parse_packet_bytes(&packet),
        Err(PacketError::Fragmented)
    );
}

#[test]
fn truncated_tcp_header_is_rejected() {
    let mut packet = tcp_packet();
    packet.truncate(packet.len() - 1);
    assert_eq!(
        parse_packet_bytes(&packet),
        Err(PacketError::Truncated)
    );
}

#[test]
fn truncated_udp_header_is_rejected() {
    let mut packet = udp_packet();
    packet.truncate(packet.len() - 1);
    assert_eq!(
        parse_packet_bytes(&packet),
        Err(PacketError::Truncated)
    );
}

#[test]
fn ipv6_extension_chain_is_rejected_in_abi_v1() {
    let mut packet = vec![0u8; 14 + 40 + 8];
    packet[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    packet[14] = 0x60;
    packet[20] = 0;
    assert_eq!(
        parse_packet_bytes(&packet),
        Err(PacketError::UnsupportedNetwork)
    );
}

#[test]
fn tcp_destination_rewrites_use_rfc1071_checksums() {
    let mut packet = tcp_packet();
    let view = parse_packet_bytes(&packet).expect("valid TCP vector");
    assert_eq!(view.transport, TransportProtocol::Tcp);

    rewrite_ipv4_destination(&mut packet, [203, 0, 113, 9]).expect("rewrite destination");
    assert_eq!(&packet[30..34], &[203, 0, 113, 9]);
    assert_eq!(&packet[24..26], &[0x2a, 0x91]);
    assert_eq!(&packet[50..52], &[0x1e, 0x08]);

    rewrite_transport_port(&mut packet, PortField::Destination, 8443).expect("rewrite port");
    assert_eq!(&packet[36..38], &[0x20, 0xfb]);
    assert_eq!(&packet[50..52], &[0x1c, 0x9d]);
}

#[test]
fn udp_source_rewrites_use_rfc1071_checksums() {
    let mut packet = udp_packet();
    let view = parse_packet_bytes(&packet).expect("valid UDP vector");
    assert_eq!(view.transport, TransportProtocol::Udp);

    rewrite_ipv4_source(&mut packet, [192, 0, 2, 44]).expect("rewrite source");
    assert_eq!(&packet[26..30], &[192, 0, 2, 44]);
    assert_eq!(&packet[24..26], &[0xe7, 0xa5]);
    assert_eq!(&packet[40..42], &[0x16, 0x84]);

    rewrite_transport_port(&mut packet, PortField::Source, 1053).expect("rewrite port");
    assert_eq!(&packet[34..36], &[0x04, 0x1d]);
    assert_eq!(&packet[40..42], &[0x27, 0x50]);
}

#[test]
fn ipv4_udp_zero_checksum_remains_disabled() {
    let mut packet = udp_packet();
    packet[40..42].copy_from_slice(&[0, 0]);

    rewrite_ipv4_destination(&mut packet, [10, 9, 8, 8]).expect("rewrite destination");
    rewrite_transport_port(&mut packet, PortField::Destination, 5353).expect("rewrite port");

    assert_eq!(&packet[40..42], &[0, 0]);
}
