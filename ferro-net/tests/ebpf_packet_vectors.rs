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
        0x45, 0x00, 0x00, 0x28, 0x12, 0x34, 0x40, 0x00, 0x40, 0x06, 0x3c, 0x65, 0xc0, 0x00, 0x02,
        0x01, 0xc6, 0x33, 0x64, 0x02, // TCP: 12345 -> 8080, SYN, checksum 0x2fdc.
        0x30, 0x39, 0x1f, 0x90, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x40,
        0x00, 0x2f, 0xdc, 0x00, 0x00,
    ]
}

fn udp_packet() -> Vec<u8> {
    vec![
        // Ethernet: destination, source, EtherType IPv4.
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00,
        // IPv4: 10.1.2.3 -> 10.9.8.7, 28 bytes, UDP, checksum 0x9dce.
        0x45, 0x00, 0x00, 0x1c, 0xbe, 0xef, 0x00, 0x00, 0x40, 0x11, 0x9d, 0xce, 0x0a, 0x01, 0x02,
        0x03, 0x0a, 0x09, 0x08, 0x07,
        // UDP: 5353 -> 53, eight-byte datagram, checksum 0xccac.
        0x14, 0xe9, 0x00, 0x35, 0x00, 0x08, 0xcc, 0xac,
    ]
}

fn rfc1071_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut words = bytes.chunks_exact(2);
    for word in &mut words {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    if let Some(byte) = words.remainder().first() {
        sum += u32::from(*byte) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn reference_ipv4_checksum(packet: &[u8]) -> u16 {
    let ipv4_offset = 14;
    let ipv4_header_len = usize::from(packet[ipv4_offset] & 0x0f) * 4;
    let mut header = packet[ipv4_offset..ipv4_offset + ipv4_header_len].to_vec();
    header[10..12].copy_from_slice(&[0, 0]);
    rfc1071_checksum(&header)
}

fn reference_transport_checksum(packet: &[u8]) -> u16 {
    let ipv4_offset = 14;
    let ipv4_header_len = usize::from(packet[ipv4_offset] & 0x0f) * 4;
    let ipv4_total_len = usize::from(u16::from_be_bytes([
        packet[ipv4_offset + 2],
        packet[ipv4_offset + 3],
    ]));
    let transport_offset = ipv4_offset + ipv4_header_len;
    let transport_len = ipv4_total_len - ipv4_header_len;
    let protocol = packet[ipv4_offset + 9];
    let checksum_offset = match protocol {
        6 => 16,
        17 => 6,
        _ => panic!("reference checksum requires TCP or UDP"),
    };

    let mut covered = Vec::with_capacity(12 + transport_len);
    covered.extend_from_slice(&packet[ipv4_offset + 12..ipv4_offset + 20]);
    covered.extend_from_slice(&[0, protocol]);
    covered.extend_from_slice(&(transport_len as u16).to_be_bytes());
    covered.extend_from_slice(&packet[transport_offset..transport_offset + transport_len]);
    covered[12 + checksum_offset..14 + checksum_offset].copy_from_slice(&[0, 0]);
    rfc1071_checksum(&covered)
}

fn tcp_packet_with_odd_payload() -> Vec<u8> {
    let mut packet = tcp_packet();
    packet.extend_from_slice(&[0xde, 0xad, 0xbe]);
    packet[16..18].copy_from_slice(&43u16.to_be_bytes());
    packet[24..26].copy_from_slice(&[0, 0]);
    let ipv4_checksum = reference_ipv4_checksum(&packet);
    packet[24..26].copy_from_slice(&ipv4_checksum.to_be_bytes());
    packet[50..52].copy_from_slice(&[0, 0]);
    let transport_checksum = reference_transport_checksum(&packet);
    packet[50..52].copy_from_slice(&transport_checksum.to_be_bytes());
    packet
}

fn udp_packet_with_odd_payload() -> Vec<u8> {
    let mut packet = udp_packet();
    packet.extend_from_slice(&[0xa1, 0xb2, 0xc3]);
    packet[16..18].copy_from_slice(&31u16.to_be_bytes());
    packet[38..40].copy_from_slice(&11u16.to_be_bytes());
    packet[24..26].copy_from_slice(&[0, 0]);
    let ipv4_checksum = reference_ipv4_checksum(&packet);
    packet[24..26].copy_from_slice(&ipv4_checksum.to_be_bytes());
    packet[40..42].copy_from_slice(&[0, 0]);
    let transport_checksum = reference_transport_checksum(&packet);
    packet[40..42].copy_from_slice(&transport_checksum.to_be_bytes());
    packet
}

fn short_tcp_header_packet() -> Vec<u8> {
    let mut packet = tcp_packet();
    packet[16..18].copy_from_slice(&39u16.to_be_bytes());
    packet.truncate(14 + 39);
    packet
}

fn short_udp_header_packet() -> Vec<u8> {
    let mut packet = udp_packet();
    packet[16..18].copy_from_slice(&27u16.to_be_bytes());
    packet.truncate(14 + 27);
    packet
}

fn assert_all_rewrites_leave_packet_unchanged(input: &[u8]) {
    let original = input.to_vec();

    let mut packet = original.clone();
    assert!(rewrite_ipv4_destination(&mut packet, [203, 0, 113, 10]).is_err());
    assert_eq!(packet, original);

    let mut packet = original.clone();
    assert!(rewrite_ipv4_source(&mut packet, [192, 0, 2, 45]).is_err());
    assert_eq!(packet, original);

    let mut packet = original.clone();
    assert!(rewrite_transport_port(&mut packet, PortField::Source, 1234).is_err());
    assert_eq!(packet, original);

    let mut packet = original.clone();
    assert!(rewrite_transport_port(&mut packet, PortField::Destination, 4321).is_err());
    assert_eq!(packet, original);
}

#[test]
fn truncated_ethernet_is_rejected() {
    assert_eq!(parse_packet_bytes(&[0u8; 13]), Err(PacketError::Truncated));
}

#[test]
fn truncated_ipv4_is_rejected() {
    assert_eq!(parse_packet_bytes(&[0u8; 20]), Err(PacketError::Truncated));
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
    assert_eq!(parse_packet_bytes(&packet), Err(PacketError::Truncated));
}

#[test]
fn ipv4_more_fragments_is_rejected() {
    let mut packet = tcp_packet();
    packet[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
    assert_eq!(parse_packet_bytes(&packet), Err(PacketError::Fragmented));
}

#[test]
fn ipv4_fragment_offset_is_rejected() {
    let mut packet = tcp_packet();
    packet[20..22].copy_from_slice(&1u16.to_be_bytes());
    assert_eq!(parse_packet_bytes(&packet), Err(PacketError::Fragmented));
}

#[test]
fn truncated_tcp_header_is_rejected() {
    let packet = short_tcp_header_packet();
    assert_eq!(packet.len() - 14, 39);
    assert_eq!(u16::from_be_bytes([packet[16], packet[17]]), 39);
    assert_eq!(parse_packet_bytes(&packet), Err(PacketError::Truncated));
}

#[test]
fn truncated_udp_header_is_rejected() {
    let packet = short_udp_header_packet();
    assert_eq!(packet.len() - 14, 27);
    assert_eq!(u16::from_be_bytes([packet[16], packet[17]]), 27);
    assert_eq!(parse_packet_bytes(&packet), Err(PacketError::Truncated));
}

#[test]
fn ipv6_is_rejected_at_ethertype_in_abi_v1() {
    let mut packet = vec![0u8; 14 + 40];
    packet[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    packet[14] = 0x60;
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
fn network_backend_localhost_publish_vector_dnat_and_reverse_dnat_preserve_loopback_tuple() {
    let localhost = [127, 0, 0, 1];
    let endpoint = [10, 44, 1, 2];

    let mut request = tcp_packet();
    rewrite_ipv4_source(&mut request, localhost).unwrap();
    rewrite_ipv4_destination(&mut request, localhost).unwrap();
    rewrite_transport_port(&mut request, PortField::Source, 51_000).unwrap();
    rewrite_transport_port(&mut request, PortField::Destination, 8_080).unwrap();
    rewrite_ipv4_destination(&mut request, endpoint).unwrap();
    rewrite_transport_port(&mut request, PortField::Destination, 80).unwrap();
    assert_eq!(&request[26..30], &localhost);
    assert_eq!(&request[30..34], &endpoint);
    assert_eq!(u16::from_be_bytes([request[34], request[35]]), 51_000);
    assert_eq!(u16::from_be_bytes([request[36], request[37]]), 80);
    assert_eq!(
        u16::from_be_bytes([request[24], request[25]]),
        reference_ipv4_checksum(&request)
    );
    assert_eq!(
        u16::from_be_bytes([request[50], request[51]]),
        reference_transport_checksum(&request)
    );

    let mut response = tcp_packet();
    rewrite_ipv4_source(&mut response, endpoint).unwrap();
    rewrite_ipv4_destination(&mut response, localhost).unwrap();
    rewrite_transport_port(&mut response, PortField::Source, 80).unwrap();
    rewrite_transport_port(&mut response, PortField::Destination, 51_000).unwrap();
    rewrite_ipv4_source(&mut response, localhost).unwrap();
    rewrite_transport_port(&mut response, PortField::Source, 8_080).unwrap();
    assert_eq!(&response[26..30], &localhost);
    assert_eq!(&response[30..34], &localhost);
    assert_eq!(u16::from_be_bytes([response[34], response[35]]), 8_080);
    assert_eq!(u16::from_be_bytes([response[36], response[37]]), 51_000);
    assert_eq!(
        u16::from_be_bytes([response[24], response[25]]),
        reference_ipv4_checksum(&response)
    );
    assert_eq!(
        u16::from_be_bytes([response[50], response[51]]),
        reference_transport_checksum(&response)
    );
}

#[test]
fn ipv4_udp_zero_checksum_remains_disabled() {
    let mut packet = udp_packet();
    packet[40..42].copy_from_slice(&[0, 0]);

    rewrite_ipv4_destination(&mut packet, [10, 9, 8, 8]).expect("rewrite destination");
    rewrite_transport_port(&mut packet, PortField::Destination, 5353).expect("rewrite port");

    assert_eq!(&packet[40..42], &[0, 0]);
}

#[test]
fn odd_length_tcp_rewrites_match_independent_rfc1071_checksums() {
    let mut packet = tcp_packet_with_odd_payload();

    rewrite_ipv4_destination(&mut packet, [203, 0, 113, 9]).expect("rewrite destination");
    rewrite_transport_port(&mut packet, PortField::Destination, 8443).expect("rewrite port");

    assert_eq!(
        u16::from_be_bytes([packet[24], packet[25]]),
        reference_ipv4_checksum(&packet)
    );
    assert_eq!(
        u16::from_be_bytes([packet[50], packet[51]]),
        reference_transport_checksum(&packet)
    );
    assert_eq!(&packet[54..], &[0xde, 0xad, 0xbe]);
}

#[test]
fn odd_length_udp_rewrites_match_independent_rfc1071_checksums() {
    let mut packet = udp_packet_with_odd_payload();

    rewrite_ipv4_source(&mut packet, [192, 0, 2, 44]).expect("rewrite source");
    rewrite_transport_port(&mut packet, PortField::Source, 1053).expect("rewrite port");

    assert_eq!(
        u16::from_be_bytes([packet[24], packet[25]]),
        reference_ipv4_checksum(&packet)
    );
    assert_eq!(
        u16::from_be_bytes([packet[40], packet[41]]),
        reference_transport_checksum(&packet)
    );
    assert_eq!(&packet[42..], &[0xa1, 0xb2, 0xc3]);
}

#[test]
fn malformed_packets_are_unchanged_by_every_rewrite() {
    let mut packet = tcp_packet();
    packet[14] = 0x44;
    assert_all_rewrites_leave_packet_unchanged(&packet);
}

#[test]
fn truncated_packets_are_unchanged_by_every_rewrite() {
    assert_all_rewrites_leave_packet_unchanged(&short_tcp_header_packet());
    assert_all_rewrites_leave_packet_unchanged(&short_udp_header_packet());
}

#[test]
fn fragmented_packets_are_unchanged_by_every_rewrite() {
    let mut more_fragments = tcp_packet();
    more_fragments[20..22].copy_from_slice(&0x2000u16.to_be_bytes());
    assert_all_rewrites_leave_packet_unchanged(&more_fragments);

    let mut fragment_offset = udp_packet();
    fragment_offset[20..22].copy_from_slice(&1u16.to_be_bytes());
    assert_all_rewrites_leave_packet_unchanged(&fragment_offset);
}

#[test]
fn unsupported_packets_are_unchanged_by_every_rewrite() {
    let mut ipv6 = vec![0u8; 14 + 40];
    ipv6[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
    ipv6[14] = 0x60;
    assert_all_rewrites_leave_packet_unchanged(&ipv6);

    let mut unsupported_transport = tcp_packet();
    unsupported_transport[23] = 1;
    assert_all_rewrites_leave_packet_unchanged(&unsupported_transport);
}
