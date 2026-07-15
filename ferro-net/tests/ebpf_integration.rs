#![cfg(target_os = "linux")]

use std::{env, net::Ipv4Addr, path::Path};

use ferro_net::ebpf::{
    embedded_object_abi, embedded_object_sha256, EbpfNetwork, EbpfNetworkConfig,
};
use ferro_net::ebpf_abi::PROGRAM_ABI_VERSION;

fn config() -> EbpfNetworkConfig {
    EbpfNetworkConfig {
        network_id: "test-network".to_string(),
        interface: "eth-test0".to_string(),
        external_ipv4: [203, 0, 113, 8],
        external_ifindex: 17,
        loopback_ifindex: 1,
        next_hop_mac: [2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee],
        snat_port_start: 50_000,
        snat_port_end: 50_031,
        expected_object_sha256: embedded_object_sha256(),
    }
}

#[test]
fn network_pin_path_is_the_exact_owned_ferrocrate_path() {
    assert_eq!(
        config().pin_path().unwrap(),
        Path::new("/sys/fs/bpf/ferrocrate/test-network")
    );
}

#[test]
fn embedded_elf_exposes_the_expected_program_abi_and_hash() {
    assert_eq!(embedded_object_abi().unwrap(), PROGRAM_ABI_VERSION);
    assert_ne!(embedded_object_sha256(), [0; 32]);
}

#[test]
#[ignore = "Task 7 qualification: requires explicit root/capability, bpffs, tc, interface, and reserved-port setup"]
fn privileged_aya_load_detach_smoke_deferred_to_task_7() {
    let interface = env::var("FERRO_EBPF_TEST_INTERFACE").expect("test interface");
    let external_ifindex = env::var("FERRO_EBPF_TEST_IFINDEX")
        .expect("test ifindex")
        .parse()
        .expect("numeric test ifindex");
    let external_ipv4 = env::var("FERRO_EBPF_TEST_EXTERNAL_IPV4")
        .expect("test external IPv4")
        .parse::<Ipv4Addr>()
        .expect("valid test external IPv4")
        .octets();
    let next_hop_mac =
        parse_mac(&env::var("FERRO_EBPF_TEST_NEXT_HOP_MAC").expect("test next-hop MAC"));
    let snat_port_start = env::var("FERRO_EBPF_TEST_SNAT_START")
        .expect("test SNAT start")
        .parse()
        .expect("numeric test SNAT start");
    let snat_port_end = env::var("FERRO_EBPF_TEST_SNAT_END")
        .expect("test SNAT end")
        .parse()
        .expect("numeric test SNAT end");
    let mut network = EbpfNetwork::load(EbpfNetworkConfig {
        network_id: env::var("FERRO_EBPF_TEST_NETWORK_ID")
            .unwrap_or_else(|_| format!("loader-smoke-{}", std::process::id())),
        interface,
        external_ipv4,
        external_ifindex,
        loopback_ifindex: 1,
        next_hop_mac,
        snat_port_start,
        snat_port_end,
        expected_object_sha256: embedded_object_sha256(),
    })
    .expect("real Aya loader path");

    network.detach().expect("real detach");
    network.detach().expect("idempotent real detach");
}

fn parse_mac(value: &str) -> [u8; 6] {
    let bytes = value
        .split(':')
        .map(|byte| u8::from_str_radix(byte, 16).expect("hex MAC byte"))
        .collect::<Vec<_>>();
    bytes.try_into().expect("six-byte MAC")
}
