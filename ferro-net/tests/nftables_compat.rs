#![cfg(target_os = "linux")]

use ferro_net::nftables::{NftRule, build_nft_add_rule_cmd};

#[test]
fn nftables_rule_builder_compat() {
    let rule = NftRule {
        family: "ip".to_string(),
        table: "nat".to_string(),
        chain: "prerouting".to_string(),
        expr: vec!["tcp".to_string(), "dport".to_string(), "443".to_string(), "dnat".to_string(), "to".to_string(), "10.0.0.3:443".to_string()],
    };
    let cmd = build_nft_add_rule_cmd(&rule).expect("build nftables command");
    assert_eq!(
        cmd,
        vec![
            "nft", "add", "rule", "ip", "nat", "prerouting", "tcp", "dport", "443", "dnat", "to", "10.0.0.3:443"
        ]
    );
}
