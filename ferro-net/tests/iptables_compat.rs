use ferro_net::iptables::{IptablesRule, build_iptables_cmd};

#[test]
fn iptables_rule_builder_compat() {
    let rule = IptablesRule {
        table: "nat".to_string(),
        chain: "PREROUTING".to_string(),
        args: vec!["-p".to_string(), "tcp".to_string(), "--dport".to_string(), "443".to_string()],
    };
    let cmd = build_iptables_cmd(&rule);
    assert_eq!(cmd, vec!["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "443"]);
}
