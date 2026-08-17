use crate::backend::NetworkBackend;
use crate::validate::{
    validate_cidr, validate_interface_name, validate_ip, validate_port, validate_protocol,
    ValidationError,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMapping {
    pub host_port: u16,
    pub container_port: u16,
    pub protocol: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPlan {
    commands: Vec<Vec<String>>,
    cleanup_commands: Vec<Vec<String>>,
    firewall_id: Option<String>,
}

impl NetworkPlan {
    pub fn commands(&self) -> &[Vec<String>] {
        &self.commands
    }

    pub fn cleanup_commands(&self) -> &[Vec<String>] {
        &self.cleanup_commands
    }

    pub fn firewall_id(&self) -> Option<&str> {
        self.firewall_id.as_deref()
    }

    pub fn ownership_marker(&self) -> Option<String> {
        self.firewall_id
            .as_ref()
            .map(|firewall_id| format!("ferrocrate:{}", firewall_id.to_ascii_lowercase()))
    }

    pub fn expected_owned_state(&self) -> String {
        self.commands
            .iter()
            .map(|command| command.join(" "))
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn rollback_commands_for(&self, setup_index: usize) -> Vec<Vec<String>> {
        let Some(command) = self.commands.get(setup_index) else {
            return Vec::new();
        };
        match command.first().map(String::as_str) {
            Some("iptables") => {
                let mut rollback = command.clone();
                match rollback.get(3).map(String::as_str) {
                    Some("-N") => rollback[3] = "-X".to_string(),
                    Some("-A" | "-I") => rollback[3] = "-D".to_string(),
                    _ => return Vec::new(),
                }
                vec![rollback]
            }
            Some("nft")
                if command.get(1).map(String::as_str) == Some("add")
                    && command.get(2).map(String::as_str) == Some("table") =>
            {
                vec![vec![
                    "nft".to_string(),
                    "delete".to_string(),
                    "table".to_string(),
                    command.get(3).cloned().unwrap_or_default(),
                    command.get(4).cloned().unwrap_or_default(),
                ]]
            }
            _ => Vec::new(),
        }
    }
}

pub fn build_network_plan(
    backend: NetworkBackend,
    owner_id: &str,
    mappings: &[PortMapping],
    container_ip: &str,
    source_cidr: &str,
    bridge: &str,
) -> Result<NetworkPlan, ValidationError> {
    validate_ip(container_ip)?;
    validate_cidr(source_cidr)?;
    validate_interface_name(bridge)?;
    for mapping in mappings {
        validate_port(mapping.host_port)?;
        validate_port(mapping.container_port)?;
        validate_protocol(&mapping.protocol)?;
    }

    match backend {
        NetworkBackend::Ebpf => Ok(NetworkPlan {
            commands: Vec::new(),
            cleanup_commands: Vec::new(),
            firewall_id: None,
        }),
        NetworkBackend::Iptables => Ok(build_owned_iptables_plan(
            owner_id,
            mappings,
            container_ip,
            source_cidr,
            bridge,
        )),
        NetworkBackend::Nftables => Ok(build_owned_nftables_plan(
            owner_id,
            mappings,
            container_ip,
            source_cidr,
            bridge,
        )),
    }
}

pub fn firewall_owner_token(owner_id: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in owner_id.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn iptables_cmd(table: &str, action: &str, chain: &str, args: &[&str]) -> Vec<String> {
    let mut command = vec![
        "iptables".to_string(),
        "-t".to_string(),
        table.to_string(),
        action.to_string(),
        chain.to_string(),
    ];
    command.extend(args.iter().map(|arg| (*arg).to_string()));
    command
}

fn build_owned_iptables_plan(
    owner_id: &str,
    mappings: &[PortMapping],
    container_ip: &str,
    source_cidr: &str,
    bridge: &str,
) -> NetworkPlan {
    let token = firewall_owner_token(owner_id);
    let firewall_id = format!("fc_{token}");
    let prerouting = format!("{firewall_id}_PRE");
    let output = format!("{firewall_id}_OUT");
    let postrouting = format!("{firewall_id}_POST");
    let forward = format!("{firewall_id}_FWD");
    let comment = format!("ferrocrate:{firewall_id}");
    let chains = [
        ("nat", prerouting.as_str()),
        ("nat", output.as_str()),
        ("nat", postrouting.as_str()),
        ("filter", forward.as_str()),
    ];
    let jumps = [
        ("nat", "PREROUTING", prerouting.as_str()),
        ("nat", "OUTPUT", output.as_str()),
        ("nat", "POSTROUTING", postrouting.as_str()),
        ("filter", "FORWARD", forward.as_str()),
    ];
    let mut commands = Vec::new();
    for (table, chain) in chains {
        commands.push(iptables_cmd(table, "-N", chain, &[]));
    }
    for (table, parent, child) in jumps {
        // Insert each owned dispatch first. This prevents a stale same-port
        // NAT chain, or a host FORWARD chain installed by another runtime,
        // from shadowing the current authorized endpoint rule.
        commands.push(iptables_cmd(
            table,
            "-I",
            parent,
            &["1", "-m", "comment", "--comment", &comment, "-j", child],
        ));
    }
    commands.push(iptables_cmd(
        "nat",
        "-A",
        &postrouting,
        &["-s", source_cidr, "!", "-o", bridge, "-j", "MASQUERADE"],
    ));
    for mapping in mappings {
        let host_port = mapping.host_port.to_string();
        let container_port = mapping.container_port.to_string();
        let destination = format!("{container_ip}:{container_port}");
        for chain in [&prerouting, &output] {
            commands.push(iptables_cmd(
                "nat",
                "-A",
                chain,
                &[
                    "-p",
                    &mapping.protocol,
                    "--dport",
                    &host_port,
                    "-j",
                    "DNAT",
                    "--to-destination",
                    &destination,
                ],
            ));
        }
        commands.push(iptables_cmd(
            "filter",
            "-A",
            &forward,
            &[
                "-p",
                &mapping.protocol,
                "-d",
                container_ip,
                "--dport",
                &container_port,
                "-j",
                "ACCEPT",
            ],
        ));
        // Host-loopback requests retain a 127/8 source after OUTPUT DNAT.
        // Route them through the bridge gateway so the container can return
        // the response through conntrack instead of routing 127/8 directly.
        commands.push(iptables_cmd(
            "nat",
            "-A",
            &postrouting,
            &[
                "-s",
                "127.0.0.0/8",
                "-d",
                &format!("{container_ip}/32"),
                "-p",
                &mapping.protocol,
                "--dport",
                &container_port,
                "-j",
                "MASQUERADE",
            ],
        ));
    }

    let mut cleanup_commands = Vec::new();
    for (table, parent, child) in jumps.into_iter().rev() {
        cleanup_commands.push(iptables_cmd(
            table,
            "-D",
            parent,
            &["-m", "comment", "--comment", &comment, "-j", child],
        ));
    }
    for (table, chain) in chains.into_iter().rev() {
        cleanup_commands.push(iptables_cmd(table, "-F", chain, &[]));
        cleanup_commands.push(iptables_cmd(table, "-X", chain, &[]));
    }

    NetworkPlan {
        commands,
        cleanup_commands,
        firewall_id: Some(firewall_id),
    }
}

fn nft_cmd(args: &[&str]) -> Vec<String> {
    let mut command = vec!["nft".to_string()];
    command.extend(args.iter().map(|arg| (*arg).to_string()));
    command
}

fn build_owned_nftables_plan(
    owner_id: &str,
    mappings: &[PortMapping],
    container_ip: &str,
    source_cidr: &str,
    bridge: &str,
) -> NetworkPlan {
    let firewall_id = format!("fc_{}", firewall_owner_token(owner_id));
    let marker = format!("ferrocrate:{firewall_id}");
    let mut commands = vec![
        nft_cmd(&["add", "table", "ip", &firewall_id]),
        nft_cmd(&[
            "add",
            "chain",
            "ip",
            &firewall_id,
            "prerouting",
            "{",
            "type",
            "nat",
            "hook",
            "prerouting",
            "priority",
            "dstnat",
            ";",
            "}",
        ]),
        nft_cmd(&[
            "add",
            "chain",
            "ip",
            &firewall_id,
            "output",
            "{",
            "type",
            "nat",
            "hook",
            "output",
            "priority",
            "dstnat",
            ";",
            "}",
        ]),
        nft_cmd(&[
            "add",
            "chain",
            "ip",
            &firewall_id,
            "postrouting",
            "{",
            "type",
            "nat",
            "hook",
            "postrouting",
            "priority",
            "srcnat",
            ";",
            "}",
        ]),
        nft_cmd(&[
            "add",
            "chain",
            "ip",
            &firewall_id,
            "forward",
            "{",
            "type",
            "filter",
            "hook",
            "forward",
            "priority",
            "filter",
            ";",
            "policy",
            "accept",
            ";",
            "}",
        ]),
        nft_cmd(&[
            "add",
            "rule",
            "ip",
            &firewall_id,
            "forward",
            "counter",
            "comment",
            &marker,
        ]),
        nft_cmd(&[
            "add",
            "rule",
            "ip",
            &firewall_id,
            "postrouting",
            "ip",
            "saddr",
            source_cidr,
            "oifname",
            "!=",
            bridge,
            "masquerade",
        ]),
    ];
    for mapping in mappings {
        let host_port = mapping.host_port.to_string();
        let container_port = mapping.container_port.to_string();
        let destination = format!("{container_ip}:{container_port}");
        for chain in ["prerouting", "output"] {
            commands.push(nft_cmd(&[
                "add",
                "rule",
                "ip",
                &firewall_id,
                chain,
                &mapping.protocol,
                "dport",
                &host_port,
                "dnat",
                "to",
                &destination,
            ]));
        }
        commands.push(nft_cmd(&[
            "add",
            "rule",
            "ip",
            &firewall_id,
            "forward",
            "ip",
            "daddr",
            container_ip,
            &mapping.protocol,
            "dport",
            &container_port,
            "accept",
        ]));
    }
    NetworkPlan {
        commands,
        cleanup_commands: vec![nft_cmd(&["delete", "table", "ip", &firewall_id])],
        firewall_id: Some(firewall_id),
    }
}

pub fn build_iptables_prerouting_cmd(
    mapping: &PortMapping,
    container_ip: &str,
) -> Result<Vec<String>, ValidationError> {
    validate_port(mapping.host_port)?;
    validate_port(mapping.container_port)?;
    validate_protocol(&mapping.protocol)?;
    validate_ip(container_ip)?;
    Ok(vec![
        "iptables".into(),
        "-t".into(),
        "nat".into(),
        "-A".into(),
        "PREROUTING".into(),
        "-p".into(),
        mapping.protocol.clone(),
        "--dport".into(),
        mapping.host_port.to_string(),
        "-j".into(),
        "DNAT".into(),
        "--to-destination".into(),
        format!("{container_ip}:{}", mapping.container_port),
    ])
}

pub fn build_iptables_forward_cmd(
    mapping: &PortMapping,
    container_ip: &str,
) -> Result<Vec<String>, ValidationError> {
    validate_port(mapping.container_port)?;
    validate_protocol(&mapping.protocol)?;
    validate_ip(container_ip)?;
    Ok(vec![
        "iptables".into(),
        "-A".into(),
        "FORWARD".into(),
        "-p".into(),
        mapping.protocol.clone(),
        "-d".into(),
        container_ip.into(),
        "--dport".into(),
        mapping.container_port.to_string(),
        "-j".into(),
        "ACCEPT".into(),
    ])
}

pub fn build_iptables_masquerade_cmd(
    source_cidr: &str,
    bridge: &str,
) -> Result<Vec<String>, ValidationError> {
    validate_cidr(source_cidr)?;
    validate_interface_name(bridge)?;
    Ok(vec![
        "iptables".into(),
        "-t".into(),
        "nat".into(),
        "-A".into(),
        "POSTROUTING".into(),
        "-s".into(),
        source_cidr.into(),
        "!".into(),
        "-o".into(),
        bridge.into(),
        "-j".into(),
        "MASQUERADE".into(),
    ])
}

pub fn build_iptables_output_dnat_cmd(
    mapping: &PortMapping,
    container_ip: &str,
) -> Result<Vec<String>, ValidationError> {
    validate_port(mapping.host_port)?;
    validate_port(mapping.container_port)?;
    validate_protocol(&mapping.protocol)?;
    validate_ip(container_ip)?;
    Ok(vec![
        "iptables".into(),
        "-t".into(),
        "nat".into(),
        "-A".into(),
        "OUTPUT".into(),
        "-o".into(),
        "lo".into(),
        "-p".into(),
        mapping.protocol.clone(),
        "--dport".into(),
        mapping.host_port.to_string(),
        "-j".into(),
        "DNAT".into(),
        "--to-destination".into(),
        format!("{container_ip}:{}", mapping.container_port),
    ])
}

#[cfg(test)]
mod tests {
    use super::{build_iptables_forward_cmd, build_iptables_prerouting_cmd, PortMapping};

    #[test]
    fn builds_portmap_commands() {
        let mapping = PortMapping {
            host_port: 8080,
            container_port: 80,
            protocol: "tcp".to_string(),
        };

        let prerouting = build_iptables_prerouting_cmd(&mapping, "10.0.0.2").unwrap();
        assert_eq!(
            prerouting,
            vec![
                "iptables",
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-p",
                "tcp",
                "--dport",
                "8080",
                "-j",
                "DNAT",
                "--to-destination",
                "10.0.0.2:80"
            ]
        );

        let forward = build_iptables_forward_cmd(&mapping, "10.0.0.2").unwrap();
        assert_eq!(
            forward,
            vec![
                "iptables", "-A", "FORWARD", "-p", "tcp", "-d", "10.0.0.2", "--dport", "80", "-j",
                "ACCEPT"
            ]
        );
    }

    #[test]
    fn rejects_invalid_port_mappings() {
        let mapping = PortMapping {
            host_port: 0, // Invalid
            container_port: 80,
            protocol: "tcp".to_string(),
        };
        assert!(build_iptables_prerouting_cmd(&mapping, "10.0.0.2").is_err());

        let mapping = PortMapping {
            host_port: 8080,
            container_port: 80,
            protocol: "invalid".to_string(),
        };
        assert!(build_iptables_prerouting_cmd(&mapping, "10.0.0.2").is_err());

        let mapping = PortMapping {
            host_port: 8080,
            container_port: 80,
            protocol: "tcp".to_string(),
        };
        assert!(build_iptables_prerouting_cmd(&mapping, "not-an-ip").is_err());
    }

    #[test]
    fn builds_masquerade_command() {
        let cmd = super::build_iptables_masquerade_cmd("10.0.0.0/24", "ferro0").unwrap();
        assert_eq!(
            cmd,
            vec![
                "iptables",
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-s",
                "10.0.0.0/24",
                "!",
                "-o",
                "ferro0",
                "-j",
                "MASQUERADE"
            ]
        );
    }

    #[test]
    fn builds_output_dnat_command() {
        let mapping = PortMapping {
            host_port: 8080,
            container_port: 80,
            protocol: "tcp".to_string(),
        };
        let cmd = super::build_iptables_output_dnat_cmd(&mapping, "10.0.0.2").unwrap();
        assert_eq!(
            cmd,
            vec![
                "iptables",
                "-t",
                "nat",
                "-A",
                "OUTPUT",
                "-o",
                "lo",
                "-p",
                "tcp",
                "--dport",
                "8080",
                "-j",
                "DNAT",
                "--to-destination",
                "10.0.0.2:80"
            ]
        );
    }

    #[test]
    fn masquerade_rejects_bad_interface() {
        assert!(super::build_iptables_masquerade_cmd("10.0.0.0/24", "bad;rm").is_err());
    }

    #[test]
    fn masquerade_rejects_bad_cidr() {
        assert!(super::build_iptables_masquerade_cmd("not-a-cidr", "ferro0").is_err());
    }

    #[test]
    fn network_backend_plans_are_command_isolated_and_owned() {
        let mapping = super::PortMapping {
            host_port: 18080,
            container_port: 80,
            protocol: "tcp".to_string(),
        };
        for (backend, binary) in [
            (crate::NetworkBackend::Iptables, "iptables"),
            (crate::NetworkBackend::Nftables, "nft"),
        ] {
            let plan = super::build_network_plan(
                backend,
                "container-a",
                std::slice::from_ref(&mapping),
                "10.0.0.2",
                "10.0.0.0/24",
                "ferro0",
            )
            .unwrap();
            assert!(plan
                .commands()
                .iter()
                .chain(plan.cleanup_commands())
                .all(|command| command.first().map(String::as_str) == Some(binary)));
            assert!(plan.ownership_marker().unwrap().contains("ferrocrate:"));
            assert!(!plan.expected_owned_state().is_empty());
        }
    }

    #[test]
    fn network_backend_firewall_ids_do_not_collide_on_shared_prefixes() {
        let first = super::firewall_owner_token("aaaaaaaaaaaa-container-one");
        let second = super::firewall_owner_token("aaaaaaaaaaaa-container-two");
        assert_ne!(first, second);
    }

    #[test]
    fn network_backend_iptables_uses_one_canonical_owner_token_end_to_end() {
        let plan = super::build_network_plan(
            crate::backend::NetworkBackend::Iptables,
            "canonical-owner",
            &[PortMapping {
                host_port: 45_123,
                container_port: 80,
                protocol: "tcp".to_string(),
            }],
            "10.0.0.2",
            "10.0.0.0/24",
            "ferro0",
        )
        .unwrap();
        let firewall_id = plan.firewall_id().unwrap();
        let marker = plan.ownership_marker().unwrap();

        assert_eq!(marker, format!("ferrocrate:{firewall_id}"));
        assert!(plan
            .commands()
            .iter()
            .filter(|command| { command.iter().any(|argument| argument == "--comment") })
            .all(|command| command.iter().any(|argument| argument == &marker)));
        assert!(plan.commands().iter().all(|command| {
            command
                .iter()
                .filter(|argument| argument.starts_with("FC_") || argument.starts_with("fc_"))
                .all(|argument| argument.to_ascii_lowercase().contains(firewall_id))
        }));
        assert!(plan.commands().iter().any(|command| {
            command.iter().any(|argument| argument == "127.0.0.0/8")
                && command.iter().any(|argument| argument == "10.0.0.2/32")
                && command.iter().any(|argument| argument == "MASQUERADE")
        }));
    }

    #[test]
    fn network_backend_setup_rollback_is_scoped_to_successful_mutations() {
        let plan = super::build_network_plan(
            crate::backend::NetworkBackend::Iptables,
            "rollback-owner",
            &[],
            "10.0.0.2",
            "10.0.0.0/24",
            "ferro0",
        )
        .unwrap();
        assert!(plan.rollback_commands_for(plan.commands().len()).is_empty());
        for (index, command) in plan.commands().iter().enumerate() {
            let rollback = plan.rollback_commands_for(index);
            assert_eq!(rollback.len(), 1);
            assert_eq!(rollback[0][..3], command[..3]);
            assert_eq!(rollback[0][3], if command[3] == "-N" { "-X" } else { "-D" });
        }
    }
}
