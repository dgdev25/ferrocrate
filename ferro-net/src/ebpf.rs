#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfProgram {
    pub name: String,
    pub object_path: String,
    pub section: String,
}

pub fn build_bpftool_load_cmd(program: &EbpfProgram, pin_path: &str) -> Vec<String> {
    vec![
        "bpftool".into(),
        "prog".into(),
        "load".into(),
        program.object_path.clone(),
        pin_path.into(),
        "type".into(),
        program.section.clone(),
    ]
}

pub fn build_tc_attach_cmd(iface: &str, pin_path: &str, direction: &str) -> Vec<String> {
    vec![
        "tc".into(),
        "filter".into(),
        "add".into(),
        "dev".into(),
        iface.into(),
        direction.into(),
        "bpf".into(),
        "da".into(),
        "pinned".into(),
        pin_path.into(),
    ]
}

pub fn build_xdp_attach_cmd(iface: &str, pin_path: &str) -> Vec<String> {
    vec![
        "ip".into(),
        "link".into(),
        "set".into(),
        iface.into(),
        "xdp".into(),
        "pinned".into(),
        pin_path.into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::{EbpfProgram, build_bpftool_load_cmd, build_tc_attach_cmd, build_xdp_attach_cmd};

    #[test]
    fn builds_bpftool_load_command() {
        let prog = EbpfProgram {
            name: "ferro_xdp".to_string(),
            object_path: "/opt/ferro/xdp.o".to_string(),
            section: "xdp".to_string(),
        };

        assert_eq!(
            build_bpftool_load_cmd(&prog, "/sys/fs/bpf/ferro"),
            vec![
                "bpftool", "prog", "load", "/opt/ferro/xdp.o", "/sys/fs/bpf/ferro",
                "type", "xdp"
            ]
        );
    }

    #[test]
    fn builds_attach_commands() {
        assert_eq!(
            build_tc_attach_cmd("eth0", "/sys/fs/bpf/ferro", "ingress"),
            vec![
                "tc", "filter", "add", "dev", "eth0", "ingress", "bpf", "da", "pinned",
                "/sys/fs/bpf/ferro"
            ]
        );
        assert_eq!(
            build_xdp_attach_cmd("eth0", "/sys/fs/bpf/ferro"),
            vec!["ip", "link", "set", "eth0", "xdp", "pinned", "/sys/fs/bpf/ferro"]
        );
    }
}
