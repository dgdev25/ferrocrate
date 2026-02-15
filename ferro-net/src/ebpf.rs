use crate::executor::{ExecError, exec_cmd, exec_cmd_capture};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EbpfProgram {
    pub name: String,
    pub object_path: String,
    pub section: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityMonitorConfig {
    pub object_path: String,
    pub pin_root: String,
    pub events: Vec<String>,
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

pub fn build_tracepoint_attach_cmd(pin_path: &str, category: &str, event: &str) -> Vec<String> {
    vec![
        "bpftool".into(),
        "prog".into(),
        "attach".into(),
        "pinned".into(),
        pin_path.into(),
        "tracepoint".into(),
        category.into(),
        event.into(),
    ]
}

pub fn install_security_monitor(config: &SecurityMonitorConfig) -> Result<Vec<String>, ExecError> {
    let events = if config.events.is_empty() {
        default_security_events()
            .iter()
            .map(|event| (*event).to_string())
            .collect::<Vec<_>>()
    } else {
        config.events.clone()
    };
    let mut installed = Vec::new();
    for event in events {
        let normalized = sanitize_event(&event)?;
        let pin_path = format!("{}/{}", config.pin_root, normalized);
        let program = EbpfProgram {
            name: format!("ferro_security_{}", normalized),
            object_path: config.object_path.clone(),
            section: "tracepoint".to_string(),
        };
        exec_cmd(&build_bpftool_load_cmd(&program, &pin_path))?;
        let tracepoint = format!("sys_enter_{}", normalized);
        exec_cmd(&build_tracepoint_attach_cmd(
            &pin_path,
            "syscalls",
            &tracepoint,
        ))?;
        // Verify the program is present at the pin path.
        let _ = exec_cmd_capture(&[
            "bpftool".to_string(),
            "prog".to_string(),
            "show".to_string(),
            "pinned".to_string(),
            pin_path.clone(),
        ])?;
        installed.push(normalized);
    }
    Ok(installed)
}

fn sanitize_event(event: &str) -> Result<String, ExecError> {
    let normalized = event.trim().to_ascii_lowercase();
    if normalized.is_empty()
        || !normalized
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return Err(ExecError::CommandFailed {
            cmd: format!("event={event}"),
            stderr: "invalid security monitor event".to_string(),
        });
    }
    Ok(normalized)
}

fn default_security_events() -> &'static [&'static str] {
    &["execve", "connect", "open", "ptrace", "mount", "unshare"]
}

#[cfg(test)]
mod tests {
    use super::{
        EbpfProgram, build_bpftool_load_cmd, build_tc_attach_cmd, build_tracepoint_attach_cmd,
        build_xdp_attach_cmd, sanitize_event,
    };

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
        assert_eq!(
            build_tracepoint_attach_cmd("/sys/fs/bpf/ferro-sec", "syscalls", "sys_enter_execve"),
            vec![
                "bpftool",
                "prog",
                "attach",
                "pinned",
                "/sys/fs/bpf/ferro-sec",
                "tracepoint",
                "syscalls",
                "sys_enter_execve"
            ]
        );
    }

    #[test]
    fn event_sanitization_rejects_invalid_names() {
        let err = sanitize_event("execve;rm -rf /").expect_err("invalid");
        assert!(err.to_string().contains("invalid security monitor event"));
        assert_eq!(sanitize_event(" ExEcVe ").expect("valid"), "execve");
    }
}
