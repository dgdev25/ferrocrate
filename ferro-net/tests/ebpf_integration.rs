#![cfg(target_os = "linux")]

use ferro_net::ebpf::{build_bpftool_load_cmd, build_xdp_attach_cmd, EbpfProgram};
use ferro_net::netns::build_ip_netns_add_cmd;
use ferro_net::veth::{build_ip_link_add_veth_cmd, VethConfig, VethPair};
use nix::unistd::Uid;
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn command_exists(bin: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn run_vec(cmd: Vec<String>) -> Result<(), String> {
    let (program, args) = cmd
        .split_first()
        .ok_or_else(|| "empty command".to_string())?;
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|err| format!("failed to run {program}: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("command failed: {program} status={status}"))
    }
}

fn run_cmd(program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|err| format!("failed to run {program}: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("command failed: {program} status={status}"))
    }
}

#[test]
#[ignore]
fn ebpf_xdp_integration_smoke() {
    if !Uid::effective().is_root() {
        eprintln!("skipping: requires root");
        return;
    }
    if !command_exists("ip") || !command_exists("bpftool") {
        eprintln!("skipping: requires ip and bpftool");
        return;
    }
    if !Path::new("/sys/fs/bpf").exists() {
        eprintln!("skipping: /sys/fs/bpf not available");
        return;
    }

    let obj_path = env::var("FERRO_EBPF_OBJ").unwrap_or_default();
    if obj_path.is_empty() {
        eprintln!("skipping: set FERRO_EBPF_OBJ to a compiled eBPF object path");
        return;
    }

    let pid = std::process::id();
    let netns = format!("ferro-netns-{pid}");
    let veth_host = format!("vethh{pid}");
    let veth_ns = format!("vethn{pid}");
    let pin_path = format!("/sys/fs/bpf/ferro-test-{pid}");

    let mut result = Ok(());

    let config = VethConfig {
        pair: VethPair {
            host: veth_host.clone(),
            container: veth_ns.clone(),
        },
        mtu: None,
        host_addr: None,
        container_addr: None,
    };

    if result.is_ok() {
        result = build_ip_netns_add_cmd(&netns)
            .map_err(|e| e.to_string())
            .and_then(run_vec);
    }
    if result.is_ok() {
        result = build_ip_link_add_veth_cmd(&config)
            .map_err(|e| e.to_string())
            .and_then(run_vec);
    }
    if result.is_ok() {
        result = run_cmd("ip", &["link", "set", &veth_ns, "netns", &netns]);
    }
    if result.is_ok() {
        result = run_cmd("ip", &["link", "set", &veth_host, "up"]);
    }
    if result.is_ok() {
        let _ = fs::create_dir_all(&pin_path);
        let program = EbpfProgram {
            name: "ferro_xdp".to_string(),
            object_path: obj_path,
            section: "xdp".to_string(),
        };
        result = run_vec(build_bpftool_load_cmd(&program, &pin_path));
    }
    if result.is_ok() {
        result = run_vec(build_xdp_attach_cmd(&veth_host, &pin_path));
    }

    let _ = run_cmd("ip", &["link", "set", &veth_host, "xdp", "off"]);
    let _ = run_cmd("ip", &["link", "del", &veth_host]);
    let _ = run_cmd("ip", &["netns", "del", &netns]);
    let _ = fs::remove_dir_all(&pin_path);

    if let Err(err) = result {
        panic!("integration test failed: {err}");
    }
}
