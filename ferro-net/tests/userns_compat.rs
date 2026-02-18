#![cfg(target_os = "linux")]

use std::env;
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
fn ebpf_userns_smoke() {
    if !command_exists("unshare") || !command_exists("bpftool") || !command_exists("ip") {
        eprintln!("skipping: requires unshare, bpftool, and ip");
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

    let pin_path = "/sys/fs/bpf/ferro-userns-test";
    let cmd =
        format!("set -e; mkdir -p {pin_path}; bpftool prog load {obj_path} {pin_path} type xdp");
    let result = run_cmd("unshare", &["-Urn", "sh", "-c", &cmd]);
    if let Err(err) = result {
        panic!("userns eBPF test failed: {err}");
    }

    let _ = run_cmd(
        "unshare",
        &["-Urn", "sh", "-c", "rm -rf /sys/fs/bpf/ferro-userns-test"],
    );
}

#[test]
#[ignore]
fn iptables_nftables_userns_smoke() {
    if !command_exists("unshare") || !command_exists("ip") {
        eprintln!("skipping: requires unshare and ip");
        return;
    }

    if command_exists("iptables") {
        let result = run_cmd("unshare", &["-Urn", "sh", "-c", "iptables -S"]);
        if let Err(err) = result {
            panic!("userns iptables test failed: {err}");
        }
    } else {
        eprintln!("skipping: iptables not installed");
    }

    if command_exists("nft") {
        let result = run_cmd("unshare", &["-Urn", "sh", "-c", "nft list ruleset"]);
        if let Err(err) = result {
            panic!("userns nftables test failed: {err}");
        }
    } else {
        eprintln!("skipping: nft not installed");
    }
}
