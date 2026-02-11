use std::process::Command;

fn command_exists(bin: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn kernel_version() -> Option<(u32, u32, u32)> {
    let output = Command::new("uname").arg("-r").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&output.stdout);
    let version = raw.trim();
    let mut parts = Vec::new();
    let mut current = String::new();
    for ch in version.chars() {
        if ch.is_ascii_digit() {
            current.push(ch);
        } else if ch == '.' {
            parts.push(current.clone());
            current.clear();
        } else {
            break;
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    let major = parts.get(0)?.parse().ok()?;
    let minor = parts.get(1).unwrap_or(&"0".to_string()).parse().ok()?;
    let patch = parts.get(2).unwrap_or(&"0".to_string()).parse().ok()?;
    Some((major, minor, patch))
}

fn version_at_least(actual: (u32, u32, u32), min: (u32, u32, u32)) -> bool {
    if actual.0 != min.0 {
        return actual.0 > min.0;
    }
    if actual.1 != min.1 {
        return actual.1 > min.1;
    }
    actual.2 >= min.2
}

#[test]
#[ignore]
fn iptables_kernel_compat_smoke() {
    let Some(actual) = kernel_version() else {
        eprintln!("skipping: unable to parse kernel version");
        return;
    };
    if !version_at_least(actual, (3, 10, 0)) {
        eprintln!("skipping: kernel < 3.10");
        return;
    }
    if !command_exists("iptables") {
        eprintln!("skipping: iptables not installed");
        return;
    }

    let status = Command::new("iptables")
        .arg("-S")
        .status()
        .expect("failed to run iptables -S");
    assert!(status.success(), "iptables -S failed");

    let status = Command::new("iptables")
        .args(["-t", "nat", "-S"])
        .status()
        .expect("failed to run iptables -t nat -S");
    assert!(status.success(), "iptables -t nat -S failed");
}

#[test]
#[ignore]
fn nftables_kernel_compat_smoke() {
    let Some(actual) = kernel_version() else {
        eprintln!("skipping: unable to parse kernel version");
        return;
    };
    if !version_at_least(actual, (3, 13, 0)) {
        eprintln!("skipping: kernel < 3.13");
        return;
    }
    if !command_exists("nft") {
        eprintln!("skipping: nft not installed");
        return;
    }

    let status = Command::new("nft")
        .args(["list", "ruleset"])
        .status()
        .expect("failed to run nft list ruleset");
    assert!(status.success(), "nft list ruleset failed");
}
