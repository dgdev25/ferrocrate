#![cfg(target_os = "linux")]

//! Real rootless Compose workload qualification.
//!
//! This is opt-in because it needs a user namespace, slirp4netns, an OCI
//! registry/cache, and a host bind mount. Run it on a matching host with:
//! `FERROCRATE_RUN_ROOTLESS_E2E=1 cargo test -p ferro-cli --test
//! rootless_compose_integration -- --nocapture`.

use std::fs;
use std::process::Command;

#[test]
fn rootless_compose_executes_a_bind_mount_and_cleans_up() {
    if std::env::var("FERROCRATE_RUN_ROOTLESS_E2E").as_deref() != Ok("1") {
        return;
    }
    assert!(
        !nix::unistd::Uid::effective().is_root(),
        "run this fixture as a non-root user"
    );

    let root = tempfile::tempdir().expect("root tempdir");
    let project = root.path().join("project");
    let workspace = project.join("workspace");
    fs::create_dir_all(&workspace).expect("workspace");
    fs::write(workspace.join("input"), b"rootless-compose\n").expect("input");
    fs::write(
        project.join("compose.yml"),
        "services:\n  writer:\n    image: alpine:3.20\n    command: [\"sh\", \"-c\", \"cat /data/input > /data/output; echo named-volume > /named/marker; sleep 30\"]\n    volumes:\n      - ./workspace:/data\n      - named:/named\n    network_mode: none\nvolumes:\n  named: {}\n",
    )
    .expect("compose file");

    let runtime = root.path().join("runtime");
    let binary = env!("CARGO_BIN_EXE_ferro-cli");
    let mut up = Command::new(binary);
    up.current_dir(&project)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .env("FERROCRATE_ROOTLESS_NETNS", "1")
        .env("FERROCRATE_NETWORK_BACKEND", "iptables")
        .args(["compose", "--file", "compose.yml", "up", "--detach"]);
    let output = up.output().expect("compose up");
    assert!(
        output.status.success(),
        "rootless compose up failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    for _ in 0..100 {
        if workspace.join("output").exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if !workspace.join("output").exists() {
        let diagnostics = Command::new(binary)
            .current_dir(&project)
            .env("FERROCRATE_RUNTIME_DIR", &runtime)
            .args(["logs", "writer"])
            .output()
            .expect("compose logs");
        let inspect = Command::new(binary)
            .current_dir(&project)
            .env("FERROCRATE_RUNTIME_DIR", &runtime)
            .args(["inspect", "writer"])
            .output()
            .expect("inspect writer");
        panic!(
            "rootless compose workload did not create the bind-mounted output; logs={} stderr={} inspect={} inspect_stderr={}",
            String::from_utf8_lossy(&diagnostics.stdout),
            String::from_utf8_lossy(&diagnostics.stderr),
            String::from_utf8_lossy(&inspect.stdout),
            String::from_utf8_lossy(&inspect.stderr)
        );
    }

    let mut down = Command::new(binary);
    down.current_dir(&project)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .env("FERROCRATE_ROOTLESS_NETNS", "1")
        .env("FERROCRATE_NETWORK_BACKEND", "iptables")
        .args(["compose", "--file", "compose.yml", "down"]);
    let down_output = down.output().expect("compose down");
    assert!(
        down_output.status.success(),
        "rootless compose down failed: {}",
        String::from_utf8_lossy(&down_output.stderr)
    );
    assert_eq!(
        fs::read_to_string(workspace.join("output")).expect("bind-mounted output"),
        "rootless-compose\n"
    );
    assert_eq!(
        fs::read_to_string(runtime.join("volumes/named/marker")).expect("named volume output"),
        "named-volume\n"
    );
}

#[test]
fn rootless_run_mounts_bind_and_named_volumes() {
    if std::env::var("FERROCRATE_RUN_ROOTLESS_E2E").as_deref() != Ok("1") {
        return;
    }
    assert!(
        !nix::unistd::Uid::effective().is_root(),
        "run this fixture as a non-root user"
    );

    let root = tempfile::tempdir().expect("root tempdir");
    let workspace = root.path().join("workspace");
    fs::create_dir_all(&workspace).expect("workspace");
    fs::write(workspace.join("input"), b"rootless-run\n").expect("input");
    let runtime = root.path().join("runtime");
    let binary = env!("CARGO_BIN_EXE_ferro-cli");
    let pull = Command::new(binary)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .args(["pull", "alpine:3.20"])
        .output()
        .expect("pull alpine");
    assert!(
        pull.status.success(),
        "rootless pull failed: {}",
        String::from_utf8_lossy(&pull.stderr)
    );

    let bind = Command::new(binary)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .env("FERROCRATE_ROOTLESS_NETNS", "1")
        .args([
            "run",
            "--rm",
            "--network",
            "none",
            "--volume",
            &format!("{}:/data", workspace.display()),
            "alpine:3.20",
            "sh",
            "-c",
            "cat /data/input > /data/output",
        ])
        .output()
        .expect("rootless bind run");
    assert!(
        bind.status.success(),
        "rootless bind run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&bind.stdout),
        String::from_utf8_lossy(&bind.stderr)
    );
    assert_eq!(
        fs::read_to_string(workspace.join("output")).expect("bind output"),
        "rootless-run\n"
    );

    let named = Command::new(binary)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .env("FERROCRATE_ROOTLESS_NETNS", "1")
        .args([
            "run",
            "--rm",
            "--network",
            "none",
            "--volume",
            "named:/data",
            "alpine:3.20",
            "sh",
            "-c",
            "echo named-run > /data/output",
        ])
        .output()
        .expect("rootless named-volume run");
    assert!(
        named.status.success(),
        "rootless named-volume run failed: stdout={} stderr={}",
        String::from_utf8_lossy(&named.stdout),
        String::from_utf8_lossy(&named.stderr)
    );
    assert_eq!(
        fs::read_to_string(runtime.join("volumes/named/output")).expect("named output"),
        "named-run\n"
    );
}

#[test]
fn rootless_compose_waits_for_successfully_completed_dependency() {
    if std::env::var("FERROCRATE_RUN_ROOTLESS_E2E").as_deref() != Ok("1") {
        return;
    }
    assert!(!nix::unistd::Uid::effective().is_root());

    let root = tempfile::tempdir().expect("root tempdir");
    let project = root.path().join("project");
    let workspace = project.join("workspace");
    fs::create_dir_all(&workspace).expect("workspace");
    fs::write(
        project.join("compose.yml"),
        "services:\n  job:\n    image: alpine:3.20\n    command: [\"sh\", \"-c\", \"echo completed\"]\n    network_mode: none\n  dependent:\n    image: alpine:3.20\n    command: [\"sh\", \"-c\", \"echo dependent > /data/output; sleep 2\"]\n    network_mode: none\n    volumes:\n      - ./workspace:/data\n    depends_on:\n      job:\n        condition: service_completed_successfully\n",
    )
    .expect("compose file");

    let runtime = root.path().join("runtime");
    let binary = env!("CARGO_BIN_EXE_ferro-cli");
    let output = Command::new(binary)
        .current_dir(&project)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .env("FERROCRATE_ROOTLESS_NETNS", "1")
        .env("FERROCRATE_NETWORK_BACKEND", "iptables")
        .args(["compose", "--file", "compose.yml", "up", "--detach"])
        .output()
        .expect("compose up");
    assert!(
        output.status.success(),
        "completion-condition compose up failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    for _ in 0..100 {
        if workspace.join("output").exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert_eq!(
        fs::read_to_string(workspace.join("output")).expect("dependent output"),
        "dependent\n"
    );

    let down = Command::new(binary)
        .current_dir(&project)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .args(["compose", "--file", "compose.yml", "down"])
        .output()
        .expect("compose down");
    assert!(
        down.status.success(),
        "completion-condition compose down failed: {}",
        String::from_utf8_lossy(&down.stderr)
    );
}
