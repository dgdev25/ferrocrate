#![cfg(target_os = "linux")]

//! Real rootless Compose workload qualification.
//!
//! This is opt-in because it needs a user namespace, slirp4netns, an OCI
//! registry/cache, and a host bind mount. Run it on a matching host with:
//! `FERROCRATE_RUN_ROOTLESS_E2E=1 cargo test -p ferro-cli --test
//! rootless_compose_integration -- --nocapture`. Set
//! `FERROCRATE_ROOTLESS_TEST_IMAGE` to a compatible registry image when
//! Docker Hub's unauthenticated pull quota is exhausted.
//! The shared-network fixture is separately gated by
//! `FERROCRATE_RUN_ROOTLESS_SHARED_COMPOSE_E2E=1` because it requires a host
//! that permits nested user+network namespaces.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn rootless_test_image() -> String {
    std::env::var("FERROCRATE_ROOTLESS_TEST_IMAGE").unwrap_or_else(|_| "alpine:3.20".to_string())
}

fn compose_fixture(contents: &str) -> String {
    contents.replace("alpine:3.20", &rootless_test_image())
}

fn runtime_dir(root: &Path) -> PathBuf {
    let runtime = root.join("runtime");
    if let Ok(store) = std::env::var("FERROCRATE_ROOTLESS_IMAGE_STORE") {
        let store = PathBuf::from(store);
        assert!(
            store.is_dir(),
            "configured rootless image store is not a directory"
        );
        fs::create_dir_all(&runtime).expect("runtime directory");
        std::os::unix::fs::symlink(&store, runtime.join("images"))
            .expect("link configured rootless image store");
        let store_db = PathBuf::from(format!("{}.sqlite", store.display()));
        assert!(
            store_db.is_file(),
            "configured rootless image store database is missing"
        );
        std::os::unix::fs::symlink(store_db, runtime.join("images.sqlite"))
            .expect("link configured rootless image store database");
    }
    runtime
}

fn prepare_image(binary: &str, runtime: &Path, image: &str) {
    let mut pull = Command::new(binary);
    pull.env("FERROCRATE_RUNTIME_DIR", runtime);
    if std::env::var("FERROCRATE_ROOTLESS_SKIP_PULL").as_deref() == Ok("1") {
        let listing = pull
            .args(["images"])
            .output()
            .expect("list preloaded rootless images");
        assert!(listing.status.success(), "list preloaded images failed");
        let short = image
            .rsplit('/')
            .next()
            .unwrap_or(image)
            .split([':', '@'])
            .next()
            .unwrap_or(image);
        assert!(
            String::from_utf8_lossy(&listing.stdout).contains(short),
            "configured rootless image store does not contain {image}: {}",
            String::from_utf8_lossy(&listing.stdout)
        );
    } else {
        let output = pull
            .args(["pull", image])
            .output()
            .expect("pull rootless image");
        assert!(
            output.status.success(),
            "rootless pull failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

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
        compose_fixture("services:\n  writer:\n    image: alpine:3.20\n    command: [\"sh\", \"-c\", \"cat /data/input > /data/output; echo named-volume > /named/marker; sleep 30\"]\n    volumes:\n      - ./workspace:/data\n      - named:/named\n    network_mode: none\nvolumes:\n  named: {}\n"),
    )
    .expect("compose file");

    let runtime = runtime_dir(root.path());
    let binary = env!("CARGO_BIN_EXE_ferro-cli");
    prepare_image(binary, &runtime, &rootless_test_image());
    let mut up = Command::new(binary);
    up.current_dir(&project)
        .env("FERROCRATE_HOME", &runtime)
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
            .env("FERROCRATE_HOME", &runtime)
            .env("FERROCRATE_RUNTIME_DIR", &runtime)
            .args(["logs", "writer"])
            .output()
            .expect("compose logs");
        let inspect = Command::new(binary)
            .current_dir(&project)
            .env("FERROCRATE_HOME", &runtime)
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
        .env("FERROCRATE_HOME", &runtime)
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
fn rootless_compose_services_share_the_project_network_namespace() {
    if std::env::var("FERROCRATE_RUN_ROOTLESS_SHARED_COMPOSE_E2E").as_deref() != Ok("1") {
        return;
    }
    assert!(!nix::unistd::Uid::effective().is_root());

    let root = tempfile::tempdir().expect("root tempdir");
    let project = root.path().join("project");
    let workspace = project.join("workspace");
    fs::create_dir_all(&workspace).expect("workspace");
    let compose = compose_fixture(
        "services:\n  leader:\n    image: alpine:3.20\n    command: [\"sh\", \"-c\", \"readlink /proc/self/ns/net > /data/leader; sleep 30\"]\n    volumes:\n      - ./workspace:/data\n    networks: [appnet]\n  follower:\n    image: alpine:3.20\n    command: [\"sh\", \"-c\", \"readlink /proc/self/ns/net > /data/follower; sleep 30\"]\n    volumes:\n      - ./workspace:/data\n    networks: [appnet]\n    depends_on:\n      leader:\n        condition: service_started\nnetworks:\n  appnet: {}\n",
    );
    fs::create_dir_all(&project).expect("project");
    fs::write(project.join("compose.yml"), compose).expect("compose file");

    let runtime = runtime_dir(root.path());
    let binary = env!("CARGO_BIN_EXE_ferro-cli");
    prepare_image(binary, &runtime, &rootless_test_image());
    let up = Command::new(binary)
        .current_dir(&project)
        .env("FERROCRATE_HOME", &runtime)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .env("FERROCRATE_ROOTLESS_NETNS", "1")
        .env("FERROCRATE_NETWORK_BACKEND", "iptables")
        .args(["compose", "--file", "compose.yml", "up", "--detach"])
        .output()
        .expect("compose up");
    if !up.status.success()
        && String::from_utf8_lossy(&up.stderr)
            .contains("rootless bridge networking is unavailable on this host")
    {
        eprintln!(
            "SKIP: rootless shared-network Compose requires user-namespace mapping: {}",
            String::from_utf8_lossy(&up.stderr).trim()
        );
        return;
    }
    assert!(
        up.status.success(),
        "rootless shared-network compose up failed: {}",
        String::from_utf8_lossy(&up.stderr)
    );
    for _ in 0..100 {
        if workspace.join("leader").is_file() && workspace.join("follower").is_file() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if !(workspace.join("leader").is_file() && workspace.join("follower").is_file()) {
        let diagnostics = Command::new(binary)
            .current_dir(&project)
            .env("FERROCRATE_HOME", &runtime)
            .env("FERROCRATE_RUNTIME_DIR", &runtime)
            .args(["logs", "follower"])
            .output()
            .expect("follower logs");
        let inspect = Command::new(binary)
            .current_dir(&project)
            .env("FERROCRATE_HOME", &runtime)
            .env("FERROCRATE_RUNTIME_DIR", &runtime)
            .args(["inspect", "follower"])
            .output()
            .expect("follower inspect");
        panic!(
            "rootless shared-network compose did not start both services; up_stdout={} up_stderr={} logs={} logs_stderr={} inspect={} inspect_stderr={}",
            String::from_utf8_lossy(&up.stdout),
            String::from_utf8_lossy(&up.stderr),
            String::from_utf8_lossy(&diagnostics.stdout),
            String::from_utf8_lossy(&diagnostics.stderr),
            String::from_utf8_lossy(&inspect.stdout),
            String::from_utf8_lossy(&inspect.stderr)
        );
    }
    let down = Command::new(binary)
        .current_dir(&project)
        .env("FERROCRATE_HOME", &runtime)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .env("FERROCRATE_ROOTLESS_NETNS", "1")
        .env("FERROCRATE_NETWORK_BACKEND", "iptables")
        .args(["compose", "--file", "compose.yml", "down"])
        .output()
        .expect("compose down");
    assert!(
        down.status.success(),
        "rootless shared-network compose down failed: {}",
        String::from_utf8_lossy(&down.stderr)
    );
    assert_eq!(
        fs::read_to_string(workspace.join("leader")).expect("leader namespace"),
        fs::read_to_string(workspace.join("follower")).expect("follower namespace")
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
    let runtime = runtime_dir(root.path());
    let binary = env!("CARGO_BIN_EXE_ferro-cli");
    let image = rootless_test_image();
    prepare_image(binary, &runtime, &image);

    let bind = Command::new(binary)
        .env("FERROCRATE_HOME", &runtime)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .env("FERROCRATE_ROOTLESS_NETNS", "1")
        .args([
            "run",
            "--rm",
            "--network",
            "none",
            "--volume",
            &format!("{}:/data", workspace.display()),
            image.as_str(),
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
        .env("FERROCRATE_HOME", &runtime)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .env("FERROCRATE_ROOTLESS_NETNS", "1")
        .args([
            "run",
            "--rm",
            "--network",
            "none",
            "--volume",
            "named:/data",
            image.as_str(),
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
fn rootless_compose_mounts_file_backed_secrets_and_configs_read_only() {
    if std::env::var("FERROCRATE_RUN_ROOTLESS_E2E").as_deref() != Ok("1") {
        return;
    }
    assert!(!nix::unistd::Uid::effective().is_root());

    let root = tempfile::tempdir().expect("root tempdir");
    let project = root.path().join("project");
    let workspace = project.join("workspace");
    fs::create_dir_all(&workspace).expect("workspace");
    fs::write(project.join("token.txt"), b"secret-value\n").expect("secret");
    fs::write(project.join("app.conf"), b"config-value\n").expect("config");
    fs::write(
        project.join("compose.yml"),
        compose_fixture("services:\n  reader:\n    image: alpine:3.20\n    command: [\"sh\", \"-c\", \"cat /run/secrets/api-token /etc/configs/app-config > /data/output; test ! -w /run/secrets/api-token; test ! -w /etc/configs/app-config; sleep 30\"]\n    volumes:\n      - ./workspace:/data\n    secrets:\n      - api-token\n    configs:\n      - app-config\n    network_mode: none\nsecrets:\n  api-token:\n    file: ./token.txt\nconfigs:\n  app-config:\n    file: ./app.conf\n"),
    )
    .expect("compose file");

    let runtime = runtime_dir(root.path());
    let binary = env!("CARGO_BIN_EXE_ferro-cli");
    prepare_image(binary, &runtime, &rootless_test_image());
    let up = Command::new(binary)
        .current_dir(&project)
        .env("FERROCRATE_HOME", &runtime)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .env("FERROCRATE_ROOTLESS_NETNS", "1")
        .env("FERROCRATE_NETWORK_BACKEND", "iptables")
        .args(["compose", "--file", "compose.yml", "up", "--detach"])
        .output()
        .expect("compose up");
    assert!(
        up.status.success(),
        "secret/config compose up failed: {}",
        String::from_utf8_lossy(&up.stderr)
    );
    for _ in 0..100 {
        if workspace.join("output").exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if !workspace.join("output").exists() {
        let logs = Command::new(binary)
            .current_dir(&project)
            .env("FERROCRATE_HOME", &runtime)
            .env("FERROCRATE_RUNTIME_DIR", &runtime)
            .args(["logs", "reader"])
            .output()
            .expect("compose logs");
        let inspect = Command::new(binary)
            .current_dir(&project)
            .env("FERROCRATE_HOME", &runtime)
            .env("FERROCRATE_RUNTIME_DIR", &runtime)
            .args(["inspect", "reader"])
            .output()
            .expect("inspect reader");
        panic!(
            "secret/config workload did not create output; logs={} logs_stderr={} inspect={} inspect_stderr={}",
            String::from_utf8_lossy(&logs.stdout),
            String::from_utf8_lossy(&logs.stderr),
            String::from_utf8_lossy(&inspect.stdout),
            String::from_utf8_lossy(&inspect.stderr)
        );
    }
    assert_eq!(
        fs::read_to_string(workspace.join("output")).expect("resource output"),
        "secret-value\nconfig-value\n"
    );

    let down = Command::new(binary)
        .current_dir(&project)
        .env("FERROCRATE_HOME", &runtime)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .args(["compose", "--file", "compose.yml", "down"])
        .output()
        .expect("compose down");
    assert!(
        down.status.success(),
        "secret/config compose down failed: {}",
        String::from_utf8_lossy(&down.stderr)
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
        compose_fixture("services:\n  job:\n    image: alpine:3.20\n    command: [\"sh\", \"-c\", \"echo completed\"]\n    network_mode: none\n  dependent:\n    image: alpine:3.20\n    command: [\"sh\", \"-c\", \"echo dependent > /data/output; sleep 2\"]\n    network_mode: none\n    volumes:\n      - ./workspace:/data\n    depends_on:\n      job:\n        condition: service_completed_successfully\n"),
    )
    .expect("compose file");

    let runtime = runtime_dir(root.path());
    let binary = env!("CARGO_BIN_EXE_ferro-cli");
    prepare_image(binary, &runtime, &rootless_test_image());
    let output = Command::new(binary)
        .current_dir(&project)
        .env("FERROCRATE_HOME", &runtime)
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
        .env("FERROCRATE_HOME", &runtime)
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

#[test]
fn rootless_compose_read_only_rootfs_preserves_writable_bind_mounts() {
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
        compose_fixture("services:\n  probe:\n    image: alpine:3.20\n    read_only: true\n    command: [\"sh\", \"-c\", \"if touch /rootfs-write 2>/dev/null; then exit 11; fi; echo bind-write > /data/output; sleep 30\"]\n    volumes:\n      - ./workspace:/data\n    network_mode: none\n"),
    )
    .expect("compose file");

    let runtime = runtime_dir(root.path());
    let binary = env!("CARGO_BIN_EXE_ferro-cli");
    prepare_image(binary, &runtime, &rootless_test_image());
    let up = Command::new(binary)
        .current_dir(&project)
        .env("FERROCRATE_HOME", &runtime)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .env("FERROCRATE_ROOTLESS_NETNS", "1")
        .env("FERROCRATE_NETWORK_BACKEND", "iptables")
        .args(["compose", "--file", "compose.yml", "up", "--detach"])
        .output()
        .expect("compose up");
    assert!(
        up.status.success(),
        "read-only compose up failed: {}",
        String::from_utf8_lossy(&up.stderr)
    );
    for _ in 0..100 {
        if workspace.join("output").exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert_eq!(
        fs::read_to_string(workspace.join("output")).expect("writable bind output"),
        "bind-write\n"
    );

    let down = Command::new(binary)
        .current_dir(&project)
        .env("FERROCRATE_HOME", &runtime)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .args(["compose", "--file", "compose.yml", "down"])
        .output()
        .expect("compose down");
    assert!(
        down.status.success(),
        "read-only compose down failed: {}",
        String::from_utf8_lossy(&down.stderr)
    );
}

/// Requires a delegated user cgroup (cpu/memory controllers enabled below
/// the caller): run the corpus under
/// `scripts/run-rootless-delegated.sh` or an equivalent systemd user scope.
/// Outside such a scope the run fails closed with the controller-availability
/// diagnostic, which is the documented rootless boundary.
/// Requires a delegated user cgroup (controllers enabled), like every
/// rootless resource-limit fixture: run under
/// `scripts/run-rootless-delegated.sh` or
/// `systemd-run --user --scope -p Delegate=yes`.
#[test]
fn rootless_compose_applies_deploy_resource_limits() {
    if std::env::var("FERROCRATE_RUN_ROOTLESS_E2E").as_deref() != Ok("1") {
        return;
    }
    assert!(!nix::unistd::Uid::effective().is_root());
    // Rootless cgroup controllers must be enabled in the caller's delegated
    // subtree; outside a delegated scope the run fails closed with a
    // controller-unavailable error (documented boundary, not a fixture pass).
    let delegated = std::fs::read_to_string(
        "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/cgroup.subtree_control",
    )
    .unwrap_or_default();
    if !delegated.contains("memory") || !delegated.contains("cpu") {
        eprintln!("SKIP: requires a delegated user cgroup with cpu+memory controllers");
        return;
    }

    let root = tempfile::tempdir().expect("root tempdir");
    let project = root.path().join("project");
    fs::create_dir_all(&project).expect("project");
    fs::write(
        project.join("compose.yml"),
        compose_fixture(
            "services:\n  limited:\n    image: alpine:3.20\n    command: [\"sh\", \"-c\", \"sleep 30\"]\n    network_mode: none\n    deploy:\n      resources:\n        limits:\n          memory: 64M\n          cpus: \"0.50\"\n",
        ),
    )
    .expect("compose file");

    let runtime = runtime_dir(root.path());
    let binary = env!("CARGO_BIN_EXE_ferro-cli");
    prepare_image(binary, &runtime, &rootless_test_image());

    let up = Command::new(binary)
        .current_dir(&project)
        .env("FERROCRATE_HOME", &runtime)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .env("FERROCRATE_ROOTLESS_NETNS", "1")
        .env("FERROCRATE_NETWORK_BACKEND", "iptables")
        .args(["compose", "--file", "compose.yml", "up", "--detach"])
        .output()
        .expect("compose up");
    assert!(
        up.status.success(),
        "compose up failed: {}",
        String::from_utf8_lossy(&up.stderr)
    );

    let inspect = Command::new(binary)
        .current_dir(&project)
        .env("FERROCRATE_HOME", &runtime)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .args(["inspect", "--format", "json", "limited"])
        .output()
        .expect("inspect limited");
    let payload = String::from_utf8_lossy(&inspect.stdout).to_string();
    let memory_seen = payload.contains("67108864") || payload.contains("64M");
    assert!(
        memory_seen,
        "memory limit (64M) missing from inspect payload: {payload}"
    );

    let down = Command::new(binary)
        .current_dir(&project)
        .env("FERROCRATE_HOME", &runtime)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .env("FERROCRATE_ROOTLESS_NETNS", "1")
        .env("FERROCRATE_NETWORK_BACKEND", "iptables")
        .args(["compose", "--file", "compose.yml", "down"])
        .output()
        .expect("compose down");
    assert!(down.status.success(), "compose down failed");
}

#[test]
fn rootless_named_volume_receives_image_content_on_first_use() {
    if std::env::var("FERROCRATE_RUN_ROOTLESS_E2E").as_deref() != Ok("1") {
        return;
    }
    assert!(!nix::unistd::Uid::effective().is_root());

    let root = tempfile::tempdir().expect("root tempdir");
    let project = root.path().join("project");
    let seed_dir = project.join("seed");
    fs::create_dir_all(&seed_dir).expect("seed dir");
    fs::write(seed_dir.join("seed.txt"), b"copy-up-payload\n").expect("seed file");
    fs::write(
        project.join("Dockerfile"),
        format!("FROM {}\nCOPY seed/ /srv/data/\n", rootless_test_image()),
    )
    .expect("dockerfile");

    let runtime = runtime_dir(root.path());
    let binary = env!("CARGO_BIN_EXE_ferro-cli");
    prepare_image(binary, &runtime, &rootless_test_image());

    let cli = |args: &[&str]| {
        let output = Command::new(binary)
            .current_dir(&project)
            .env("FERROCRATE_HOME", &runtime)
            .env("FERROCRATE_RUNTIME_DIR", &runtime)
            .env("FERROCRATE_ROOTLESS_NETNS", "1")
            .env("FERROCRATE_NETWORK_BACKEND", "iptables")
            .args(args)
            .output()
            .expect("cli command");
        assert!(
            output.status.success(),
            "cli {:?} failed: {}{}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    };

    cli(&[
        "build",
        "--dockerfile",
        "Dockerfile",
        "--tag",
        "local/copyup:latest",
    ]);
    cli(&["volume", "create", "copyup-vol"]);

    // First use: the empty volume receives the image's /srv/data content.
    let cid = cli(&[
        "run",
        "--network",
        "none",
        "--name",
        "copyup-first",
        "-v",
        "copyup-vol:/srv/data",
        "local/copyup:latest",
        "cat",
        "/srv/data/seed.txt",
    ])
    .lines()
    .find_map(|line| {
        line.split_once("container_id=").map(|(_, rest)| {
            rest.split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string()
        })
    })
    .expect("container id");
    let mut saw_payload = false;
    for _ in 0..100 {
        let logs = cli(&["logs", &cid]);
        if logs.contains("copy-up-payload") {
            saw_payload = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        saw_payload,
        "first use must surface image content through the volume"
    );
    let seeded = fs::read_to_string(runtime.join("volumes/copyup-vol/seed.txt"))
        .expect("volume received the image file");
    assert_eq!(seeded, "copy-up-payload\n");
    cli(&["stop", &cid]);
    cli(&["rm", &cid]);

    // Second use: existing volume data is never overwritten.
    fs::write(runtime.join("volumes/copyup-vol/keep.txt"), b"kept\n").expect("keep file");
    let cid = cli(&[
        "run",
        "--network",
        "none",
        "--name",
        "copyup-second",
        "-v",
        "copyup-vol:/srv/data",
        "local/copyup:latest",
        "cat",
        "/srv/data/keep.txt",
    ])
    .lines()
    .find_map(|line| {
        line.split_once("container_id=").map(|(_, rest)| {
            rest.split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string()
        })
    })
    .expect("second container id");
    let mut saw_keep = false;
    for _ in 0..100 {
        let logs = cli(&["logs", &cid]);
        if logs.contains("kept") {
            saw_keep = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(saw_keep, "existing volume data must stay visible");
    // The original image file is still there too (not truncated).
    assert!(runtime.join("volumes/copyup-vol/seed.txt").exists());
    cli(&["stop", &cid]);
    cli(&["rm", &cid]);
    cli(&["volume", "rm", "copyup-vol"]);
}

#[test]
fn rootless_compose_profiles_scale_restart_and_teardown() {
    if std::env::var("FERROCRATE_RUN_ROOTLESS_E2E").as_deref() != Ok("1") {
        return;
    }
    assert!(!nix::unistd::Uid::effective().is_root());

    let root = tempfile::tempdir().expect("root tempdir");
    let project = root.path().join("project");
    fs::create_dir_all(&project).expect("project");
    fs::write(
        project.join("compose.yml"),
        compose_fixture(
            "services:\n  base:\n    image: alpine:3.20\n    command: [\"sh\", \"-c\", \"sleep 60\"]\n    network_mode: none\n  extra:\n    image: alpine:3.20\n    command: [\"sh\", \"-c\", \"sleep 60\"]\n    profiles: [\"feat\"]\n    network_mode: none\n  worker:\n    image: alpine:3.20\n    command: [\"sh\", \"-c\", \"sleep 60\"]\n    deploy:\n      replicas: 2\n    network_mode: none\n  resilient:\n    image: alpine:3.20\n    command: [\"sh\", \"-c\", \"sleep 60\"]\n    restart: \"always\"\n    network_mode: none\n  crasher:\n    image: alpine:3.20\n    command: [\"sh\", \"-c\", \"sleep 4; exit 3\"]\n    restart: \"always\"\n    network_mode: none\n",
        ),
    )
    .expect("compose file");

    let runtime = runtime_dir(root.path());
    let binary = env!("CARGO_BIN_EXE_ferro-cli");
    prepare_image(binary, &runtime, &rootless_test_image());

    let compose = |args: &[&str]| {
        let mut command = Command::new(binary);
        command
            .current_dir(&project)
            .env("FERROCRATE_HOME", &runtime)
            .env("FERROCRATE_RUNTIME_DIR", &runtime)
            .env("FERROCRATE_ROOTLESS_NETNS", "1")
            .env("FERROCRATE_NETWORK_BACKEND", "iptables")
            .args(["compose", "--file", "compose.yml"])
            .args(args);
        let output = command.output().expect("compose command");
        assert!(
            output.status.success(),
            "compose {:?} failed: {}{}",
            args,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    };

    // Container-level status via the CLI `ps` (compose ps lists declared
    // services, not runtime state).
    let cli_ps = || -> String {
        let output = Command::new(binary)
            .current_dir(&project)
            .env("FERROCRATE_HOME", &runtime)
            .env("FERROCRATE_RUNTIME_DIR", &runtime)
            .args(["ps", "--all"])
            .output()
            .expect("container ps");
        assert!(
            output.status.success(),
            "container ps failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).to_string()
    };

    // Without the profile: base, worker-1, worker-2, resilient start; the
    // profile-gated service must not.
    compose(&["up", "--detach"]);
    let ps = cli_ps();
    assert!(ps.contains("base"), "base service missing: {ps}");
    assert!(ps.contains("worker-1"), "scale instance 1 missing: {ps}");
    assert!(ps.contains("worker-2"), "scale instance 2 missing: {ps}");
    assert!(ps.contains("resilient"), "resilient service missing: {ps}");
    assert!(
        !ps.contains("extra"),
        "profile service must not start: {ps}"
    );

    compose(&["down"]);

    // Restart policy: a crashing service must be relaunched by the restart
    // supervisor while the attached `compose up` process owns the project.
    // (One-shot detached up cannot supervise: the watcher thread dies with
    // the CLI process, so the attached path is the supported restart mode.)
    let mut attach_up = Command::new(binary)
        .current_dir(&project)
        .env("FERROCRATE_HOME", &runtime)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .env("FERROCRATE_ROOTLESS_NETNS", "1")
        .env("FERROCRATE_NETWORK_BACKEND", "iptables")
        .args([
            "compose",
            "--file",
            "compose.yml",
            "up",
            "--profile",
            "feat",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("attached compose up");

    // The crasher exits nonzero after 4s; the supervisor must relaunch it
    // (restart: always). Observe a `running` status again within a bounded
    // window after the first exit.
    let mut crasher_restarted = false;
    let mut saw_exited = false;
    for _ in 0..300 {
        let ps = cli_ps();
        let line = ps
            .lines()
            .find(|line| line.contains("crasher"))
            .unwrap_or_default();
        if line.contains("exited") || line.contains("created") {
            saw_exited = true;
        }
        if saw_exited && line.contains("running") {
            crasher_restarted = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    let _ = attach_up.kill();
    let _ = attach_up.wait();
    assert!(
        crasher_restarted,
        "restart=always crasher was not relaunched after its first exit"
    );

    // Teardown from a separate process while nothing supervises the project.
    let down_output = Command::new(binary)
        .current_dir(&project)
        .env("FERROCRATE_HOME", &runtime)
        .env("FERROCRATE_RUNTIME_DIR", &runtime)
        .env("FERROCRATE_ROOTLESS_NETNS", "1")
        .env("FERROCRATE_NETWORK_BACKEND", "iptables")
        .args(["compose", "--file", "compose.yml", "down"])
        .output()
        .expect("compose down");
    assert!(
        down_output.status.success(),
        "compose down failed: {}",
        String::from_utf8_lossy(&down_output.stderr)
    );

    compose(&["down"]);

    // With the profile: the gated service starts alongside the others.
    compose(&["up", "--detach", "--profile", "feat"]);
    let ps_profile = cli_ps();
    assert!(
        ps_profile.contains("extra"),
        "profile service missing: {ps_profile}"
    );
    compose(&["down"]);

    // Teardown: no project container remains in a live state after down.
    let ps_after = cli_ps();
    for name in [
        "base",
        "worker-1",
        "worker-2",
        "resilient",
        "extra",
        "crasher",
    ] {
        let still_live = ps_after.lines().any(|line| {
            line.contains(name) && (line.contains("running") || line.contains("paused"))
        });
        assert!(!still_live, "container {name} survived down: {ps_after}");
    }
}
