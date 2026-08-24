#![cfg(target_os = "linux")]

#![cfg(unix)]

//! Opt-in production-kernel qualification for the authenticated
//! controller -> agent -> netd path using two isolated Linux namespaces.

use base64::Engine;
use ed25519_dalek::SigningKey;
use ferro_core::authorization::helper_grant::{GrantIssuer, ResourceBinding};
use ferro_core::authorization::{AuthorizationMode, AuthorizationServiceMode};
use ferro_mgr::agent::netd_client::UnixNetdClient;
use ferro_mgr::agent::netd_sequence::{NetdSequence, SequenceValue};
use ferro_mgr::agent::{Agent, StateStore};
use ferro_mgr::controller_authorization::{ControllerGrantIssuer, ControllerPolicy};
use ferro_mgr::desired_state::DesiredStateBuilder;
use ferro_mgr::proto::{DesiredState, OverlayState, Peer};
use ferro_netd::grants::{GrantLedger, GrantVerifier};
use ferro_netd::policy::Policy;
use ferro_netd::server::NetdServer;
use ferro_netd::transport::serve_authenticated_one;
use nix::sched::{setns, CloneFlags};
use std::fs;
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

fn run(args: &[&str]) {
    let status = Command::new(args[0]).args(&args[1..]).status().unwrap();
    assert!(status.success(), "command failed: {args:?}");
}

fn output(args: &[&str]) -> String {
    let result = Command::new(args[0]).args(&args[1..]).output().unwrap();
    assert!(result.status.success(), "command failed: {args:?}");
    String::from_utf8(result.stdout).unwrap().trim().to_owned()
}

fn output_with_stdin(args: &[&str], input: &str) -> String {
    use std::io::Write;
    let mut child = Command::new(args[0])
        .args(&args[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success());
    String::from_utf8(result.stdout).unwrap().trim().to_owned()
}

fn netns_path(name: &str) -> PathBuf {
    PathBuf::from("/run/netns").join(name)
}

fn spawn_netd(
    namespace: String,
    node_id: &'static str,
    socket: PathBuf,
    key_path: PathBuf,
    helper_public: ed25519_dalek::VerifyingKey,
    manager_public: String,
    directory: PathBuf,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let ns = fs::File::open(netns_path(&namespace)).unwrap();
        setns(ns.as_fd(), CloneFlags::CLONE_NEWNET).unwrap();
        let policy = Policy::new("cluster-a".into(), node_id.into(), &manager_public).unwrap();
        let verifier = GrantVerifier::new(
            helper_public,
            "runtime",
            "key-1",
            "boot-a",
            GrantLedger::open(directory.join("grants.json")).unwrap(),
        );
        let mut server = NetdServer::with_wireguard(0, policy, key_path, 51820)
            .with_authorization_identity(
                AuthorizationServiceMode::new(AuthorizationMode::Shadow, Some([9; 32])).unwrap(),
                "boot-a",
            )
            .with_grants(verifier)
            .load_journal(directory.join("ownership.json"))
            .unwrap();
        let listener = UnixListener::bind(socket).unwrap();
        let executable = fs::read_link(format!("/proc/{}/exe", std::process::id())).unwrap();
        serve_authenticated_one(&listener, &mut server, 0, &executable, 101).unwrap();
    })
}

fn make_desired(
    builder: &DesiredStateBuilder,
    peer_node: &str,
    peer_key: Vec<u8>,
    endpoint: &str,
    address: &str,
    allowed_ip: &str,
) -> DesiredState {
    let lease = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 3_600;
    builder.snapshot(
        1,
        vec![OverlayState {
            overlay_id: "wg0".into(),
            routes: vec![allowed_ip.into()],
            peers: vec![Peer {
                node_id: peer_node.into(),
                public_key: peer_key,
                endpoint: endpoint.into(),
                allowed_ips: vec![allowed_ip.into()],
            }],
            wireguard: Some(true),
            addresses: vec![address.into()],
        }],
        lease,
    )
}

fn run_agent(
    node_id: &str,
    desired: DesiredState,
    bundle: Vec<u8>,
    socket: &Path,
    directory: &Path,
    desired_key: &SigningKey,
    envelope_key: &SigningKey,
) {
    let sequence = NetdSequence::open(
        directory.join("sequence.json"),
        SequenceValue {
            epoch: 0,
            revision: 0,
        },
    )
    .unwrap();
    let agent = Agent::new_enforcing(
        "cluster-a",
        desired_key.verifying_key().to_bytes().to_vec(),
        StateStore::new(directory.join("agent-state.json")),
        UnixNetdClient::new(socket)
            .with_node_id(node_id)
            .with_authorization_identity(
                AuthorizationServiceMode::new(AuthorizationMode::Shadow, Some([9; 32])).unwrap(),
                "boot-a",
            )
            .with_transport_signing_key(envelope_key.clone()),
    )
    .unwrap()
    .with_netd_sequence(sequence)
    .with_netd_envelope_signer(envelope_key.clone());
    assert_eq!(
        agent.reconcile_with_bundle(desired, &bundle, 101).unwrap(),
        1
    );
}

#[test]
#[ignore]
fn authenticated_two_namespace_wireguard_path() {
    assert_eq!(nix::unistd::geteuid().as_raw(), 0, "root is required");
    let directory = tempfile::tempdir_in("/run").unwrap();
    assert!(
        directory.path().starts_with("/run/"),
        "qualification runtime must use tmpfs-backed /run: {}",
        directory.path().display()
    );
    let nonce = format!(
        "{}{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let ns_a = format!("fc-a-{nonce}");
    let ns_b = format!("fc-b-{nonce}");
    run(&["ip", "netns", "add", &ns_a]);
    run(&["ip", "netns", "add", &ns_b]);
    struct Cleanup(String, String);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = Command::new("ip")
                .args(["netns", "delete", &self.0])
                .status();
            let _ = Command::new("ip")
                .args(["netns", "delete", &self.1])
                .status();
        }
    }
    let _cleanup = Cleanup(ns_a.clone(), ns_b.clone());
    let va = format!("va{}", std::process::id());
    let vb = format!("vb{}", std::process::id());
    run(&[
        "ip", "link", "add", &va, "type", "veth", "peer", "name", &vb,
    ]);
    run(&["ip", "link", "set", &va, "netns", &ns_a]);
    run(&["ip", "link", "set", &vb, "netns", &ns_b]);
    for ns in [&ns_a, &ns_b] {
        run(&["ip", "-n", ns, "link", "set", "lo", "up"]);
    }
    run(&[
        "ip",
        "-n",
        &ns_a,
        "addr",
        "add",
        "10.200.0.1/24",
        "dev",
        &va,
    ]);
    run(&[
        "ip",
        "-n",
        &ns_b,
        "addr",
        "add",
        "10.200.0.2/24",
        "dev",
        &vb,
    ]);
    run(&["ip", "-n", &ns_a, "link", "set", &va, "up"]);
    run(&["ip", "-n", &ns_b, "link", "set", &vb, "up"]);

    let key_a = output(&["wg", "genkey"]);
    let key_b = output(&["wg", "genkey"]);
    let pub_a = output_with_stdin(&["wg", "pubkey"], &key_a);
    let pub_b = output_with_stdin(&["wg", "pubkey"], &key_b);
    let key_path_a = directory.path().join("key-a");
    let key_path_b = directory.path().join("key-b");
    fs::write(&key_path_a, format!("{key_a}\n")).unwrap();
    fs::write(&key_path_b, format!("{key_b}\n")).unwrap();
    for path in [&key_path_a, &key_path_b] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let helper = SigningKey::from_bytes(&[8; 32]);
    let helper_path = directory.path().join("helper.key");
    fs::write(&helper_path, helper.to_bytes()).unwrap();
    fs::set_permissions(&helper_path, fs::Permissions::from_mode(0o600)).unwrap();
    let envelope = SigningKey::from_bytes(&[7; 32]);
    let desired_key = SigningKey::from_bytes(&[4; 32]);
    let manager_public =
        base64::engine::general_purpose::STANDARD.encode(envelope.verifying_key().to_bytes());
    let builder = DesiredStateBuilder::new("cluster-a", 2, desired_key.to_bytes().to_vec());
    let policy = ControllerPolicy::new(
        ["node-a".into(), "node-b".into()],
        [(
            "wg0".into(),
            ResourceBinding::new("123e4567-e89b-12d3-a456-426614174000", 7).unwrap(),
        )],
    );
    let grant_issuer = |policy: ControllerPolicy| {
        ControllerGrantIssuer::new(
            GrantIssuer::from_key_file("key-1", &helper_path, 0).unwrap(),
            envelope.clone(),
            "runtime",
            "boot-a",
            policy,
        )
    };
    let desired_a = make_desired(
        &builder,
        "node-b",
        base64::engine::general_purpose::STANDARD
            .decode(pub_b)
            .unwrap(),
        "10.200.0.2:51820",
        "10.99.0.1/24",
        "10.99.0.2/32",
    );
    let desired_b = make_desired(
        &builder,
        "node-a",
        base64::engine::general_purpose::STANDARD
            .decode(pub_a)
            .unwrap(),
        "10.200.0.1:51820",
        "10.99.0.2/24",
        "10.99.0.1/32",
    );
    let ops_a = grant_issuer(policy.clone())
        .issue_exact_diff(&desired_a, "node-a", &[], u64::MAX - 60_000)
        .unwrap();
    let ops_b = grant_issuer(policy)
        .issue_exact_diff(&desired_b, "node-b", &[], u64::MAX - 60_000)
        .unwrap();
    let bundle_a = builder
        .authorization_bundle(&desired_a, "node-a", ops_a)
        .unwrap();
    let bundle_b = builder
        .authorization_bundle(&desired_b, "node-b", ops_b)
        .unwrap();
    let dir_a = directory.path().join("a");
    let dir_b = directory.path().join("b");
    fs::create_dir(&dir_a).unwrap();
    fs::create_dir(&dir_b).unwrap();
    let socket_a = directory.path().join("a.sock");
    let socket_b = directory.path().join("b.sock");
    let server_a = spawn_netd(
        ns_a.clone(),
        "node-a",
        socket_a.clone(),
        key_path_a,
        helper.verifying_key(),
        manager_public.clone(),
        dir_a.clone(),
    );
    let server_b = spawn_netd(
        ns_b.clone(),
        "node-b",
        socket_b.clone(),
        key_path_b,
        helper.verifying_key(),
        manager_public,
        dir_b.clone(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while (!socket_a.exists() || !socket_b.exists()) && std::time::Instant::now() < deadline {
        thread::yield_now();
    }
    assert!(
        socket_a.exists() && socket_b.exists(),
        "netd sockets did not become ready"
    );
    run_agent(
        "node-a",
        desired_a,
        bundle_a,
        &socket_a,
        &dir_a,
        &desired_key,
        &envelope,
    );
    run_agent(
        "node-b",
        desired_b,
        bundle_b,
        &socket_b,
        &dir_b,
        &desired_key,
        &envelope,
    );
    server_a.join().unwrap();
    server_b.join().unwrap();
    run(&[
        "ip",
        "netns",
        "exec",
        &ns_a,
        "ping",
        "-c",
        "2",
        "-W",
        "3",
        "10.99.0.2",
    ]);
    run(&[
        "ip",
        "netns",
        "exec",
        &ns_b,
        "ping",
        "-c",
        "2",
        "-W",
        "3",
        "10.99.0.1",
    ]);
}
