#![cfg(target_os = "linux")]

use ed25519_dalek::{Signer, SigningKey};
use ferro_core::authorization::{
    gate::AuthorizationGate, policy::PolicyStore, Action, PrincipalResolver,
};
use ferro_core::runtime::ContainerRuntime;
use ferro_core::witness::{JournalConfig, JournalMode, WitnessJournal};
use ferro_cri::runtime::image_service_client::ImageServiceClient;
use ferro_cri::runtime::runtime_service_client::RuntimeServiceClient;
use ferro_cri::runtime::{
    ContainerConfig, ContainerStatsRequest, ContainerStatusRequest, CreateContainerRequest,
    ImageFsInfoRequest, ListContainerStatsRequest, ListContainersRequest, ListImagesRequest,
    ListPodSandboxRequest, PodSandboxConfig, PodSandboxMetadata, PodSandboxStatusRequest,
    RemoveContainerRequest, RemovePodSandboxRequest, RunPodSandboxRequest, StartContainerRequest,
    StatusRequest, StopContainerRequest, StopPodSandboxRequest, VersionRequest,
};
use ferro_cri::runtime::{ImageSpec, PullImageRequest, RemoveImageRequest};
use ferro_cri::server::{
    CriDelegationClaims, CriDelegationVerifier, CriIdentityPolicy, DelegationAssertion,
    DelegationTrustKey,
};
use httptest::matchers::request;
use httptest::responders::status_code;
use httptest::{Expectation, Server};
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use std::io::Cursor;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tar::{Builder, Header};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

#[path = "../../tests/support/qualification_fixture.rs"]
mod qualification_fixture;

static ENV_LOCK: Mutex<()> = Mutex::new(());

async fn wait_for_socket(path: &std::path::Path) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if path.exists() && UnixStream::connect(path).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("CRI socket did not appear: {}", path.display());
}

fn spawn_cri_process(runtime: &std::path::Path, socket: &std::path::Path) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_ferro-cri"))
        .env("FERROCRATE_RUNTIME_DIR", runtime)
        .env("FERROCRATE_CRI_SOCKET", socket)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn CRI daemon")
}

fn running_as_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim() == "0")
        .unwrap_or(false)
}

fn set_crash_point(point: &str) {
    unsafe {
        std::env::set_var(
            "FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE",
            "cri-fault-injection",
        );
        std::env::set_var("FERROCRATE_CRI_TEST_CRASH_POINT", point);
    }
}

fn clear_crash_point() {
    unsafe {
        std::env::remove_var("FERROCRATE_CRI_TEST_CRASH_POINT");
    }
}

fn clear_crash_fixture() {
    unsafe {
        std::env::remove_var("FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE");
    }
}

async fn wait_for_cri_crash(daemon: &mut std::process::Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if daemon.try_wait().expect("poll CRI crash").is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        daemon.try_wait().expect("wait for CRI crash").is_some(),
        "CRI daemon did not terminate at the injected crash point"
    );
}

fn read_cri_state(
    runtime: &Path,
    kind: &str,
) -> std::collections::BTreeMap<String, serde_json::Value> {
    let payload: Vec<u8> = rusqlite::Connection::open(runtime.join("cri-state.sqlite"))
        .expect("open CRI state")
        .query_row(
            "SELECT payload FROM cri_state WHERE kind=?1",
            rusqlite::params![kind],
            |row| row.get(0),
        )
        .expect("read CRI state kind");
    serde_json::from_slice(&payload).expect("decode CRI state kind")
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn cri_wire_delegation_accepts_once_and_rejects_replay_expiry_and_tampering() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    let qualification_before = ferro_core::observability::authorization_metrics_snapshot();
    let runtime = tempfile::tempdir().expect("runtime tempdir");
    let socket = runtime.path().join("delegated-cri.sock");
    unsafe {
        std::env::set_var("FERROCRATE_RUNTIME_DIR", runtime.path());
    }

    let registry = Server::run();
    let manifest = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:46b68ac1696c3870d537f376868d9402400de28587e345264a77b65da09669be","size":13},"layers":[]}"#;
    registry.expect(
        Expectation::matching(request::method_path(
            "GET",
            "/v2/library/alpine/manifests/latest",
        ))
        .times(2)
        .respond_with(status_code(200).body(manifest)),
    );
    let manifest_digest = "sha256:6ee1fcf5d0cc4a59012ec52e3e5a99b2bec3336099150b110fa8e992d208b93c";
    registry.expect(
        Expectation::matching(request::method_path(
            "GET",
            format!("/v2/library/alpine/manifests/{manifest_digest}"),
        ))
        .times(2)
        .respond_with(status_code(200).body(manifest)),
    );
    registry.expect(Expectation::matching(request::method_path(
        "GET", "/v2/library/alpine/blobs/sha256:46b68ac1696c3870d537f376868d9402400de28587e345264a77b65da09669be",
    )).respond_with(status_code(200).body("{\"config\":{}}")));

    let (peer, _other) = StdUnixStream::pair().unwrap();
    let transport = PrincipalResolver::from_cri_peer_credentials(&peer).unwrap();
    let subject = transport.principal().id().as_str().to_owned();
    let signing = SigningKey::from_bytes(&[23; 32]);
    let policy_path = runtime.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        "schema_version = 1\ngeneration = 1\nmode = \"shadow\"\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&policy_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let gate = Arc::new(AuthorizationGate::new(Arc::new(
        PolicyStore::load(&policy_path).unwrap(),
    )));
    let journal = Arc::new(
        WitnessJournal::open(JournalConfig::new(
            runtime.path().join("witness"),
            [41; 16],
            JournalMode::Required,
        ))
        .unwrap(),
    );
    let control_runtime = Arc::new(
        ContainerRuntime::new_with_authorization(runtime.path(), gate, Some(journal)).unwrap(),
    );
    let (_, runtime_policy_digest, runtime_boot) =
        control_runtime.delegation_authority_binding().unwrap();
    let mismatched = CriDelegationVerifier::open(
        vec![DelegationTrustKey::developer(
            "issuer",
            "wire-key",
            signing.verifying_key(),
        )],
        "wire",
        runtime_boot.clone(),
        [99; 32],
        runtime.path().join("mismatch-replay"),
    )
    .unwrap();
    let mismatch_error = ferro_cri::server::serve_with_identity_policy(
        runtime.path().join("must-not-bind.sock"),
        CriIdentityPolicy::with_signed_verifier("wire", Arc::new(mismatched)),
        Arc::clone(&control_runtime),
    )
    .await
    .expect_err("policy mismatch must fail before serving");
    assert!(mismatch_error.to_string().contains("policy digest"));
    assert!(!runtime.path().join("must-not-bind.sock").exists());
    let verifier = CriDelegationVerifier::open(
        vec![DelegationTrustKey::developer(
            "issuer",
            "wire-key",
            signing.verifying_key(),
        )],
        "wire",
        runtime_boot.clone(),
        runtime_policy_digest,
        runtime.path().join("replay"),
    )
    .unwrap();
    let policy = CriIdentityPolicy::with_signed_verifier("wire", Arc::new(verifier));
    let socket_for_server = socket.clone();
    let runtime_for_server = Arc::clone(&control_runtime);
    let server = tokio::spawn(async move {
        let _ = ferro_cri::server::serve_with_identity_policy(
            socket_for_server,
            policy,
            runtime_for_server,
        )
        .await;
    });
    wait_for_socket(&socket).await;
    let channel = connect_channel(socket.clone()).await;
    let mut client = ImageServiceClient::new(channel);
    let image = format!("{}/library/alpine", registry.addr());
    let resource = ferro_core::image_tagging::canonicalize_reference(&image).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let signed = |nonce: &str, deadline: u64, action: Action| {
        let claims = CriDelegationClaims::new(
            "issuer",
            "wire-key",
            subject.clone(),
            "wire",
            "delegated-user",
            vec![action],
            vec![resource.clone()],
            nonce,
            deadline,
            runtime_boot.clone(),
            runtime_policy_digest,
        )
        .unwrap();
        DelegationAssertion::new(
            claims.clone(),
            signing.sign(&claims.signing_bytes()).to_bytes(),
        )
        .unwrap()
    };
    let invoke = |assertion: &DelegationAssertion| {
        let mut request = tonic::Request::new(PullImageRequest {
            image: Some(ImageSpec {
                image: image.clone(),
            }),
            auth: Default::default(),
            sandbox_config: String::new(),
        });
        request.metadata_mut().insert_bin(
            "ferro-delegation-bin",
            tonic::metadata::MetadataValue::from_bytes(&assertion.wire_bytes()),
        );
        request
    };

    let token = signed("wire-once", now + 60_000, Action::ImagePull);
    client
        .pull_image(invoke(&token))
        .await
        .expect("valid wire delegation");
    let delete = signed("wire-delete", now + 60_000, Action::ImageDelete);
    let mut delete_request = tonic::Request::new(RemoveImageRequest {
        image: Some(ImageSpec {
            image: resource.clone(),
        }),
    });
    delete_request.metadata_mut().insert_bin(
        "ferro-delegation-bin",
        tonic::metadata::MetadataValue::from_bytes(&delete.wire_bytes()),
    );
    client
        .remove_image(delete_request)
        .await
        .expect("valid delegated remove");
    client
        .pull_image(PullImageRequest {
            image: Some(ImageSpec {
                image: image.clone(),
            }),
            auth: Default::default(),
            sandbox_config: String::new(),
        })
        .await
        .expect("authenticated transport principal is authoritative by default");
    assert_eq!(
        client.pull_image(invoke(&token)).await.unwrap_err().code(),
        tonic::Code::PermissionDenied
    );
    let expired = signed("wire-expired", now.saturating_sub(1), Action::ImagePull);
    assert_eq!(
        client
            .pull_image(invoke(&expired))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );
    let mut tampered = signed("wire-tampered", now + 60_000, Action::ImagePull).wire_bytes();
    *tampered.last_mut().unwrap() ^= 1;
    let mut tampered_request = tonic::Request::new(PullImageRequest {
        image: Some(ImageSpec { image }),
        auth: Default::default(),
        sandbox_config: String::new(),
    });
    tampered_request.metadata_mut().insert_bin(
        "ferro-delegation-bin",
        tonic::metadata::MetadataValue::from_bytes(&tampered),
    );
    assert_eq!(
        client
            .pull_image(tampered_request)
            .await
            .unwrap_err()
            .code(),
        tonic::Code::PermissionDenied
    );

    server.abort();
    let _ = server.await;

    ferro_core::observability::persist_authorization_fixture_evidence(
        "cri",
        qualification_before,
        ferro_core::observability::authorization_metrics_snapshot(),
    )
    .expect("persist CRI qualification evidence");
    unsafe {
        std::env::remove_var("FERROCRATE_RUNTIME_DIR");
    }
}

/// Exercises the public tonic-over-UDS CRI mutation path under every rollout
/// mode.  This deliberately starts the production server and talks to it with
/// the generated client; calling `SurfaceAuthorization` directly here would
/// not establish a CRI compatibility claim.
#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn public_cri_pull_preserves_disabled_shadow_and_enforce_contracts() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    let running_as_root = Command::new("id")
        .arg("-u")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim() == "0")
        .unwrap_or(false);

    for mode in ["disabled", "shadow", "enforce"] {
        let before = ferro_core::observability::authorization_metrics_snapshot();
        let runtime = qualification_fixture::configured_runtime(mode);
        let socket = runtime.path().join(format!("cri-{mode}.sock"));
        unsafe {
            std::env::set_var("FERROCRATE_RUNTIME_DIR", runtime.path());
        }

        let registry = Server::run();
        let manifest = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:46b68ac1696c3870d537f376868d9402400de28587e345264a77b65da09669be","size":13},"layers":[]}"#;
        registry.expect(
            Expectation::matching(request::method_path(
                "GET",
                "/v2/library/alpine/manifests/latest",
            ))
            .times(0..=1)
            .respond_with(status_code(200).body(manifest)),
        );
        let manifest_digest =
            "sha256:6ee1fcf5d0cc4a59012ec52e3e5a99b2bec3336099150b110fa8e992d208b93c";
        registry.expect(
            Expectation::matching(request::method_path(
                "GET",
                format!("/v2/library/alpine/manifests/{manifest_digest}"),
            ))
            .times(0..=1)
            .respond_with(status_code(200).body(manifest)),
        );
        registry.expect(Expectation::matching(request::method_path(
            "GET",
            "/v2/library/alpine/blobs/sha256:46b68ac1696c3870d537f376868d9402400de28587e345264a77b65da09669be",
        )).times(0..=1).respond_with(status_code(200).body("{\"config\":{}}")));

        let socket_for_server = socket.clone();
        let server = tokio::spawn(async move {
            let _ = ferro_cri::server::serve(socket_for_server).await;
        });
        wait_for_socket(&socket).await;

        let image = format!("{}/library/alpine", registry.addr());
        let mut client = ImageServiceClient::new(connect_channel(socket.clone()).await);
        let result = client
            .pull_image(PullImageRequest {
                image: Some(ImageSpec {
                    image: image.clone(),
                }),
                auth: Default::default(),
                sandbox_config: String::new(),
            })
            .await;

        let canonical = ferro_core::image_tagging::canonicalize_reference(&image)
            .expect("canonical image reference");
        if mode == "enforce" && !running_as_root {
            let error = result.expect_err("enforce must deny before CRI mutation");
            assert_eq!(error.code(), tonic::Code::PermissionDenied);
            assert!(error.message().contains("PolicyDenied"));
        } else {
            // The qualification fixture uses the peer's resolved role. A
            // rootful socket is an administrator principal, so enforce mode
            // must allow this ordinary image pull; non-root developers remain
            // denied and are checked above.
            let response = result
                .expect("authorized CRI pull must succeed")
                .into_inner();
            assert_eq!(response.image_ref, canonical);
        }

        drop(client);
        server.abort();
        let _ = server.await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        let store = ferro_core::image_store::LocalImageStore::open(runtime.path().join("images"))
            .expect("open production image store");
        assert_eq!(
            store
                .resolve_reference(&canonical)
                .expect("inspect image store")
                .is_some(),
            mode != "enforce" || running_as_root,
            "denied enforce pull must leave the public CRI image store unchanged"
        );
        ferro_core::observability::persist_authorization_fixture_evidence(
            &format!("cri-{mode}"),
            before,
            ferro_core::observability::authorization_metrics_snapshot(),
        )
        .expect("persist per-mode CRI qualification evidence");
    }
    unsafe {
        std::env::remove_var("FERROCRATE_RUNTIME_DIR");
    }
}

async fn connect_channel(socket_path: std::path::PathBuf) -> Channel {
    Endpoint::try_from("http://[::]:50051")
        .expect("endpoint")
        .connect_with_connector(service_fn(move |_| {
            let socket_path = socket_path.clone();
            async move { UnixStream::connect(socket_path).await.map(TokioIo::new) }
        }))
        .await
        .expect("connect channel")
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn cri_socket_serves_runtime_and_image_requests() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    let runtime = tempfile::tempdir().expect("runtime tempdir");
    let socket = runtime.path().join("cri.sock");

    unsafe {
        std::env::set_var("FERROCRATE_RUNTIME_DIR", runtime.path());
    }

    let socket_for_server = socket.clone();
    let server = tokio::spawn(async move {
        let _ = ferro_cri::server::serve(socket_for_server).await;
    });

    wait_for_socket(&socket).await;

    let channel = connect_channel(socket.clone()).await;

    let mut runtime_client = RuntimeServiceClient::new(channel.clone());
    let version = runtime_client
        .version(VersionRequest::default())
        .await
        .expect("version rpc")
        .into_inner();
    assert_eq!(version.runtime_name, "ferrocrate");
    assert_eq!(version.runtime_api_version, "v1");

    let status = runtime_client
        .status(StatusRequest { verbose: true })
        .await
        .expect("status rpc")
        .into_inner();
    assert!(status.status.is_some());
    assert!(status.info.contains_key("runtimeName"));

    let mut image_client = ImageServiceClient::new(channel);
    let listed = image_client
        .list_images(ListImagesRequest {
            filter: String::new(),
        })
        .await
        .expect("list images rpc")
        .into_inner();
    assert!(listed.images.is_empty());

    let fs_info = image_client
        .image_fs_info(ImageFsInfoRequest {})
        .await
        .expect("image fs info rpc")
        .into_inner();
    assert_eq!(fs_info.image_filesystems.len(), 1);
    assert!(fs_info.image_filesystems[0].mountpoint.ends_with("/images"));

    server.abort();
    let _ = server.await;

    unsafe {
        std::env::remove_var("FERROCRATE_RUNTIME_DIR");
    }
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn cri_socket_serves_durable_sandbox_and_container_lifecycle() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    let runtime = tempfile::tempdir().expect("runtime tempdir");
    let socket = runtime.path().join("cri-lifecycle.sock");

    unsafe {
        std::env::set_var("FERROCRATE_RUNTIME_DIR", runtime.path());
    }
    let socket_for_server = socket.clone();
    let server = tokio::spawn(async move {
        let _ = ferro_cri::server::serve(socket_for_server).await;
    });
    wait_for_socket(&socket).await;

    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let sandbox = client
        .run_pod_sandbox(RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "wire-pod".into(),
                    uid: "wire-uid".into(),
                    namespace: "default".into(),
                    attempt: 1,
                }),
                hostname: "wire-pod".into(),
                log_directory: String::new(),
                dns_config: String::new(),
                network_namespace: "none".into(),
            }),
            runtime_handler: String::new(),
        })
        .await
        .expect("run sandbox rpc")
        .into_inner()
        .pod_sandbox_id;
    let listed = client
        .list_pod_sandbox(ListPodSandboxRequest { filter: None })
        .await
        .expect("list sandbox rpc")
        .into_inner();
    assert_eq!(listed.items.len(), 1);
    assert_eq!(listed.items[0].id, sandbox);
    assert_eq!(
        listed.items[0]
            .metadata
            .as_ref()
            .expect("sandbox metadata")
            .name,
        "wire-pod"
    );
    let container = client
        .create_container(CreateContainerRequest {
            pod_sandbox_id: sandbox.clone(),
            config: Some(ContainerConfig {
                metadata_name: "wire-container".into(),
                image: "missing:latest".into(),
                command: vec!["true".into()],
                args: Vec::new(),
                env: Default::default(),
            }),
            sandbox_config: None,
        })
        .await
        .expect("create container rpc")
        .into_inner()
        .container_id;
    let listed = client
        .list_containers(ListContainersRequest { filter: None })
        .await
        .expect("list container rpc")
        .into_inner();
    assert_eq!(listed.containers.len(), 1);
    assert_eq!(listed.containers[0].id, container);
    assert_eq!(
        listed.containers[0]
            .metadata
            .as_ref()
            .expect("container metadata")
            .name,
        "wire-container"
    );
    let stats = client
        .container_stats(ContainerStatsRequest {
            container_id: container.clone(),
        })
        .await
        .expect("container stats rpc")
        .into_inner();
    assert!(stats.stats.expect("stats projection").stats_timestamp > 0);
    let listed_stats = client
        .list_container_stats(ListContainerStatsRequest { filter: None })
        .await
        .expect("list container stats rpc")
        .into_inner();
    assert_eq!(listed_stats.stats.len(), 1);
    assert_eq!(listed_stats.stats[0].id, container);
    assert_eq!(
        client
            .container_status(ContainerStatusRequest {
                container_id: container.clone(),
                verbose: true,
            })
            .await
            .expect("container status rpc")
            .into_inner()
            .status
            .expect("container status")
            .state,
        ferro_cri::runtime::ContainerState::Created as i32
    );
    let start_error = client
        .start_container(StartContainerRequest {
            container_id: container.clone(),
        })
        .await
        .expect_err("missing image must fail over socket");
    assert_eq!(start_error.code(), tonic::Code::Internal);
    client
        .remove_container(RemoveContainerRequest {
            container_id: container,
        })
        .await
        .expect("remove container rpc");
    client
        .stop_pod_sandbox(StopPodSandboxRequest {
            pod_sandbox_id: sandbox.clone(),
        })
        .await
        .expect("stop sandbox rpc");
    client
        .remove_pod_sandbox(RemovePodSandboxRequest {
            pod_sandbox_id: sandbox,
        })
        .await
        .expect("remove sandbox rpc");

    server.abort();
    let _ = server.await;
    unsafe {
        std::env::remove_var("FERROCRATE_RUNTIME_DIR");
    }
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn cri_process_kill_recovers_sqlite_metadata_on_restart() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    let runtime = tempfile::tempdir().expect("runtime tempdir");
    let socket = runtime.path().join("cri-process-restart.sock");
    let mut daemon = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;

    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let sandbox = client
        .run_pod_sandbox(RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "kill-pod".into(),
                    uid: "kill-uid".into(),
                    namespace: "default".into(),
                    attempt: 1,
                }),
                hostname: "kill-pod".into(),
                log_directory: String::new(),
                dns_config: String::new(),
                network_namespace: "none".into(),
            }),
            runtime_handler: String::new(),
        })
        .await
        .expect("run sandbox")
        .into_inner()
        .pod_sandbox_id;
    let container = client
        .create_container(CreateContainerRequest {
            pod_sandbox_id: sandbox.clone(),
            config: Some(ContainerConfig {
                metadata_name: "kill-container".into(),
                image: "missing:latest".into(),
                command: vec!["true".into()],
                args: Vec::new(),
                env: Default::default(),
            }),
            sandbox_config: None,
        })
        .await
        .expect("create container")
        .into_inner()
        .container_id;

    daemon.kill().expect("kill CRI daemon");
    let _ = daemon.wait();
    let mut restarted = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut recovered_client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let status = recovered_client
        .container_status(ContainerStatusRequest {
            container_id: container.clone(),
            verbose: false,
        })
        .await
        .expect("status after process restart")
        .into_inner()
        .status
        .expect("recovered container status");
    assert_eq!(status.id, container);
    assert_eq!(
        status.state,
        ferro_cri::runtime::ContainerState::Created as i32
    );
    recovered_client
        .remove_container(RemoveContainerRequest {
            container_id: container,
        })
        .await
        .expect("remove recovered container");
    recovered_client
        .stop_pod_sandbox(StopPodSandboxRequest {
            pod_sandbox_id: sandbox.clone(),
        })
        .await
        .expect("stop recovered sandbox");
    recovered_client
        .remove_pod_sandbox(RemovePodSandboxRequest {
            pod_sandbox_id: sandbox,
        })
        .await
        .expect("remove recovered sandbox");
    restarted.kill().expect("stop restarted CRI daemon");
    let _ = restarted.wait();
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn cri_rootless_bridge_request_fails_before_kernel_mutation() {
    if nix::unistd::Uid::effective().is_root() {
        return;
    }
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    let runtime = tempfile::tempdir().expect("runtime tempdir");
    let socket = runtime.path().join("cri-rootless-bridge-boundary.sock");
    let mut daemon = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let error = client
        .run_pod_sandbox(RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "rootless-bridge-boundary-pod".into(),
                    uid: "rootless-bridge-boundary-uid".into(),
                    namespace: "default".into(),
                    attempt: 1,
                }),
                hostname: "rootless-bridge-boundary-pod".into(),
                log_directory: String::new(),
                dns_config: String::new(),
                network_namespace: "bridge".into(),
            }),
            runtime_handler: String::new(),
        })
        .await
        .expect_err("rootless CRI bridge must fail closed");
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert!(error.message().contains("rootless CRI bridge sandboxes"));
    daemon.kill().expect("stop CRI daemon");
    let _ = daemon.wait();
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn cri_store_publication_crash_recovers_sandbox_metadata() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    let runtime = tempfile::tempdir().expect("runtime tempdir");
    let socket = runtime
        .path()
        .join("cri-sandbox-store-publication-crash.sock");
    unsafe {
        std::env::set_var(
            "FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE",
            "cri-fault-injection",
        );
        std::env::set_var(
            "FERROCRATE_CRI_TEST_CRASH_POINT",
            "after-sandbox-store-publication",
        );
    }
    let mut daemon = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let _transport_error = client
        .run_pod_sandbox(RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "sandbox-store-crash-pod".into(),
                    uid: "sandbox-store-crash-uid".into(),
                    namespace: "default".into(),
                    attempt: 1,
                }),
                hostname: "sandbox-store-crash-pod".into(),
                log_directory: String::new(),
                dns_config: String::new(),
                network_namespace: "none".into(),
            }),
            runtime_handler: String::new(),
        })
        .await
        .expect_err("fault injection must terminate after sandbox publication");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if daemon.try_wait().expect("poll CRI crash").is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(daemon.try_wait().expect("wait for CRI crash").is_some());
    unsafe {
        std::env::remove_var("FERROCRATE_CRI_TEST_CRASH_POINT");
    }

    let mut restarted = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut recovered = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    recovered
        .status(StatusRequest { verbose: false })
        .await
        .expect("restarted CRI service ready");
    let payload: Vec<u8> = rusqlite::Connection::open(runtime.path().join("cri-state.sqlite"))
        .expect("open CRI state")
        .query_row(
            "SELECT payload FROM cri_state WHERE kind='sandboxes'",
            [],
            |row| row.get(0),
        )
        .expect("published sandbox payload");
    let records: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(&payload).expect("decode sandbox payload");
    let sandbox = records
        .iter()
        .find(|(_, record)| record["name"] == "sandbox-store-crash-pod")
        .map(|(id, _)| id.clone())
        .expect("published sandbox record");
    let listed = recovered
        .list_pod_sandbox(ListPodSandboxRequest { filter: None })
        .await
        .expect("list recovered sandbox")
        .into_inner();
    assert!(listed.items.iter().any(|item| item.id == sandbox));
    recovered
        .stop_pod_sandbox(StopPodSandboxRequest {
            pod_sandbox_id: sandbox.clone(),
        })
        .await
        .expect("stop recovered sandbox");
    recovered
        .remove_pod_sandbox(RemovePodSandboxRequest {
            pod_sandbox_id: sandbox,
        })
        .await
        .expect("remove recovered sandbox");
    restarted.kill().expect("stop restarted CRI daemon");
    let _ = restarted.wait();
    unsafe {
        std::env::remove_var("FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE");
    }
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn cri_store_publication_crash_recovers_container_metadata() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    let runtime = tempfile::tempdir().expect("runtime tempdir");
    let socket = runtime.path().join("cri-store-publication-crash.sock");
    unsafe {
        std::env::set_var(
            "FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE",
            "cri-fault-injection",
        );
        std::env::set_var(
            "FERROCRATE_CRI_TEST_CRASH_POINT",
            "after-container-store-publication",
        );
    }
    let mut daemon = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let sandbox = client
        .run_pod_sandbox(RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "store-crash-pod".into(),
                    uid: "store-crash-uid".into(),
                    namespace: "default".into(),
                    attempt: 1,
                }),
                hostname: "store-crash-pod".into(),
                log_directory: String::new(),
                dns_config: String::new(),
                network_namespace: "none".into(),
            }),
            runtime_handler: String::new(),
        })
        .await
        .expect("run sandbox")
        .into_inner()
        .pod_sandbox_id;
    let _transport_error = client
        .create_container(CreateContainerRequest {
            pod_sandbox_id: sandbox.clone(),
            config: Some(ContainerConfig {
                metadata_name: "store-crash-container".into(),
                image: "missing:latest".into(),
                command: vec!["true".into()],
                args: Vec::new(),
                env: Default::default(),
            }),
            sandbox_config: None,
        })
        .await
        .expect_err("fault injection must terminate after container publication");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if daemon.try_wait().expect("poll CRI crash").is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(daemon.try_wait().expect("wait for CRI crash").is_some());
    unsafe {
        std::env::remove_var("FERROCRATE_CRI_TEST_CRASH_POINT");
    }

    let mut restarted = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut recovered = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    recovered
        .status(StatusRequest { verbose: false })
        .await
        .expect("restarted CRI service ready");
    let payload: Vec<u8> = rusqlite::Connection::open(runtime.path().join("cri-state.sqlite"))
        .expect("open CRI state")
        .query_row(
            "SELECT payload FROM cri_state WHERE kind='containers'",
            [],
            |row| row.get(0),
        )
        .expect("published container payload");
    let records: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(&payload).expect("decode container payload");
    let container = records
        .iter()
        .find(|(_, record)| record["name"] == "store-crash-container")
        .map(|(id, _)| id.clone())
        .expect("published container record");
    let status = recovered
        .container_status(ContainerStatusRequest {
            container_id: container,
            verbose: false,
        })
        .await;
    assert!(status.is_ok(), "published container must be recoverable");
    restarted.kill().expect("stop restarted CRI daemon");
    let _ = restarted.wait();
    unsafe {
        std::env::remove_var("FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE");
    }
}

#[tokio::test]
#[ignore = "Requires rootful CRI bridge networking"]
#[allow(clippy::await_holding_lock)]
async fn cri_network_effect_crash_is_cleaned_from_pending_state() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    if !running_as_root() {
        eprintln!("skipping CRI network effect fixture: root is required");
        return;
    }
    let runtime = tempfile::tempdir().expect("runtime tempdir");
    let socket = runtime.path().join("cri-network-effect-crash.sock");
    unsafe {
        std::env::set_var(
            "FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE",
            "cri-fault-injection",
        );
        std::env::set_var(
            "FERROCRATE_CRI_TEST_CRASH_POINT",
            "after-sandbox-network-effect",
        );
    }
    let mut daemon = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    client
        .run_pod_sandbox(RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "network-crash-pod".into(),
                    uid: "network-crash-uid".into(),
                    namespace: "default".into(),
                    attempt: 1,
                }),
                hostname: "network-crash-pod".into(),
                log_directory: String::new(),
                dns_config: String::new(),
                network_namespace: "bridge".into(),
            }),
            runtime_handler: String::new(),
        })
        .await
        .expect_err("fault injection must terminate after network effect");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if daemon.try_wait().expect("poll CRI crash").is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(daemon.try_wait().expect("wait for CRI crash").is_some());
    unsafe {
        std::env::remove_var("FERROCRATE_CRI_TEST_CRASH_POINT");
    }

    let payload: Vec<u8> = rusqlite::Connection::open(runtime.path().join("cri-state.sqlite"))
        .expect("open CRI state")
        .query_row(
            "SELECT payload FROM cri_state WHERE kind='pending-sandbox-networks'",
            [],
            |row| row.get(0),
        )
        .expect("pending network payload");
    let pending: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(&payload).expect("decode pending network payload");
    let record = pending.values().next().expect("pending network record");
    let namespace = record["netns_name"]
        .as_str()
        .expect("pending namespace")
        .to_string();
    let bridge = record["network"]["bridge"]
        .as_str()
        .expect("pending bridge")
        .to_string();

    let mut restarted = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut recovered = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    recovered
        .status(StatusRequest { verbose: false })
        .await
        .expect("restarted CRI service ready");
    let pending_after: Vec<u8> =
        rusqlite::Connection::open(runtime.path().join("cri-state.sqlite"))
            .expect("open recovered CRI state")
            .query_row(
                "SELECT payload FROM cri_state WHERE kind='pending-sandbox-networks'",
                [],
                |row| row.get(0),
            )
            .expect("recovered pending network payload");
    let pending_after: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(&pending_after).expect("decode recovered pending payload");
    assert!(
        pending_after.is_empty(),
        "pending network must be reclaimed"
    );
    assert!(!ferro_net::netns_path(&namespace).exists());
    assert!(ferro_net::observe_bridge_identity(&bridge)
        .expect("observe bridge")
        .is_none());
    restarted.kill().expect("stop restarted CRI daemon");
    let _ = restarted.wait();
    unsafe {
        std::env::remove_var("FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE");
    }
}

#[tokio::test]
#[ignore = "Requires rootful CRI bridge networking"]
#[allow(clippy::await_holding_lock)]
async fn cri_remove_sandbox_network_effect_crash_is_reconciled_on_restart() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    if !running_as_root() {
        eprintln!("skipping CRI remove network effect fixture: root is required");
        return;
    }
    let runtime = tempfile::tempdir().expect("runtime tempdir");
    let socket = runtime.path().join("cri-remove-network-effect-crash.sock");
    unsafe {
        std::env::set_var(
            "FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE",
            "cri-fault-injection",
        );
        std::env::set_var(
            "FERROCRATE_CRI_TEST_CRASH_POINT",
            "after-sandbox-network-remove-effect",
        );
    }
    let mut daemon = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let sandbox = client
        .run_pod_sandbox(RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "remove-network-crash-pod".into(),
                    uid: "remove-network-crash-uid".into(),
                    namespace: "default".into(),
                    attempt: 1,
                }),
                hostname: "remove-network-crash-pod".into(),
                log_directory: String::new(),
                dns_config: String::new(),
                network_namespace: "bridge".into(),
            }),
            runtime_handler: String::new(),
        })
        .await
        .expect("run bridge sandbox")
        .into_inner()
        .pod_sandbox_id;
    let remove = client
        .remove_pod_sandbox(RemovePodSandboxRequest {
            pod_sandbox_id: sandbox.clone(),
        })
        .await;
    assert!(
        remove.is_err(),
        "fault injection must terminate after network removal"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if daemon.try_wait().expect("poll CRI remove crash").is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(daemon
        .try_wait()
        .expect("wait for CRI remove crash")
        .is_some());
    unsafe {
        std::env::remove_var("FERROCRATE_CRI_TEST_CRASH_POINT");
    }

    let payload: Vec<u8> = rusqlite::Connection::open(runtime.path().join("cri-state.sqlite"))
        .expect("open CRI state")
        .query_row(
            "SELECT payload FROM cri_state WHERE kind='pending-sandbox-networks'",
            [],
            |row| row.get(0),
        )
        .expect("pending remove network payload");
    let pending: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(&payload).expect("decode pending remove payload");
    let record = pending.get(&sandbox).expect("pending removed sandbox");
    let namespace = record["netns_name"]
        .as_str()
        .expect("pending namespace")
        .to_string();
    let bridge = record["network"]["bridge"]
        .as_str()
        .expect("pending bridge")
        .to_string();

    let mut restarted = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut recovered = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    recovered
        .status(StatusRequest { verbose: false })
        .await
        .expect("restarted CRI service ready");
    let pending_after: Vec<u8> =
        rusqlite::Connection::open(runtime.path().join("cri-state.sqlite"))
            .expect("open recovered CRI state")
            .query_row(
                "SELECT payload FROM cri_state WHERE kind='pending-sandbox-networks'",
                [],
                |row| row.get(0),
            )
            .expect("recovered pending remove payload");
    let pending_after: std::collections::BTreeMap<String, serde_json::Value> =
        serde_json::from_slice(&pending_after).expect("decode recovered pending remove payload");
    assert!(
        pending_after.is_empty(),
        "removed sandbox pending state must be reclaimed"
    );
    assert!(!ferro_net::netns_path(&namespace).exists());
    assert!(ferro_net::observe_bridge_identity(&bridge)
        .expect("observe removed bridge")
        .is_none());
    let status = recovered
        .pod_sandbox_status(PodSandboxStatusRequest {
            pod_sandbox_id: sandbox,
            verbose: false,
        })
        .await;
    assert!(
        status.is_err(),
        "removed sandbox must stay removed after recovery"
    );
    restarted.kill().expect("stop restarted CRI daemon");
    let _ = restarted.wait();
    unsafe {
        std::env::remove_var("FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE");
    }
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn cri_process_kill_operation_matrix_reopens_each_durable_transition() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    let runtime = tempfile::tempdir().expect("runtime tempdir");
    let socket = runtime.path().join("cri-operation-matrix.sock");
    let mut daemon = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;

    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let sandbox = client
        .run_pod_sandbox(RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "matrix-pod".into(),
                    uid: "matrix-uid".into(),
                    namespace: "default".into(),
                    attempt: 1,
                }),
                hostname: "matrix-pod".into(),
                log_directory: String::new(),
                dns_config: String::new(),
                network_namespace: "none".into(),
            }),
            runtime_handler: String::new(),
        })
        .await
        .expect("run sandbox")
        .into_inner()
        .pod_sandbox_id;

    // Kill immediately after the sandbox transition and prove that the
    // replacement daemon recovered the durable record before the next RPC.
    daemon.kill().expect("kill after sandbox create");
    let _ = daemon.wait();
    daemon = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let sandbox_status = client
        .pod_sandbox_status(PodSandboxStatusRequest {
            pod_sandbox_id: sandbox.clone(),
            verbose: false,
        })
        .await
        .expect("sandbox status after restart")
        .into_inner()
        .status
        .expect("sandbox record");
    assert_eq!(sandbox_status.id, sandbox);

    let container = client
        .create_container(CreateContainerRequest {
            pod_sandbox_id: sandbox.clone(),
            config: Some(ContainerConfig {
                metadata_name: "matrix-container".into(),
                image: "missing:latest".into(),
                command: vec!["true".into()],
                args: Vec::new(),
                env: Default::default(),
            }),
            sandbox_config: None,
        })
        .await
        .expect("create container")
        .into_inner()
        .container_id;

    // Kill after container persistence and verify both records survive.
    daemon.kill().expect("kill after container create");
    let _ = daemon.wait();
    daemon = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let status = client
        .container_status(ContainerStatusRequest {
            container_id: container.clone(),
            verbose: false,
        })
        .await
        .expect("container status after restart")
        .into_inner()
        .status
        .expect("container record");
    assert_eq!(status.id, container);
    assert_eq!(
        status.state,
        ferro_cri::runtime::ContainerState::Created as i32
    );

    client
        .stop_pod_sandbox(StopPodSandboxRequest {
            pod_sandbox_id: sandbox.clone(),
        })
        .await
        .expect("stop sandbox");
    daemon.kill().expect("kill after sandbox stop");
    let _ = daemon.wait();
    daemon = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let stopped = client
        .pod_sandbox_status(PodSandboxStatusRequest {
            pod_sandbox_id: sandbox.clone(),
            verbose: false,
        })
        .await
        .expect("stopped sandbox status after restart")
        .into_inner()
        .status
        .expect("stopped sandbox record");
    assert_eq!(
        stopped.state,
        ferro_cri::runtime::PodSandboxState::Notready as i32
    );

    client
        .remove_container(RemoveContainerRequest {
            container_id: container.clone(),
        })
        .await
        .expect("remove container");
    daemon.kill().expect("kill after container remove");
    let _ = daemon.wait();
    daemon = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let removed_container = client
        .container_status(ContainerStatusRequest {
            container_id: container.clone(),
            verbose: false,
        })
        .await
        .expect_err("removed container must remain absent after restart");
    assert_eq!(removed_container.code(), tonic::Code::NotFound);

    client
        .remove_pod_sandbox(RemovePodSandboxRequest {
            pod_sandbox_id: sandbox.clone(),
        })
        .await
        .expect("remove sandbox");
    daemon.kill().expect("kill after sandbox remove");
    let _ = daemon.wait();
    daemon = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let removed_sandbox = client
        .pod_sandbox_status(PodSandboxStatusRequest {
            pod_sandbox_id: sandbox,
            verbose: false,
        })
        .await
        .expect_err("removed sandbox must remain absent after restart");
    assert_eq!(removed_sandbox.code(), tonic::Code::NotFound);

    daemon.kill().expect("stop matrix daemon");
    let _ = daemon.wait();
}

#[tokio::test]
#[ignore = "Requires rootful OCI execution"]
#[allow(clippy::await_holding_lock)]
async fn cri_start_recovery_rebinds_runtime_after_mid_operation_crash() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    if Command::new("id")
        .arg("-u")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim() != "0")
        .unwrap_or(true)
    {
        eprintln!("skipping CRI crash recovery fixture: root is required");
        return;
    }

    let runtime = tempfile::tempdir().expect("runtime tempdir");
    seed_runnable_fixture_image(runtime.path());
    let socket = runtime.path().join("cri-start-crash.sock");
    unsafe {
        std::env::set_var(
            "FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE",
            "cri-fault-injection",
        );
        std::env::set_var("FERROCRATE_CRI_TEST_CRASH_POINT", "after-runtime-effect");
    }
    let mut daemon = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;

    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let sandbox = client
        .run_pod_sandbox(RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "crash-pod".into(),
                    uid: "crash-uid".into(),
                    namespace: "default".into(),
                    attempt: 1,
                }),
                hostname: "crash-pod".into(),
                log_directory: String::new(),
                dns_config: String::new(),
                network_namespace: "bridge".into(),
            }),
            runtime_handler: String::new(),
        })
        .await
        .expect("sandbox")
        .into_inner()
        .pod_sandbox_id;
    let container = client
        .create_container(CreateContainerRequest {
            pod_sandbox_id: sandbox,
            config: Some(ContainerConfig {
                metadata_name: "crash-container".into(),
                image: "fixture:latest".into(),
                command: vec!["/bin/busybox".into(), "sleep".into(), "30".into()],
                args: Vec::new(),
                env: Default::default(),
            }),
            sandbox_config: None,
        })
        .await
        .expect("container")
        .into_inner()
        .container_id;

    let _ = client
        .start_container(StartContainerRequest {
            container_id: container.clone(),
        })
        .await
        .expect_err("fault injection must terminate the daemon before publication");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if daemon.try_wait().expect("poll CRI daemon").is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(daemon.try_wait().expect("wait for CRI crash").is_some());
    unsafe {
        std::env::remove_var("FERROCRATE_CRI_TEST_CRASH_POINT");
    }

    let mut restarted = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut recovered = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let status = recovered
        .container_status(ContainerStatusRequest {
            container_id: container.clone(),
            verbose: false,
        })
        .await
        .expect("recovered status")
        .into_inner()
        .status
        .expect("recovered container");
    assert_eq!(status.id, container);
    assert_eq!(
        status.state,
        ferro_cri::runtime::ContainerState::Exited as i32
    );

    let runtime_records = ferro_core::runtime::ContainerRuntime::new(runtime.path())
        .expect("open recovered container runtime")
        .list()
        .expect("list recovered runtime records");
    let runtime_record = runtime_records
        .iter()
        .find(|record| {
            record
                .labels
                .get("io.ferrocrate.cri-container-id")
                .is_some_and(|value| value == &container)
        })
        .expect("recovered runtime record");
    assert_eq!(runtime_record.status, "exited");
    if let Some(bridge) = runtime_record
        .network_ownership
        .as_ref()
        .and_then(|ownership| ownership.bridge.as_deref())
    {
        assert!(!std::process::Command::new("ip")
            .args(["link", "show", bridge])
            .status()
            .expect("inspect recovered bridge")
            .success());
    }

    restarted.kill().expect("stop restarted CRI daemon");
    let _ = restarted.wait();
    unsafe {
        std::env::remove_var("FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE");
    }
}

#[tokio::test]
#[ignore = "Requires rootful OCI execution"]
#[allow(clippy::await_holding_lock)]
async fn cri_start_recovery_rebinds_published_runtime_after_response_crash() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    if Command::new("id")
        .arg("-u")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim() != "0")
        .unwrap_or(true)
    {
        eprintln!("skipping CRI crash recovery fixture: root is required");
        return;
    }

    let runtime = tempfile::tempdir().expect("runtime tempdir");
    seed_runnable_fixture_image(runtime.path());
    let socket = runtime.path().join("cri-start-published-crash.sock");
    unsafe {
        std::env::set_var(
            "FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE",
            "cri-fault-injection",
        );
        std::env::set_var("FERROCRATE_CRI_TEST_CRASH_POINT", "after-cri-publication");
    }
    let mut daemon = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let sandbox = client
        .run_pod_sandbox(RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "published-crash-pod".into(),
                    uid: "published-crash-uid".into(),
                    namespace: "default".into(),
                    attempt: 1,
                }),
                hostname: "published-crash-pod".into(),
                log_directory: String::new(),
                dns_config: String::new(),
                network_namespace: "none".into(),
            }),
            runtime_handler: String::new(),
        })
        .await
        .expect("sandbox")
        .into_inner()
        .pod_sandbox_id;
    let container = client
        .create_container(CreateContainerRequest {
            pod_sandbox_id: sandbox,
            config: Some(ContainerConfig {
                metadata_name: "published-crash-container".into(),
                image: "fixture:latest".into(),
                command: vec!["/bin/busybox".into(), "sleep".into(), "30".into()],
                args: Vec::new(),
                env: Default::default(),
            }),
            sandbox_config: None,
        })
        .await
        .expect("container")
        .into_inner()
        .container_id;

    client
        .start_container(StartContainerRequest {
            container_id: container.clone(),
        })
        .await
        .expect_err("fault injection must terminate after CRI publication");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if daemon.try_wait().expect("poll CRI crash").is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(daemon.try_wait().expect("wait for CRI crash").is_some());
    unsafe {
        std::env::remove_var("FERROCRATE_CRI_TEST_CRASH_POINT");
    }

    let mut restarted = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut recovered = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let status = recovered
        .container_status(ContainerStatusRequest {
            container_id: container.clone(),
            verbose: false,
        })
        .await
        .expect("recovered status")
        .into_inner()
        .status
        .expect("recovered container");
    assert_eq!(status.id, container);
    assert_eq!(
        status.state,
        ferro_cri::runtime::ContainerState::Exited as i32
    );
    recovered
        .remove_container(RemoveContainerRequest {
            container_id: container.clone(),
        })
        .await
        .expect("recovered container cleanup");
    assert!(!std::path::Path::new("/var/run/netns")
        .join(format!("ferro-{container}"))
        .exists());
    restarted.kill().expect("stop restarted CRI daemon");
    let _ = restarted.wait();
    unsafe {
        std::env::remove_var("FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE");
    }
}

#[tokio::test]
#[ignore = "Requires rootful OCI execution"]
#[allow(clippy::await_holding_lock)]
async fn cri_stop_recovery_reconciles_runtime_after_effect_crash() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    if Command::new("id")
        .arg("-u")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim() != "0")
        .unwrap_or(true)
    {
        eprintln!("skipping CRI stop crash fixture: root is required");
        return;
    }

    let runtime = tempfile::tempdir().expect("runtime tempdir");
    seed_runnable_fixture_image(runtime.path());
    let socket = runtime.path().join("cri-stop-crash.sock");
    unsafe {
        std::env::set_var(
            "FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE",
            "cri-fault-injection",
        );
        std::env::set_var(
            "FERROCRATE_CRI_TEST_CRASH_POINT",
            "after-runtime-stop-effect",
        );
    }
    let mut daemon = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let sandbox = client
        .run_pod_sandbox(RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "stop-crash-pod".into(),
                    uid: "stop-crash-uid".into(),
                    namespace: "default".into(),
                    attempt: 1,
                }),
                hostname: "stop-crash-pod".into(),
                log_directory: String::new(),
                dns_config: String::new(),
                network_namespace: "none".into(),
            }),
            runtime_handler: String::new(),
        })
        .await
        .expect("sandbox")
        .into_inner()
        .pod_sandbox_id;
    let container = client
        .create_container(CreateContainerRequest {
            pod_sandbox_id: sandbox,
            config: Some(ContainerConfig {
                metadata_name: "stop-crash-container".into(),
                image: "fixture:latest".into(),
                command: vec!["/bin/busybox".into(), "sleep".into(), "30".into()],
                args: Vec::new(),
                env: Default::default(),
            }),
            sandbox_config: None,
        })
        .await
        .expect("container")
        .into_inner()
        .container_id;
    client
        .start_container(StartContainerRequest {
            container_id: container.clone(),
        })
        .await
        .expect("start container");

    let stop_result = client
        .stop_container(StopContainerRequest {
            container_id: container.clone(),
            timeout: 5,
        })
        .await;
    stop_result.expect_err("fault injection must terminate after runtime stop effect");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if daemon.try_wait().expect("poll CRI stop crash").is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(daemon
        .try_wait()
        .expect("wait for CRI stop crash")
        .is_some());
    unsafe {
        std::env::remove_var("FERROCRATE_CRI_TEST_CRASH_POINT");
    }

    let mut restarted = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut recovered = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let status = recovered
        .container_status(ContainerStatusRequest {
            container_id: container.clone(),
            verbose: false,
        })
        .await
        .expect("recovered status")
        .into_inner()
        .status
        .expect("recovered container");
    assert_eq!(
        status.state,
        ferro_cri::runtime::ContainerState::Exited as i32
    );
    recovered
        .remove_container(RemoveContainerRequest {
            container_id: container,
        })
        .await
        .expect("recovered container cleanup");
    restarted.kill().expect("stop restarted CRI daemon");
    let _ = restarted.wait();
    unsafe {
        std::env::remove_var("FERRO_AUTHORIZATION_QUALIFICATION_FIXTURE");
    }
}

#[tokio::test]
#[ignore = "Requires rootful CRI bridge networking"]
#[allow(clippy::await_holding_lock)]
async fn cri_pending_publication_crash_without_kernel_effects_is_reclaimed() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    if !running_as_root() {
        eprintln!("skipping CRI pending publication crash fixture: root is required");
        return;
    }
    let runtime = tempfile::tempdir().expect("runtime tempdir");
    let socket = runtime.path().join("cri-pending-publication-crash.sock");
    set_crash_point("after-sandbox-pending-publication");
    let mut daemon = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let _ = client
        .run_pod_sandbox(RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "pending-publication-crash-pod".into(),
                    uid: "pending-publication-crash-uid".into(),
                    namespace: "default".into(),
                    attempt: 1,
                }),
                hostname: "pending-publication-crash-pod".into(),
                log_directory: String::new(),
                dns_config: String::new(),
                network_namespace: "bridge".into(),
            }),
            runtime_handler: String::new(),
        })
        .await
        .expect_err("fault injection must terminate before netns creation");
    wait_for_cri_crash(&mut daemon).await;
    clear_crash_point();

    let pending = read_cri_state(runtime.path(), "pending-sandbox-networks");
    let record = pending.values().next().expect("pending network record");
    let namespace = record["netns_name"]
        .as_str()
        .expect("pending namespace")
        .to_string();
    let bridge = record["network"]["bridge"]
        .as_str()
        .expect("pending bridge")
        .to_string();
    assert!(
        !ferro_net::netns_path(&namespace).exists(),
        "crash point must fire before the namespace effect"
    );
    assert!(ferro_net::observe_bridge_identity(&bridge)
        .expect("observe bridge")
        .is_none());

    let mut restarted = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut recovered = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    recovered
        .status(StatusRequest { verbose: false })
        .await
        .expect("restarted CRI service ready");
    assert!(
        read_cri_state(runtime.path(), "pending-sandbox-networks").is_empty(),
        "pending network without kernel effects must be reclaimed on restart"
    );
    assert!(
        !ferro_net::netns_path(&namespace).exists(),
        "recovery must not recreate the namespace"
    );
    assert!(ferro_net::observe_bridge_identity(&bridge)
        .expect("observe bridge after recovery")
        .is_none());
    let listed = recovered
        .list_pod_sandbox(ListPodSandboxRequest { filter: None })
        .await
        .expect("list recovered sandboxes")
        .into_inner();
    assert!(
        listed.items.is_empty(),
        "unpublished sandbox must not reappear after recovery"
    );
    restarted.kill().expect("stop restarted CRI daemon");
    let _ = restarted.wait();
    clear_crash_fixture();
}

#[tokio::test]
#[ignore = "Requires rootful CRI bridge networking"]
#[allow(clippy::await_holding_lock)]
async fn cri_netns_effect_crash_is_reconciled_on_restart() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    if !running_as_root() {
        eprintln!("skipping CRI netns effect crash fixture: root is required");
        return;
    }
    let runtime = tempfile::tempdir().expect("runtime tempdir");
    let socket = runtime.path().join("cri-netns-effect-crash.sock");
    set_crash_point("after-sandbox-netns-effect");
    let mut daemon = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let _ = client
        .run_pod_sandbox(RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "netns-crash-pod".into(),
                    uid: "netns-crash-uid".into(),
                    namespace: "default".into(),
                    attempt: 1,
                }),
                hostname: "netns-crash-pod".into(),
                log_directory: String::new(),
                dns_config: String::new(),
                network_namespace: "bridge".into(),
            }),
            runtime_handler: String::new(),
        })
        .await
        .expect_err("fault injection must terminate after netns creation");
    wait_for_cri_crash(&mut daemon).await;
    clear_crash_point();

    let pending = read_cri_state(runtime.path(), "pending-sandbox-networks");
    let record = pending.values().next().expect("pending network record");
    let namespace = record["netns_name"]
        .as_str()
        .expect("pending namespace")
        .to_string();
    let bridge = record["network"]["bridge"]
        .as_str()
        .expect("pending bridge")
        .to_string();
    assert!(
        ferro_net::netns_path(&namespace).exists(),
        "crash point must fire after the namespace effect"
    );
    assert!(ferro_net::observe_bridge_identity(&bridge)
        .expect("observe bridge")
        .is_none());

    let mut restarted = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut recovered = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    recovered
        .status(StatusRequest { verbose: false })
        .await
        .expect("restarted CRI service ready");
    assert!(
        read_cri_state(runtime.path(), "pending-sandbox-networks").is_empty(),
        "pending network must be reclaimed after namespace-only crash"
    );
    assert!(
        !ferro_net::netns_path(&namespace).exists(),
        "recovery must remove the leaked namespace"
    );
    assert!(ferro_net::observe_bridge_identity(&bridge)
        .expect("observe bridge after recovery")
        .is_none());
    let listed = recovered
        .list_pod_sandbox(ListPodSandboxRequest { filter: None })
        .await
        .expect("list recovered sandboxes")
        .into_inner();
    assert!(
        listed.items.is_empty(),
        "unpublished sandbox must not reappear after recovery"
    );
    restarted.kill().expect("stop restarted CRI daemon");
    let _ = restarted.wait();
    clear_crash_fixture();
}

#[tokio::test]
#[ignore = "Requires rootful CRI bridge networking"]
#[allow(clippy::await_holding_lock)]
async fn cri_remove_sandbox_store_crash_is_reconciled_on_restart() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    if !running_as_root() {
        eprintln!("skipping CRI remove store crash fixture: root is required");
        return;
    }
    let runtime = tempfile::tempdir().expect("runtime tempdir");
    let socket = runtime.path().join("cri-remove-store-crash.sock");
    set_crash_point("after-sandbox-remove-store-publication");
    let mut daemon = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let sandbox = client
        .run_pod_sandbox(RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "remove-store-crash-pod".into(),
                    uid: "remove-store-crash-uid".into(),
                    namespace: "default".into(),
                    attempt: 1,
                }),
                hostname: "remove-store-crash-pod".into(),
                log_directory: String::new(),
                dns_config: String::new(),
                network_namespace: "bridge".into(),
            }),
            runtime_handler: String::new(),
        })
        .await
        .expect("run bridge sandbox")
        .into_inner()
        .pod_sandbox_id;
    let _ = client
        .remove_pod_sandbox(RemovePodSandboxRequest {
            pod_sandbox_id: sandbox.clone(),
        })
        .await
        .expect_err("fault injection must terminate before network teardown");
    wait_for_cri_crash(&mut daemon).await;
    clear_crash_point();

    let sandboxes = read_cri_state(runtime.path(), "sandboxes");
    assert!(
        !sandboxes.contains_key(&sandbox),
        "sandbox removal must already be committed"
    );
    let pending = read_cri_state(runtime.path(), "pending-sandbox-networks");
    let record = pending
        .get(&sandbox)
        .expect("pending removed sandbox record");
    let namespace = record["netns_name"]
        .as_str()
        .expect("pending namespace")
        .to_string();
    let bridge = record["network"]["bridge"]
        .as_str()
        .expect("pending bridge")
        .to_string();
    assert!(
        ferro_net::netns_path(&namespace).exists(),
        "crash point must fire before namespace teardown"
    );
    assert!(
        ferro_net::observe_bridge_identity(&bridge)
            .expect("observe leaked bridge")
            .is_some(),
        "crash point must fire before bridge teardown"
    );

    let mut restarted = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut recovered = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    recovered
        .status(StatusRequest { verbose: false })
        .await
        .expect("restarted CRI service ready");
    assert!(
        read_cri_state(runtime.path(), "pending-sandbox-networks").is_empty(),
        "pending teardown must complete on restart"
    );
    assert!(
        !ferro_net::netns_path(&namespace).exists(),
        "recovery must remove the leaked namespace"
    );
    assert!(ferro_net::observe_bridge_identity(&bridge)
        .expect("observe removed bridge")
        .is_none());
    let status = recovered
        .pod_sandbox_status(PodSandboxStatusRequest {
            pod_sandbox_id: sandbox,
            verbose: false,
        })
        .await;
    assert!(
        status.is_err(),
        "removed sandbox must stay removed after recovery"
    );
    restarted.kill().expect("stop restarted CRI daemon");
    let _ = restarted.wait();
    clear_crash_fixture();
}

#[tokio::test]
#[ignore = "Requires rootful CRI bridge networking"]
#[allow(clippy::await_holding_lock)]
async fn cri_remove_sandbox_netns_crash_clears_pending_idempotently() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    if !running_as_root() {
        eprintln!("skipping CRI remove netns crash fixture: root is required");
        return;
    }
    let runtime = tempfile::tempdir().expect("runtime tempdir");
    let socket = runtime.path().join("cri-remove-netns-crash.sock");
    set_crash_point("after-sandbox-netns-remove-effect");
    let mut daemon = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let sandbox = client
        .run_pod_sandbox(RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "remove-netns-crash-pod".into(),
                    uid: "remove-netns-crash-uid".into(),
                    namespace: "default".into(),
                    attempt: 1,
                }),
                hostname: "remove-netns-crash-pod".into(),
                log_directory: String::new(),
                dns_config: String::new(),
                network_namespace: "bridge".into(),
            }),
            runtime_handler: String::new(),
        })
        .await
        .expect("run bridge sandbox")
        .into_inner()
        .pod_sandbox_id;
    let _ = client
        .remove_pod_sandbox(RemovePodSandboxRequest {
            pod_sandbox_id: sandbox.clone(),
        })
        .await
        .expect_err("fault injection must terminate after netns teardown");
    wait_for_cri_crash(&mut daemon).await;
    clear_crash_point();

    let pending = read_cri_state(runtime.path(), "pending-sandbox-networks");
    let record = pending
        .get(&sandbox)
        .expect("pending record retained after netns teardown");
    let namespace = record["netns_name"]
        .as_str()
        .expect("pending namespace")
        .to_string();
    let bridge = record["network"]["bridge"]
        .as_str()
        .expect("pending bridge")
        .to_string();
    assert!(
        !ferro_net::netns_path(&namespace).exists(),
        "crash point must fire after namespace teardown"
    );
    assert!(ferro_net::observe_bridge_identity(&bridge)
        .expect("observe removed bridge")
        .is_none());

    let mut restarted = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut recovered = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    recovered
        .status(StatusRequest { verbose: false })
        .await
        .expect("restarted CRI service ready");
    assert!(
        read_cri_state(runtime.path(), "pending-sandbox-networks").is_empty(),
        "fully torn-down pending record must be reclaimed without new effects"
    );
    assert!(!ferro_net::netns_path(&namespace).exists());
    restarted.kill().expect("stop restarted CRI daemon");
    let _ = restarted.wait();
    clear_crash_fixture();
}

#[tokio::test]
#[ignore = "Requires rootful OCI execution"]
#[allow(clippy::await_holding_lock)]
async fn cri_remove_container_runtime_crash_rebinds_cleared_binding() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    if !running_as_root() {
        eprintln!("skipping CRI remove container crash fixture: root is required");
        return;
    }
    let runtime = tempfile::tempdir().expect("runtime tempdir");
    seed_runnable_fixture_image(runtime.path());
    let socket = runtime.path().join("cri-remove-container-crash.sock");
    set_crash_point("after-container-runtime-remove-effect");
    let mut daemon = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let sandbox = client
        .run_pod_sandbox(RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "remove-container-crash-pod".into(),
                    uid: "remove-container-crash-uid".into(),
                    namespace: "default".into(),
                    attempt: 1,
                }),
                hostname: "remove-container-crash-pod".into(),
                log_directory: String::new(),
                dns_config: String::new(),
                network_namespace: "none".into(),
            }),
            runtime_handler: String::new(),
        })
        .await
        .expect("sandbox")
        .into_inner()
        .pod_sandbox_id;
    let container = client
        .create_container(CreateContainerRequest {
            pod_sandbox_id: sandbox,
            config: Some(ContainerConfig {
                metadata_name: "remove-crash-container".into(),
                image: "fixture:latest".into(),
                command: vec!["/bin/busybox".into(), "sleep".into(), "30".into()],
                args: Vec::new(),
                env: Default::default(),
            }),
            sandbox_config: None,
        })
        .await
        .expect("container")
        .into_inner()
        .container_id;
    client
        .start_container(StartContainerRequest {
            container_id: container.clone(),
        })
        .await
        .expect("start container");
    // The runtime refuses to remove a running container, so stop first; the
    // crash point sits after the runtime removal effect, before the CRI
    // record cleanup.
    client
        .stop_container(StopContainerRequest {
            container_id: container.clone(),
            timeout: 5,
        })
        .await
        .expect("stop container before removal");
    let _ = client
        .remove_container(RemoveContainerRequest {
            container_id: container.clone(),
        })
        .await
        .expect_err("fault injection must terminate after runtime removal");
    wait_for_cri_crash(&mut daemon).await;
    clear_crash_point();

    let containers = read_cri_state(runtime.path(), "containers");
    let record = containers
        .get(&container)
        .expect("CRI container record retained after runtime removal");
    assert!(
        record["runtime_id"].as_str().is_some(),
        "crash point must fire before the CRI record removal"
    );

    let mut restarted = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut recovered = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let status = recovered
        .container_status(ContainerStatusRequest {
            container_id: container.clone(),
            verbose: false,
        })
        .await
        .expect("recovered status")
        .into_inner()
        .status
        .expect("recovered container");
    assert_eq!(status.id, container);
    assert_eq!(
        status.state,
        ferro_cri::runtime::ContainerState::Created as i32,
        "stale runtime binding must be cleared on recovery"
    );
    let containers_after = read_cri_state(runtime.path(), "containers");
    assert!(
        containers_after[&container]["runtime_id"]
            .as_str()
            .is_none(),
        "recovered CRI record must not reference the removed runtime container"
    );
    let runtime_records = ferro_core::runtime::ContainerRuntime::new(runtime.path())
        .expect("open recovered container runtime")
        .list()
        .expect("list recovered runtime records");
    assert!(
        runtime_records.iter().all(|record| {
            record
                .labels
                .get("io.ferrocrate.cri-container-id")
                .is_none_or(|value| value != &container)
        }),
        "no runtime record for the removed container may survive"
    );
    recovered
        .remove_container(RemoveContainerRequest {
            container_id: container,
        })
        .await
        .expect("remove retry after recovery");
    restarted.kill().expect("stop restarted CRI daemon");
    let _ = restarted.wait();
    clear_crash_fixture();
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn cri_journal_pending_network_without_kernel_effects_is_reclaimed() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    let runtime = tempfile::tempdir().expect("runtime tempdir");
    let pending = serde_json::json!({
        "cri-sandbox-journal": {
            "id": "cri-sandbox-journal",
            "name": "journal-pending-pod",
            "uid": "journal-pending-uid",
            "namespace": "default",
            "state": "ready",
            "created_at_unix": 1,
            "network_mode": "bridge",
            "attempt": 0,
            "runtime_handler": "",
            "netns_name": "cri-journal-absent",
            "network": {
                "bridge": "fcjn00",
                "host_veth": "fcjn01",
                "peer_veth": "fcjn02",
                "gateway": "10.240.33.1",
                "container": "10.240.33.2",
                "prefix": 30,
                "mtu": null
            }
        }
    });
    let connection = rusqlite::Connection::open(runtime.path().join("cri-state.sqlite"))
        .expect("open seeded CRI state");
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS cri_state (
                kind TEXT PRIMARY KEY NOT NULL,
                payload BLOB NOT NULL
            )",
        )
        .expect("seed CRI state schema");
    connection
        .execute(
            "INSERT INTO cri_state(kind, payload) VALUES (?1, ?2)",
            rusqlite::params![
                "pending-sandbox-networks",
                serde_json::to_vec(&pending).expect("encode pending journal state")
            ],
        )
        .expect("seed pending journal state");
    drop(connection);
    assert!(
        !ferro_net::netns_path("cri-journal-absent").exists(),
        "fixture precondition: no kernel namespace exists"
    );
    assert!(
        ferro_net::observe_bridge_identity("fcjn00")
            .expect("observe seeded bridge")
            .is_none(),
        "fixture precondition: no kernel bridge exists"
    );

    let socket = runtime.path().join("cri-journal-pending.sock");
    unsafe {
        std::env::set_var("FERROCRATE_RUNTIME_DIR", runtime.path());
    }
    let socket_for_server = socket.clone();
    let server = tokio::spawn(async move {
        let _ = ferro_cri::server::serve(socket_for_server).await;
    });
    wait_for_socket(&socket).await;
    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    client
        .status(StatusRequest { verbose: false })
        .await
        .expect("recovered CRI service ready");

    assert!(
        read_cri_state(runtime.path(), "pending-sandbox-networks").is_empty(),
        "journal-only pending network must be reclaimed without kernel effects"
    );
    assert!(
        !ferro_net::netns_path("cri-journal-absent").exists(),
        "recovery must not create kernel effects"
    );
    server.abort();
    let _ = server.await;
    unsafe {
        std::env::remove_var("FERROCRATE_RUNTIME_DIR");
    }
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn cri_journal_stale_container_runtime_binding_is_cleared_on_recovery() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    let runtime = tempfile::tempdir().expect("runtime tempdir");
    let containers = serde_json::json!({
        "cri-container-stale": {
            "id": "cri-container-stale",
            "sandbox_id": "cri-sandbox-stale",
            "name": "stale-container",
            "image": "missing:latest",
            "command": ["true"],
            "env": [],
            "runtime_id": "ferro-stale-runtime-id",
            "created_at_unix": 1
        }
    });
    let connection = rusqlite::Connection::open(runtime.path().join("cri-state.sqlite"))
        .expect("open seeded CRI state");
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS cri_state (
                kind TEXT PRIMARY KEY NOT NULL,
                payload BLOB NOT NULL
            )",
        )
        .expect("seed CRI state schema");
    connection
        .execute(
            "INSERT INTO cri_state(kind, payload) VALUES (?1, ?2)",
            rusqlite::params![
                "containers",
                serde_json::to_vec(&containers).expect("encode container journal state")
            ],
        )
        .expect("seed container journal state");
    drop(connection);

    let socket = runtime.path().join("cri-journal-stale-binding.sock");
    unsafe {
        std::env::set_var("FERROCRATE_RUNTIME_DIR", runtime.path());
    }
    let socket_for_server = socket.clone();
    let server = tokio::spawn(async move {
        let _ = ferro_cri::server::serve(socket_for_server).await;
    });
    wait_for_socket(&socket).await;
    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let status = client
        .container_status(ContainerStatusRequest {
            container_id: "cri-container-stale".into(),
            verbose: false,
        })
        .await
        .expect("recovered status for stale container")
        .into_inner()
        .status
        .expect("recovered container");
    assert_eq!(status.id, "cri-container-stale");
    assert_eq!(
        status.state,
        ferro_cri::runtime::ContainerState::Created as i32,
        "stale runtime binding must be cleared instead of reported as live"
    );
    let containers_after = read_cri_state(runtime.path(), "containers");
    assert!(
        containers_after["cri-container-stale"]["runtime_id"]
            .as_str()
            .is_none(),
        "durable record must drop the stale runtime binding"
    );
    server.abort();
    let _ = server.await;
    unsafe {
        std::env::remove_var("FERROCRATE_RUNTIME_DIR");
    }
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn cri_journal_sandbox_with_missing_netns_reports_notready_and_retains_record() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    let runtime = tempfile::tempdir().expect("runtime tempdir");
    let sandboxes = serde_json::json!({
        "cri-sandbox-journal-missing": {
            "id": "cri-sandbox-journal-missing",
            "name": "journal-missing-pod",
            "uid": "journal-missing-uid",
            "namespace": "default",
            "state": "ready",
            "created_at_unix": 1,
            "network_mode": "bridge",
            "attempt": 0,
            "runtime_handler": "",
            "netns_name": "cri-journal-missing",
            "network": {
                "bridge": "fcjn03",
                "host_veth": "fcjn04",
                "peer_veth": "fcjn05",
                "gateway": "10.240.33.5",
                "container": "10.240.33.6",
                "prefix": 30,
                "mtu": null
            }
        }
    });
    let connection = rusqlite::Connection::open(runtime.path().join("cri-state.sqlite"))
        .expect("open seeded CRI state");
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS cri_state (
                kind TEXT PRIMARY KEY NOT NULL,
                payload BLOB NOT NULL
            )",
        )
        .expect("seed CRI state schema");
    connection
        .execute(
            "INSERT INTO cri_state(kind, payload) VALUES (?1, ?2)",
            rusqlite::params![
                "sandboxes",
                serde_json::to_vec(&sandboxes).expect("encode sandbox journal state")
            ],
        )
        .expect("seed sandbox journal state");
    drop(connection);

    let socket = runtime.path().join("cri-journal-missing-netns.sock");
    unsafe {
        std::env::set_var("FERROCRATE_RUNTIME_DIR", runtime.path());
    }
    let socket_for_server = socket.clone();
    let server = tokio::spawn(async move {
        let _ = ferro_cri::server::serve(socket_for_server).await;
    });
    wait_for_socket(&socket).await;
    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let status = client
        .pod_sandbox_status(PodSandboxStatusRequest {
            pod_sandbox_id: "cri-sandbox-journal-missing".into(),
            verbose: false,
        })
        .await
        .expect("sandbox status against missing kernel namespace")
        .into_inner()
        .status
        .expect("sandbox record");
    assert_eq!(
        status.state,
        ferro_cri::runtime::PodSandboxState::Notready as i32,
        "ready-state journal record with no kernel namespace must report Notready"
    );
    let listed = client
        .list_pod_sandbox(ListPodSandboxRequest { filter: None })
        .await
        .expect("list sandboxes after reconciliation")
        .into_inner();
    assert!(
        listed
            .items
            .iter()
            .any(|item| item.id == "cri-sandbox-journal-missing"),
        "durable sandbox record must be retained, not deleted"
    );
    assert!(
        read_cri_state(runtime.path(), "pending-sandbox-networks").is_empty(),
        "reconciliation must not inject pending teardown state for a tracked sandbox"
    );
    server.abort();
    let _ = server.await;
    unsafe {
        std::env::remove_var("FERROCRATE_RUNTIME_DIR");
    }
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn cri_journal_seeded_container_remove_hits_injected_crash_point() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    let runtime = tempfile::tempdir().expect("runtime tempdir");
    let cri_container = "cri-container-remove-crash";
    let runtime_id = "ferro-seeded-runtime";
    let sandbox_id = "cri-sandbox-seeded";

    // Seed an exited runtime container directly in the runtime store so
    // remove_container reaches the runtime removal effect without privileged
    // OCI execution. Both CRI labels are required, otherwise startup
    // reconciliation would treat the binding as stale and clear it.
    let store = ferro_core::sqlite_container_store::SqliteContainerStore::open(
        runtime.path().join("containers.db"),
    )
    .expect("open runtime container store");
    store
        .put(&ferro_core::container_store::ContainerRecord {
            id: runtime_id.to_string(),
            name: Some("remove-crash-container".into()),
            pid: 0,
            process_start_time: None,
            image: "fixture:latest".into(),
            command: Vec::new(),
            tty: false,
            workdir: None,
            user: None,
            env: Vec::new(),
            labels: [
                (
                    "io.ferrocrate.cri-container-id".to_string(),
                    cri_container.to_string(),
                ),
                (
                    "io.ferrocrate.parent-resource".to_string(),
                    sandbox_id.to_string(),
                ),
            ]
            .into_iter()
            .collect(),
            annotations: Default::default(),
            capabilities: Vec::new(),
            health: None,
            health_status: "none".into(),
            health_failures: 0,
            health_checked_at_unix: None,
            health_log: Vec::new(),
            restart_policy: Default::default(),
            restart_count: 0,
            user_stopped: false,
            last_exit_code: Some(0),
            created_at_unix: 1,
            stdout_path: String::new(),
            stderr_path: String::new(),
            status: "exited".into(),
            netns: None,
            namespace_owned: false,
            namespace_identity: None,
            network_name: None,
            ip_address: None,
            ipv6_address: None,
            ports: Vec::new(),
            mounts: Vec::new(),
            tmpfs_mounts: Vec::new(),
            readonly_rootfs: false,
            no_new_privileges: false,
            resource_limits: None,
            network_backend: None,
            network_ownership: None,
            network_endpoints: Vec::new(),
            managed_overlay: None,
            managed_cleanup_provenance: None,
            managed_host_veth: None,
            ai_runtime: None,
            creation_provenance: Default::default(),
            mutation_generation: 1,
            pending_mutation: None,
        })
        .expect("seed runtime container record");
    drop(store);

    // Seed the CRI mapping exactly as a completed start_container leaves it.
    let containers = serde_json::json!({
        cri_container: {
            "id": cri_container,
            "sandbox_id": sandbox_id,
            "name": "remove-crash-container",
            "image": "fixture:latest",
            "command": ["true"],
            "env": [],
            "runtime_id": runtime_id,
            "created_at_unix": 1
        }
    });
    let connection = rusqlite::Connection::open(runtime.path().join("cri-state.sqlite"))
        .expect("open seeded CRI state");
    connection
        .execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS cri_state (
                kind TEXT PRIMARY KEY NOT NULL,
                payload BLOB NOT NULL
            )",
        )
        .expect("seed CRI state schema");
    connection
        .execute(
            "INSERT INTO cri_state(kind, payload) VALUES (?1, ?2)",
            rusqlite::params![
                "containers",
                serde_json::to_vec(&containers).expect("encode container journal state")
            ],
        )
        .expect("seed container journal state");
    drop(connection);

    let socket = runtime.path().join("cri-seeded-remove-crash.sock");
    set_crash_point("after-container-runtime-remove-effect");
    let mut daemon = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let remove = client
        .remove_container(RemoveContainerRequest {
            container_id: cri_container.to_string(),
        })
        .await;
    assert!(
        remove.is_err(),
        "crash injection must terminate the daemon after runtime removal"
    );
    wait_for_cri_crash(&mut daemon).await;
    clear_crash_point();

    // The runtime effect landed (record deleted) while the CRI mapping was
    // retained with its now-stale binding.
    let store = ferro_core::sqlite_container_store::SqliteContainerStore::open(
        runtime.path().join("containers.db"),
    )
    .expect("reopen runtime container store");
    assert!(
        store
            .get(runtime_id)
            .expect("query removed record")
            .is_none(),
        "runtime removal effect must land before the crash point"
    );
    drop(store);
    let containers_after = read_cri_state(runtime.path(), "containers");
    assert_eq!(
        containers_after[cri_container]["runtime_id"].as_str(),
        Some(runtime_id),
        "CRI record must be retained with its stale binding at the crash point"
    );

    // Restart without the crash point: reconciliation must clear the stale
    // binding and the removal retry must complete.
    let mut restarted = spawn_cri_process(runtime.path(), &socket);
    wait_for_socket(&socket).await;
    let mut recovered = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let status = recovered
        .container_status(ContainerStatusRequest {
            container_id: cri_container.to_string(),
            verbose: false,
        })
        .await
        .expect("recovered status")
        .into_inner()
        .status
        .expect("recovered container");
    assert_eq!(status.id, cri_container);
    assert_eq!(
        status.state,
        ferro_cri::runtime::ContainerState::Created as i32
    );
    recovered
        .remove_container(RemoveContainerRequest {
            container_id: cri_container.to_string(),
        })
        .await
        .expect("remove retry after recovery");
    assert!(
        !read_cri_state(runtime.path(), "containers").contains_key(cri_container),
        "remove retry must delete the CRI record"
    );
    restarted.kill().expect("stop restarted CRI daemon");
    let _ = restarted.wait();
    clear_crash_fixture();
}

fn seed_runnable_fixture_image(runtime_dir: &Path) {
    let store = ferro_core::image_store::LocalImageStore::open(runtime_dir.join("images"))
        .expect("open image store");
    let layer_path = runtime_dir.join("fixture-layer.tar");
    let busybox = std::fs::read("/usr/bin/busybox").expect("busybox is required for fixture");
    let file = std::fs::File::create(&layer_path).expect("create fixture layer");
    let mut tar = Builder::new(file);
    let mut header = Header::new_gnu();
    header.set_path("bin/busybox").expect("layer path");
    header.set_size(busybox.len() as u64);
    header.set_mode(0o755);
    header.set_cksum();
    tar.append(&header, Cursor::new(&busybox))
        .expect("append busybox");
    let mut shell_header = Header::new_gnu();
    shell_header.set_path("bin/sh").expect("layer shell path");
    shell_header.set_size(busybox.len() as u64);
    shell_header.set_mode(0o755);
    shell_header.set_cksum();
    tar.append(&shell_header, Cursor::new(&busybox))
        .expect("append shell");
    tar.finish().expect("finish fixture layer");
    let layer = std::fs::read(&layer_path).expect("read fixture layer");
    let layer_digest = format!("sha256:{:x}", Sha256::digest(&layer));

    let config = serde_json::json!({
        "architecture": "amd64",
        "os": "linux",
        "config": { "Cmd": ["/bin/busybox", "sleep", "30"] },
        "rootfs": { "type": "layers", "diff_ids": [layer_digest] }
    });
    let config_bytes = serde_json::to_vec(&config).expect("encode fixture config");
    let config_digest = format!("sha256:{:x}", Sha256::digest(&config_bytes));
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": config_bytes.len()
        },
        "layers": [{
            "mediaType": "application/vnd.oci.image.layer.v1.tar",
            "digest": layer_digest,
            "size": layer.len()
        }]
    });
    let manifest_json = serde_json::to_string(&manifest).expect("encode fixture manifest");
    let runtime = ContainerRuntime::new(runtime_dir).expect("runtime authorization");
    let authority = runtime.surface_authorization().expect("surface authority");
    let origin = ferro_core::authorization::RequestOrigin::cli_current().expect("origin");
    let plan = store
        .prepare_reference_write(
            "fixture:latest",
            manifest["config"]["digest"]
                .as_str()
                .expect("config digest"),
            "application/vnd.oci.image.manifest.v1+json",
            &manifest_json,
        )
        .expect("prepare fixture reference");
    let permit = authority
        .authorize_image_reference_write_plan(&origin, &plan)
        .expect("authorize fixture reference");
    store
        .put_reference_authorized(plan, permit)
        .expect("store fixture reference");
    let config_path = runtime_dir
        .join("images/configs")
        .join(config_digest.replace(':', "_"));
    std::fs::create_dir_all(config_path.parent().expect("config parent")).expect("config dir");
    std::fs::write(config_path, config_bytes).expect("write fixture config");
    let blob_path = runtime_dir
        .join("images/blobs")
        .join(layer_digest.replace(':', "_"));
    std::fs::create_dir_all(blob_path.parent().expect("blob parent")).expect("blob dir");
    std::fs::copy(layer_path, blob_path).expect("write fixture layer");
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn cri_socket_starts_and_execs_a_real_oci_rootfs_fixture() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    let running_as_root = Command::new("id")
        .arg("-u")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim() == "0")
        .unwrap_or(false);
    let rootless_opt_in = std::env::var("FERROCRATE_RUN_ROOTLESS_CRI_E2E")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !running_as_root && !rootless_opt_in {
        eprintln!(
            "skipping real CRI rootfs fixture: set FERROCRATE_RUN_ROOTLESS_CRI_E2E=1 for the opt-in rootless run"
        );
        return;
    }
    let runtime = tempfile::tempdir().expect("runtime tempdir");
    seed_runnable_fixture_image(runtime.path());
    let socket = runtime.path().join("cri-runnable.sock");
    unsafe {
        std::env::set_var("FERROCRATE_RUNTIME_DIR", runtime.path());
    }
    let socket_for_server = socket.clone();
    let server = tokio::spawn(async move {
        let _ = ferro_cri::server::serve(socket_for_server).await;
    });
    wait_for_socket(&socket).await;

    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let sandbox = client
        .run_pod_sandbox(RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "rootfs-pod".into(),
                    uid: "rootfs-uid".into(),
                    namespace: "default".into(),
                    attempt: 1,
                }),
                hostname: "rootfs-pod".into(),
                log_directory: String::new(),
                dns_config: String::new(),
                network_namespace: "none".into(),
            }),
            runtime_handler: String::new(),
        })
        .await
        .expect("sandbox")
        .into_inner()
        .pod_sandbox_id;
    let container = client
        .create_container(CreateContainerRequest {
            pod_sandbox_id: sandbox.clone(),
            config: Some(ContainerConfig {
                metadata_name: "rootfs-container".into(),
                image: "fixture:latest".into(),
                command: vec!["/bin/busybox".into(), "sleep".into(), "30".into()],
                args: Vec::new(),
                env: Default::default(),
            }),
            sandbox_config: None,
        })
        .await
        .expect("container")
        .into_inner()
        .container_id;
    client
        .start_container(StartContainerRequest {
            container_id: container.clone(),
        })
        .await
        .expect("start container");

    // Exercise the daemon restart boundary while the workload is live. The
    // replacement server must recover the SQLite-backed CRI metadata and
    // report the same container identity/state before any new RPC is issued.
    server.abort();
    let _ = server.await;
    let socket_for_restart = socket.clone();
    let restarted_server = tokio::spawn(async move {
        let _ = ferro_cri::server::serve(socket_for_restart).await;
    });
    wait_for_socket(&socket).await;
    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let recovered = client
        .container_status(ContainerStatusRequest {
            container_id: container.clone(),
            verbose: false,
        })
        .await
        .expect("status after daemon restart")
        .into_inner()
        .status
        .expect("recovered status");
    assert_eq!(recovered.id, container);
    assert_eq!(
        recovered.state,
        ferro_cri::runtime::ContainerState::Running as i32
    );
    let exec = client
        .exec_sync(ferro_cri::runtime::ExecSyncRequest {
            container_id: container.clone(),
            cmd: vec!["/bin/busybox".into(), "echo".into(), "cri-ok".into()],
            timeout: 5,
        })
        .await
        .expect("exec sync")
        .into_inner();
    assert_eq!(
        exec.exit_code,
        0,
        "rootfs exec failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&exec.stdout),
        String::from_utf8_lossy(&exec.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&exec.stdout).trim(), "cri-ok");
    let timed_out = client
        .exec_sync(ferro_cri::runtime::ExecSyncRequest {
            container_id: container.clone(),
            cmd: vec!["/bin/busybox".into(), "sleep".into(), "30".into()],
            timeout: 1,
        })
        .await
        .expect_err("exec timeout must be reported");
    assert_eq!(timed_out.code(), tonic::Code::DeadlineExceeded);
    client
        .stop_container(ferro_cri::runtime::StopContainerRequest {
            container_id: container.clone(),
            timeout: 5,
        })
        .await
        .expect("stop");
    let stopped_status = client
        .container_status(ContainerStatusRequest {
            container_id: container.clone(),
            verbose: false,
        })
        .await
        .expect("status after stop")
        .into_inner()
        .status
        .expect("stopped status");
    assert_eq!(
        stopped_status.state,
        ferro_cri::runtime::ContainerState::Exited as i32
    );
    assert_eq!(stopped_status.reason, "exited");
    client
        .start_container(StartContainerRequest {
            container_id: container.clone(),
        })
        .await
        .expect("start stopped container");
    let restarted_status = client
        .container_status(ContainerStatusRequest {
            container_id: container.clone(),
            verbose: false,
        })
        .await
        .expect("status after CRI start")
        .into_inner()
        .status
        .expect("restarted status");
    assert_eq!(
        restarted_status.state,
        ferro_cri::runtime::ContainerState::Running as i32
    );
    client
        .stop_container(ferro_cri::runtime::StopContainerRequest {
            container_id: container.clone(),
            timeout: 5,
        })
        .await
        .expect("stop after CRI restart");
    client
        .stop_pod_sandbox(StopPodSandboxRequest {
            pod_sandbox_id: sandbox.clone(),
        })
        .await
        .expect("stop sandbox");
    client
        .remove_pod_sandbox(RemovePodSandboxRequest {
            pod_sandbox_id: sandbox,
        })
        .await
        .expect("remove sandbox");
    restarted_server.abort();
    let _ = restarted_server.await;
    unsafe {
        std::env::remove_var("FERROCRATE_RUNTIME_DIR");
    }
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn cri_socket_rejects_malformed_and_repeated_lifecycle_requests() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    let runtime = tempfile::tempdir().expect("runtime tempdir");
    let socket = runtime.path().join("cri-errors.sock");
    unsafe {
        std::env::set_var("FERROCRATE_RUNTIME_DIR", runtime.path());
    }
    let socket_for_server = socket.clone();
    let server = tokio::spawn(async move {
        let _ = ferro_cri::server::serve(socket_for_server).await;
    });
    wait_for_socket(&socket).await;

    let mut client = RuntimeServiceClient::new(connect_channel(socket.clone()).await);
    let invalid = client
        .run_pod_sandbox(RunPodSandboxRequest {
            config: None,
            runtime_handler: String::new(),
        })
        .await
        .expect_err("missing sandbox config must fail");
    assert_eq!(invalid.code(), tonic::Code::InvalidArgument);

    let missing = client
        .create_container(CreateContainerRequest {
            pod_sandbox_id: "missing-sandbox".into(),
            config: Some(ContainerConfig {
                metadata_name: "bad".into(),
                image: "missing:latest".into(),
                command: vec!["true".into()],
                args: Vec::new(),
                env: Default::default(),
            }),
            sandbox_config: None,
        })
        .await
        .expect_err("unknown sandbox must fail");
    assert_eq!(missing.code(), tonic::Code::NotFound);

    let sandbox = client
        .run_pod_sandbox(RunPodSandboxRequest {
            config: Some(PodSandboxConfig {
                metadata: Some(PodSandboxMetadata {
                    name: "idempotent-pod".into(),
                    uid: "idempotent-uid".into(),
                    namespace: "default".into(),
                    attempt: 1,
                }),
                hostname: "idempotent-pod".into(),
                log_directory: String::new(),
                dns_config: String::new(),
                network_namespace: "none".into(),
            }),
            runtime_handler: String::new(),
        })
        .await
        .expect("sandbox")
        .into_inner()
        .pod_sandbox_id;
    client
        .remove_pod_sandbox(RemovePodSandboxRequest {
            pod_sandbox_id: sandbox.clone(),
        })
        .await
        .expect("first remove");
    let repeated = client
        .remove_pod_sandbox(RemovePodSandboxRequest {
            pod_sandbox_id: sandbox,
        })
        .await
        .expect_err("repeated remove must be typed");
    assert_eq!(repeated.code(), tonic::Code::NotFound);

    server.abort();
    let _ = server.await;
    unsafe {
        std::env::remove_var("FERROCRATE_RUNTIME_DIR");
    }
}
