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
    StatusRequest, StopPodSandboxRequest, VersionRequest,
};
use ferro_cri::runtime::{ImageSpec, PullImageRequest, RemoveImageRequest};
use ferro_cri::server::{
    CriDelegationClaims, CriDelegationVerifier, CriIdentityPolicy, DelegationAssertion,
    DelegationTrustKey,
};
use httptest::matchers::request;
use httptest::responders::status_code;
use httptest::{Expectation, Server};
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
    let manifest = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:46b68ac1696c3870d537f376868d9402400de28587e345264a77b65da09669be","size":1},"layers":[]}"#;
    registry.expect(
        Expectation::matching(request::method_path(
            "GET",
            "/v2/library/alpine/manifests/latest",
        ))
        .times(2)
        .respond_with(status_code(200).body(manifest)),
    );
    let manifest_digest = "sha256:1b75874027e3aa933373ebaaa9720a85e38f14be533478e9c3cc9163ff021544";
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
        let manifest = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:46b68ac1696c3870d537f376868d9402400de28587e345264a77b65da09669be","size":1},"layers":[]}"#;
        registry.expect(
            Expectation::matching(request::method_path(
                "GET",
                "/v2/library/alpine/manifests/latest",
            ))
            .times(0..=1)
            .respond_with(status_code(200).body(manifest)),
        );
        let manifest_digest =
            "sha256:1b75874027e3aa933373ebaaa9720a85e38f14be533478e9c3cc9163ff021544";
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
            async move { UnixStream::connect(socket_path).await }
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
#[allow(clippy::await_holding_lock)]
async fn cri_network_effect_crash_is_cleaned_from_pending_state() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
    if Command::new("id")
        .arg("-u")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim() != "0")
        .unwrap_or(true)
    {
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
    if Command::new("id")
        .arg("-u")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim() != "0")
        .unwrap_or(true)
    {
        eprintln!("skipping real CRI rootfs fixture: root is required");
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
    assert_eq!(exec.exit_code, 0);
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
