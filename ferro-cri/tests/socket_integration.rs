use ed25519_dalek::{Signer, SigningKey};
use ferro_core::authorization::{Action, PrincipalResolver};
use ferro_cri::runtime::image_service_client::ImageServiceClient;
use ferro_cri::runtime::runtime_service_client::RuntimeServiceClient;
use ferro_cri::runtime::{ImageFsInfoRequest, ListImagesRequest, StatusRequest, VersionRequest};
use ferro_cri::runtime::{ImageSpec, PullImageRequest, RemoveImageRequest};
use ferro_cri::server::{
    CriDelegationClaims, CriDelegationVerifier, CriIdentityPolicy, DelegationAssertion,
    DelegationTrustKey,
};
use httptest::matchers::request;
use httptest::responders::status_code;
use httptest::{Expectation, Server};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;

static ENV_LOCK: Mutex<()> = Mutex::new(());

async fn wait_for_socket(path: &std::path::Path) {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("CRI socket did not appear: {}", path.display());
}

#[tokio::test]
#[allow(clippy::await_holding_lock)]
async fn cri_wire_delegation_accepts_once_and_rejects_replay_expiry_and_tampering() {
    let _env_guard = ENV_LOCK.lock().expect("lock env");
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
    let verifier = CriDelegationVerifier::open(
        vec![DelegationTrustKey::developer(
            "issuer",
            "wire-key",
            signing.verifying_key(),
        )],
        "ferro-cri",
        "test-boot",
        [5; 32],
        runtime.path().join("replay"),
    )
    .unwrap();
    let policy = CriIdentityPolicy::with_signed_verifier("wire", Arc::new(verifier));
    let socket_for_server = socket.clone();
    let server = tokio::spawn(async move {
        let _ = ferro_cri::server::serve_with_identity_policy(socket_for_server, policy).await;
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
            "ferro-cri",
            "delegated-user",
            vec![action],
            vec![resource.clone()],
            nonce,
            deadline,
            "test-boot",
            [5; 32],
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
