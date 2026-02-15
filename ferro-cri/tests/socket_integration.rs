use ferro_cri::runtime::image_service_client::ImageServiceClient;
use ferro_cri::runtime::runtime_service_client::RuntimeServiceClient;
use ferro_cri::runtime::{ImageFsInfoRequest, ListImagesRequest, StatusRequest, VersionRequest};
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
