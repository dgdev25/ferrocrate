use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use ferro_core::authorization::helper_grant::{GrantIssuer, ResourceBinding};
use ferro_mgr::{
    controller_authorization::{ControllerGrantIssuer, ControllerPolicy},
    enrollment::EnrollmentService,
    pki::CertificateAuthority,
    pki::{CertificateIdentity, CertificateRole},
    proto::{
        admin_service_server::AdminServiceServer, control_service_server::ControlServiceServer,
        enrollment_service_server::EnrollmentServiceServer,
    },
    rpc::{AdminServiceImpl, ControlServiceImpl, EnrollmentServiceImpl},
    store::ManagerStore,
};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ferro_mgr::config::ManagerLimits::default()
        .validate()
        .expect("valid manager limits");
    let cluster_id =
        std::env::var("FERROCRATE_CLUSTER_ID").unwrap_or_else(|_| "local-cluster".into());
    let signing_key = base64::engine::general_purpose::STANDARD
        .decode(
            std::env::var("FERROCRATE_MANAGER_SIGNING_KEY")
                .expect("FERROCRATE_MANAGER_SIGNING_KEY is required"),
        )
        .expect("FERROCRATE_MANAGER_SIGNING_KEY must be base64");
    if signing_key.len() != 32 {
        return Err("FERROCRATE_MANAGER_SIGNING_KEY must decode to 32 bytes".into());
    }
    let bind: SocketAddr = std::env::var("FERROCRATE_MANAGER_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50051".into())
        .parse()?;
    let admin_bind: SocketAddr = std::env::var("FERROCRATE_ADMIN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50052".into())
        .parse()?;
    let control_bind: SocketAddr = std::env::var("FERROCRATE_CONTROL_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:50053".into())
        .parse()?;
    let cert = std::fs::read(
        std::env::var("FERROCRATE_MANAGER_TLS_CERT")
            .expect("FERROCRATE_MANAGER_TLS_CERT is required"),
    )?;
    let key = std::fs::read(
        std::env::var("FERROCRATE_MANAGER_TLS_KEY")
            .expect("FERROCRATE_MANAGER_TLS_KEY is required"),
    )?;
    let node_ca = Certificate::from_pem(std::fs::read(
        std::env::var("FERROCRATE_NODE_CA_CERT").expect("FERROCRATE_NODE_CA_CERT is required"),
    )?);
    let admin_ca = Certificate::from_pem(std::fs::read(
        std::env::var("FERROCRATE_ADMIN_CA_CERT").expect("FERROCRATE_ADMIN_CA_CERT is required"),
    )?);
    let identity = Identity::from_pem(cert, key);
    let database =
        std::env::var("FERROCRATE_MANAGER_DB").unwrap_or_else(|_| "ferro-mgr.sqlite".into());
    let store = Arc::new(ManagerStore::open(database)?);
    let cluster_epoch = store.cluster_epoch()?;
    let enrollment = Arc::new(EnrollmentService::new(cluster_id.clone(), store.clone()));
    let authority = Arc::new(CertificateAuthority::new(&format!(
        "{cluster_id}-node-root"
    ))?);
    let enrollment_service = EnrollmentServiceServer::new(EnrollmentServiceImpl::new(
        enrollment.clone(),
        authority.clone(),
    ));
    let controller_grants = GrantIssuer::from_key_file(
        std::env::var("FERROCRATE_CONTROLLER_GRANT_KEY_ID")
            .map_err(|_| "FERROCRATE_CONTROLLER_GRANT_KEY_ID is required")?,
        std::path::Path::new(
            &std::env::var("FERROCRATE_CONTROLLER_GRANT_SIGNING_KEY_FILE")
                .map_err(|_| "FERROCRATE_CONTROLLER_GRANT_SIGNING_KEY_FILE is required")?,
        ),
        nix::unistd::Uid::effective().as_raw(),
    )?;
    let envelope_key = read_secure_key(
        &std::env::var("FERROCRATE_CONTROLLER_ENVELOPE_SIGNING_KEY_FILE")
            .map_err(|_| "FERROCRATE_CONTROLLER_ENVELOPE_SIGNING_KEY_FILE is required")?,
    )?;
    let allowed_nodes: Vec<String> = serde_json::from_str(
        &std::env::var("FERROCRATE_CONTROLLER_ALLOWED_NODES_JSON")
            .map_err(|_| "FERROCRATE_CONTROLLER_ALLOWED_NODES_JSON is required")?,
    )?;
    let resources: BTreeMap<String, ResourceBinding> = serde_json::from_str(
        &std::env::var("FERROCRATE_CONTROLLER_RESOURCES_JSON")
            .map_err(|_| "FERROCRATE_CONTROLLER_RESOURCES_JSON is required")?,
    )?;
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    let controller = ControllerGrantIssuer::new(
        controller_grants,
        SigningKey::from_bytes(&envelope_key),
        std::env::var("FERROCRATE_CONTROLLER_GRANT_ISSUER")
            .map_err(|_| "FERROCRATE_CONTROLLER_GRANT_ISSUER is required")?,
        boot_id,
        ControllerPolicy::new(allowed_nodes, resources),
    );
    let control_impl = Arc::new(ControlServiceImpl::new_authorized(
        cluster_id.clone(),
        cluster_epoch,
        signing_key,
        store.clone(),
        controller,
    ));
    let control_service = ControlServiceServer::from_arc(control_impl.clone());
    let admin_impl =
        AdminServiceImpl::new_authorized(store, cluster_epoch, cluster_id.clone(), control_impl);
    let admin_cluster = cluster_id.clone();
    let admin_service =
        AdminServiceServer::with_interceptor(admin_impl, move |mut request: tonic::Request<()>| {
            use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
            let authenticated = request
                .extensions()
                .get::<TlsConnectInfo<TcpConnectInfo>>()
                .and_then(TlsConnectInfo::peer_certs)
                .is_some_and(|certificates| !certificates.is_empty());
            if !authenticated {
                return Err(tonic::Status::unauthenticated(
                    "administrator client certificate is required",
                ));
            }
            request.extensions_mut().insert(CertificateIdentity {
                cluster_id: admin_cluster.clone(),
                role: CertificateRole::Administrator,
                // rustls has already checked certificate validity against the admin CA.
                expires_at: i64::MAX,
            });
            Ok(request)
        });
    let public = Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity.clone()))?
        .add_service(enrollment_service)
        .serve(bind);
    let control = Server::builder()
        .tls_config(
            ServerTlsConfig::new()
                .identity(identity.clone())
                .client_ca_root(node_ca),
        )?
        .add_service(control_service)
        .serve(control_bind);
    let admin = Server::builder()
        .tls_config(
            ServerTlsConfig::new()
                .identity(identity)
                .client_ca_root(admin_ca),
        )?
        .add_service(admin_service)
        .serve(admin_bind);
    tokio::try_join!(public, control, admin)?;
    Ok(())
}

fn read_secure_key(path: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    use std::{
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    };
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != nix::unistd::Uid::effective().as_raw()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("controller envelope key custody check failed".into());
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    bytes
        .try_into()
        .map_err(|_| "controller envelope key must contain exactly 32 bytes".into())
}
