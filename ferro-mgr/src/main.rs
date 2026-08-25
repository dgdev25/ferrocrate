use std::{
    collections::BTreeMap,
    net::SocketAddr,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
};

use base64::Engine as _;
use ed25519_dalek::SigningKey;
use ferro_core::authorization::helper_grant::{GrantIssuer, ResourceBinding};
use ferro_mgr::{
    controller_authorization::{ControllerGrantIssuer, ControllerPolicy},
    enrollment::EnrollmentService,
    fleet::{
        certificate_principal, AuditJournal, BrowserIdentity, FleetAssets, FleetRole, FleetUi,
        TonicFleetBackend,
    },
    pki::CertificateAuthority,
    pki::{certificate_identity_from_der, CertificateIdentity, CertificateRole},
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
    if std::env::args().nth(1).as_deref() == Some("fleet-ui") {
        return run_fleet_ui().await;
    }
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
    let node_ca_pem = std::fs::read(
        std::env::var("FERROCRATE_NODE_CA_CERT").expect("FERROCRATE_NODE_CA_CERT is required"),
    )?;
    let node_ca = Certificate::from_pem(node_ca_pem.clone());
    let admin_ca = Certificate::from_pem(std::fs::read(
        std::env::var("FERROCRATE_ADMIN_CA_CERT").expect("FERROCRATE_ADMIN_CA_CERT is required"),
    )?);
    let identity = Identity::from_pem(cert, key);
    let database =
        std::env::var("FERROCRATE_MANAGER_DB").unwrap_or_else(|_| "ferro-mgr.sqlite".into());
    let store = Arc::new(ManagerStore::open(database)?);
    let cluster_epoch = store.cluster_epoch()?;
    let enrollment = Arc::new(EnrollmentService::new(cluster_id.clone(), store.clone()));
    let node_ca_key = std::fs::read_to_string(
        std::env::var("FERROCRATE_NODE_CA_KEY").expect("FERROCRATE_NODE_CA_KEY is required"),
    )?;
    let authority = Arc::new(CertificateAuthority::from_pem(
        std::str::from_utf8(&node_ca_pem)?,
        &node_ca_key,
    )?);
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
    let control_service = ControlServiceServer::with_interceptor(
        control_impl.as_ref().clone(),
        move |mut request: tonic::Request<()>| {
            use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
            let identity = request
                .extensions()
                .get::<TlsConnectInfo<TcpConnectInfo>>()
                .and_then(TlsConnectInfo::peer_certs)
                .and_then(|certificates| {
                    certificates
                        .first()
                        .map(|certificate| certificate_identity_from_der(certificate.as_ref()))
                })
                .ok_or_else(|| {
                    tonic::Status::unauthenticated("node client certificate is required")
                })?
                .map_err(|_| {
                    tonic::Status::unauthenticated("node certificate principal is invalid")
                })?;
            if !matches!(identity.role, CertificateRole::Node { .. }) {
                return Err(tonic::Status::permission_denied(
                    "node certificate role is required",
                ));
            }
            request.extensions_mut().insert(identity);
            Ok(request)
        },
    );
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

struct FleetUiOptions {
    listen: SocketAddr,
    insecure_loopback: bool,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    admin_endpoint: String,
    admin_domain: String,
    admin_server_ca: PathBuf,
    operator_cert: PathBuf,
    operator_key: PathBuf,
    state_dir: PathBuf,
    cluster_id: String,
}

impl FleetUiOptions {
    fn parse() -> Result<Self, String> {
        let mut listen: SocketAddr = "127.0.0.1:8443".parse().expect("static address");
        let mut insecure_loopback = false;
        let mut tls_cert = std::env::var_os("FERROCRATE_MANAGER_TLS_CERT").map(PathBuf::from);
        let mut tls_key = std::env::var_os("FERROCRATE_MANAGER_TLS_KEY").map(PathBuf::from);
        let mut admin_endpoint = std::env::var("FERROCRATE_ADMIN_ENDPOINT")
            .unwrap_or_else(|_| "https://127.0.0.1:50052".into());
        let mut admin_domain =
            std::env::var("FERROCRATE_ADMIN_TLS_DOMAIN").unwrap_or_else(|_| "localhost".into());
        let mut admin_server_ca =
            std::env::var_os("FERROCRATE_ADMIN_SERVER_CA_CERT").map(PathBuf::from);
        let mut operator_cert = std::env::var_os("FERROCRATE_ADMIN_TLS_CERT").map(PathBuf::from);
        let mut operator_key = std::env::var_os("FERROCRATE_ADMIN_TLS_KEY").map(PathBuf::from);
        let mut state_dir = std::env::var_os("FERROCRATE_FLEET_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(".ferrocrate-fleet"));
        let cluster_id =
            std::env::var("FERROCRATE_CLUSTER_ID").unwrap_or_else(|_| "local-cluster".into());
        let mut arguments = std::env::args().skip(2);
        while let Some(argument) = arguments.next() {
            let value = |arguments: &mut std::iter::Skip<std::env::Args>, name: &str| {
                arguments
                    .next()
                    .ok_or_else(|| format!("{name} requires a value"))
            };
            match argument.as_str() {
                "--listen" => {
                    listen = value(&mut arguments, "--listen")?
                        .parse()
                        .map_err(|error| format!("invalid --listen address: {error}"))?;
                }
                "--insecure-loopback" => insecure_loopback = true,
                "--tls-cert" => tls_cert = Some(value(&mut arguments, "--tls-cert")?.into()),
                "--tls-key" => tls_key = Some(value(&mut arguments, "--tls-key")?.into()),
                "--admin-endpoint" => admin_endpoint = value(&mut arguments, "--admin-endpoint")?,
                "--admin-domain" => admin_domain = value(&mut arguments, "--admin-domain")?,
                "--admin-server-ca" => {
                    admin_server_ca = Some(value(&mut arguments, "--admin-server-ca")?.into())
                }
                "--operator-cert" => {
                    operator_cert = Some(value(&mut arguments, "--operator-cert")?.into())
                }
                "--operator-key" => {
                    operator_key = Some(value(&mut arguments, "--operator-key")?.into())
                }
                "--state-dir" => state_dir = value(&mut arguments, "--state-dir")?.into(),
                _ => return Err(format!("unknown fleet-ui argument {argument}")),
            }
        }
        if insecure_loopback && !listen.ip().is_loopback() {
            return Err("--insecure-loopback is valid only for a loopback listener".into());
        }
        if !insecure_loopback && (tls_cert.is_none() || tls_key.is_none()) {
            return Err("fleet-ui is TLS-only; --tls-cert and --tls-key are required".into());
        }
        Ok(Self {
            listen,
            insecure_loopback,
            tls_cert,
            tls_key,
            admin_endpoint,
            admin_domain,
            admin_server_ca: admin_server_ca
                .ok_or_else(|| "--admin-server-ca is required".to_string())?,
            operator_cert: operator_cert
                .ok_or_else(|| "--operator-cert is required".to_string())?,
            operator_key: operator_key.ok_or_else(|| "--operator-key is required".to_string())?,
            state_dir,
            cluster_id,
        })
    }
}

async fn run_fleet_ui() -> Result<(), Box<dyn std::error::Error>> {
    let options = FleetUiOptions::parse()?;
    std::fs::create_dir_all(&options.state_dir)?;
    std::fs::set_permissions(&options.state_dir, std::fs::Permissions::from_mode(0o700))?;
    let server_ca = std::fs::read(&options.admin_server_ca)?;
    let operator_cert = std::fs::read(&options.operator_cert)?;
    let operator_key = std::fs::read(&options.operator_key)?;
    let principal = certificate_principal(&operator_cert)?;
    let backend = Arc::new(
        TonicFleetBackend::connect(
            options.admin_endpoint,
            options.admin_domain,
            server_ca,
            operator_cert,
            operator_key,
            options.cluster_id,
        )
        .await?,
    );
    let audit = Arc::new(AuditJournal::open(options.state_dir.join("audit.jsonl"))?);
    let ui = FleetUi::new(Arc::new(FleetAssets), backend, audit, 600)?;
    let operate_login = ui.mint_login(
        BrowserIdentity {
            principal: principal.clone(),
            role: FleetRole::Operate,
        },
        300,
    )?;
    let view_login = ui.mint_login(
        BrowserIdentity {
            principal,
            role: FleetRole::View,
        },
        300,
    )?;
    let operate_path = options.state_dir.join("operate.login");
    let view_path = options.state_dir.join("view.login");
    write_secret(&operate_path, &operate_login)?;
    write_secret(&view_path, &view_login)?;
    eprintln!(
        "fleet UI ready on {} (operate login: {}; view login: {})",
        options.listen,
        operate_path.display(),
        view_path.display()
    );
    if options.insecure_loopback {
        ui.spawn_insecure_loopback(options.listen)
            .await?
            .wait()
            .await?;
    } else {
        ui.serve_tls(
            options.listen,
            options.tls_cert.as_deref().expect("validated TLS cert"),
            options.tls_key.as_deref().expect("validated TLS key"),
        )
        .await?;
    }
    Ok(())
}

fn write_secret(path: &Path, value: &str) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write as _;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::Builder::new()
        .prefix(".fleet-login-")
        .tempfile_in(parent)?;
    temporary
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    writeln!(temporary, "{value}")?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    std::fs::File::open(parent)?.sync_all()?;
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
