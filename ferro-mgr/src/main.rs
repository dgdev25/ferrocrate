use std::{net::SocketAddr, sync::Arc};

use base64::Engine as _;
use ferro_mgr::{enrollment::EnrollmentService, pki::CertificateAuthority, proto::{admin_service_server::AdminServiceServer, control_service_server::ControlServiceServer, enrollment_service_server::EnrollmentServiceServer}, rpc::{AdminServiceImpl, ControlServiceImpl, EnrollmentServiceImpl}, store::ManagerStore};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ferro_mgr::config::ManagerLimits::default().validate().expect("valid manager limits");
    let cluster_id = std::env::var("FERROCRATE_CLUSTER_ID").unwrap_or_else(|_| "local-cluster".into());
    let signing_key = base64::engine::general_purpose::STANDARD.decode(std::env::var("FERROCRATE_MANAGER_SIGNING_KEY").expect("FERROCRATE_MANAGER_SIGNING_KEY is required")).expect("FERROCRATE_MANAGER_SIGNING_KEY must be base64");
    if signing_key.len() != 32 { return Err("FERROCRATE_MANAGER_SIGNING_KEY must decode to 32 bytes".into()); }
    let bind: SocketAddr = std::env::var("FERROCRATE_MANAGER_ADDR").unwrap_or_else(|_| "127.0.0.1:50051".into()).parse()?;
    let admin_bind: SocketAddr = std::env::var("FERROCRATE_ADMIN_ADDR").unwrap_or_else(|_| "127.0.0.1:50052".into()).parse()?;
    let control_bind: SocketAddr = std::env::var("FERROCRATE_CONTROL_ADDR").unwrap_or_else(|_| "127.0.0.1:50053".into()).parse()?;
    let cert = std::fs::read(std::env::var("FERROCRATE_MANAGER_TLS_CERT").expect("FERROCRATE_MANAGER_TLS_CERT is required"))?;
    let key = std::fs::read(std::env::var("FERROCRATE_MANAGER_TLS_KEY").expect("FERROCRATE_MANAGER_TLS_KEY is required"))?;
    let node_ca = Certificate::from_pem(std::fs::read(std::env::var("FERROCRATE_NODE_CA_CERT").expect("FERROCRATE_NODE_CA_CERT is required"))?);
    let admin_ca = Certificate::from_pem(std::fs::read(std::env::var("FERROCRATE_ADMIN_CA_CERT").expect("FERROCRATE_ADMIN_CA_CERT is required"))?);
    let identity = Identity::from_pem(cert, key);
    let database = std::env::var("FERROCRATE_MANAGER_DB").unwrap_or_else(|_| "ferro-mgr.sqlite".into());
    let store = Arc::new(ManagerStore::open(database)?);
    let cluster_epoch = store.cluster_epoch()?;
    let enrollment = Arc::new(EnrollmentService::new(cluster_id.clone(), store.clone()));
    let authority = Arc::new(CertificateAuthority::new(&format!("{cluster_id}-node-root"))?);
    let enrollment_service = EnrollmentServiceServer::new(EnrollmentServiceImpl::new(enrollment.clone(), authority.clone()));
    let control_service = ControlServiceServer::new(ControlServiceImpl::new(cluster_id, cluster_epoch, signing_key, store.clone()));
    let admin_service = AdminServiceServer::new(AdminServiceImpl::new(store, cluster_epoch));
    let public = Server::builder().tls_config(ServerTlsConfig::new().identity(identity.clone()))?
        .add_service(enrollment_service)
        .serve(bind);
    let control = Server::builder().tls_config(ServerTlsConfig::new().identity(identity.clone()).client_ca_root(node_ca))?
        .add_service(control_service)
        .serve(control_bind);
    let admin = Server::builder().tls_config(ServerTlsConfig::new().identity(identity).client_ca_root(admin_ca))?
        .add_service(admin_service)
        .serve(admin_bind);
    tokio::try_join!(public, control, admin)?;
    Ok(())
}
