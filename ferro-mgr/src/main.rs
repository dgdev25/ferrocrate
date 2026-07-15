use std::{net::SocketAddr, sync::Arc};

use base64::Engine as _;
use ferro_mgr::{enrollment::EnrollmentService, pki::CertificateAuthority, proto::{admin_service_server::AdminServiceServer, control_service_server::ControlServiceServer, enrollment_service_server::EnrollmentServiceServer}, rpc::{AdminServiceImpl, ControlServiceImpl, EnrollmentServiceImpl}, store::ManagerStore};
use tonic::transport::{Identity, Server, ServerTlsConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ferro_mgr::config::ManagerLimits::default().validate().expect("valid manager limits");
    let cluster_id = std::env::var("FERROCRATE_CLUSTER_ID").unwrap_or_else(|_| "local-cluster".into());
    let signing_key = base64::engine::general_purpose::STANDARD.decode(std::env::var("FERROCRATE_MANAGER_SIGNING_KEY").expect("FERROCRATE_MANAGER_SIGNING_KEY is required")).expect("FERROCRATE_MANAGER_SIGNING_KEY must be base64");
    if signing_key.len() != 32 { return Err("FERROCRATE_MANAGER_SIGNING_KEY must decode to 32 bytes".into()); }
    let bind: SocketAddr = std::env::var("FERROCRATE_MANAGER_ADDR").unwrap_or_else(|_| "127.0.0.1:50051".into()).parse()?;
    let admin_bind: SocketAddr = std::env::var("FERROCRATE_ADMIN_ADDR").unwrap_or_else(|_| "127.0.0.1:50052".into()).parse()?;
    let cert = std::fs::read(std::env::var("FERROCRATE_MANAGER_TLS_CERT").expect("FERROCRATE_MANAGER_TLS_CERT is required"))?;
    let key = std::fs::read(std::env::var("FERROCRATE_MANAGER_TLS_KEY").expect("FERROCRATE_MANAGER_TLS_KEY is required"))?;
    let tls = ServerTlsConfig::new().identity(Identity::from_pem(cert, key));
    let database = std::env::var("FERROCRATE_MANAGER_DB").unwrap_or_else(|_| "ferro-mgr.sqlite".into());
    let store = Arc::new(ManagerStore::open(database)?);
    let enrollment = Arc::new(EnrollmentService::new(cluster_id.clone(), store.clone()));
    let authority = Arc::new(CertificateAuthority::new(&format!("{cluster_id}-node-root"))?);
    let public = Server::builder().tls_config(tls.clone())?
        .add_service(EnrollmentServiceServer::new(EnrollmentServiceImpl::new(enrollment, authority)))
        .add_service(ControlServiceServer::new(ControlServiceImpl::new(cluster_id, 1, signing_key)))
        .serve(bind);
    let admin = Server::builder().tls_config(tls)?
        .add_service(AdminServiceServer::new(AdminServiceImpl::new(store, 1)))
        .serve(admin_bind);
    tokio::try_join!(public, admin)?;
    Ok(())
}
