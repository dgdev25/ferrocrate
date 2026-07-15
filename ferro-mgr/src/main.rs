use std::{net::SocketAddr, sync::Arc};

use ferro_mgr::{enrollment::EnrollmentService, pki::CertificateAuthority, proto::{admin_service_server::AdminServiceServer, control_service_server::ControlServiceServer, enrollment_service_server::EnrollmentServiceServer}, rpc::{AdminServiceImpl, ControlServiceImpl, EnrollmentServiceImpl}, store::ManagerStore};
use tonic::transport::Server;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ferro_mgr::config::ManagerLimits::default().validate().expect("valid manager limits");
    let cluster_id = std::env::var("FERROCRATE_CLUSTER_ID").unwrap_or_else(|_| "local-cluster".into());
    let bind: SocketAddr = std::env::var("FERROCRATE_MANAGER_ADDR").unwrap_or_else(|_| "127.0.0.1:50051".into()).parse()?;
    let database = std::env::var("FERROCRATE_MANAGER_DB").unwrap_or_else(|_| "ferro-mgr.sqlite".into());
    let store = Arc::new(ManagerStore::open(database)?);
    let enrollment = Arc::new(EnrollmentService::new(cluster_id.clone(), store.clone()));
    let authority = Arc::new(CertificateAuthority::new(&format!("{cluster_id}-node-root"))?);
    Server::builder()
        .add_service(EnrollmentServiceServer::new(EnrollmentServiceImpl::new(enrollment, authority)))
        .add_service(ControlServiceServer::new(ControlServiceImpl::new(cluster_id, 1)))
        .add_service(AdminServiceServer::new(AdminServiceImpl::new(store, 1)))
        .serve(bind)
        .await?;
    Ok(())
}
