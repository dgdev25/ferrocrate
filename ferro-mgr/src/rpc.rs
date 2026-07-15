use std::sync::Arc;

use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::{desired_state::DesiredStateBuilder, enrollment::EnrollmentService, pki::CertificateAuthority, proto::{admin_service_server::AdminService, control_service_server::ControlService, enrollment_service_server::EnrollmentService as EnrollmentRpc, AdminRequest, AdminResponse, AgentMessage, EnrollRequest, EnrollResponse, ManagerMessage}, store::{Enrollment, ManagerStore}};

pub struct EnrollmentServiceImpl {
    service: Arc<EnrollmentService>,
    authority: Arc<CertificateAuthority>,
}

impl EnrollmentServiceImpl {
    pub fn new(service: Arc<EnrollmentService>, authority: Arc<CertificateAuthority>) -> Self { Self { service, authority } }
}

#[tonic::async_trait]
impl EnrollmentRpc for EnrollmentServiceImpl {
    async fn enroll(&self, request: Request<EnrollRequest>) -> Result<Response<EnrollResponse>, Status> {
        let request = request.into_inner();
        if request.node_id.is_empty() || request.public_key.len() != 32 || request.endpoint.is_empty() || request.csr.is_empty() { return Err(Status::invalid_argument("node_id, endpoint, public_key, and csr are required")); }
        let certificate = self.service.enroll_csr(&request.enrollment_token, Enrollment { node_id: request.node_id, public_key: request.public_key, endpoint: request.endpoint }, std::str::from_utf8(&request.csr).map_err(|_| Status::invalid_argument("csr must be PEM"))?, &self.authority).map_err(|_| Status::permission_denied("enrollment rejected"))?;
        Ok(Response::new(EnrollResponse { cluster_id: self.service.cluster_id().into(), cluster_epoch: 1, certificate: certificate.into_bytes(), ca_certificate: self.authority.certificate_pem().as_bytes().to_vec() }))
    }
}

pub struct ControlServiceImpl { builder: Arc<DesiredStateBuilder>, revision: u64 }
impl ControlServiceImpl {
    pub fn new(cluster_id: impl Into<String>, epoch: u64, signing_key: Vec<u8>) -> Self {
        Self { builder: Arc::new(DesiredStateBuilder::new(cluster_id, epoch, signing_key)), revision: 1 }
    }
}

#[tonic::async_trait]
impl ControlService for ControlServiceImpl {
    type ControlStreamStream = ReceiverStream<Result<ManagerMessage, Status>>;
    async fn control_stream(&self, request: Request<tonic::Streaming<AgentMessage>>) -> Result<Response<Self::ControlStreamStream>, Status> {
        let mut inbound = request.into_inner();
        let (sender, receiver) = tokio::sync::mpsc::channel(64);
        let builder = self.builder.clone();
        let revision = self.revision;
        tokio::spawn(async move {
            while let Ok(Some(message)) = inbound.message().await {
                if message.node_id.is_empty() { let _ = sender.send(Ok(ManagerMessage { desired_state: None, error: "node_id is required".into() })).await; continue; }
                let desired_state = builder.snapshot(revision, Vec::new(), chrono_like_now());
                let _ = sender.send(Ok(ManagerMessage { desired_state: Some(desired_state), error: String::new() })).await;
            }
        });
        Ok(Response::new(ReceiverStream::new(receiver)))
    }
}

fn chrono_like_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |duration| duration.as_secs() as i64)
}

pub struct AdminServiceImpl { store: Arc<ManagerStore>, cluster_epoch: u64 }
impl AdminServiceImpl { pub fn new(store: Arc<ManagerStore>, cluster_epoch: u64) -> Self { Self { store, cluster_epoch } } }

#[tonic::async_trait]
impl AdminService for AdminServiceImpl {
    async fn inspect(&self, request: Request<AdminRequest>) -> Result<Response<AdminResponse>, Status> {
        let request = request.into_inner();
        if request.cluster_id.is_empty() { return Err(Status::invalid_argument("cluster_id is required")); }
        let _ = &self.store;
        Ok(Response::new(AdminResponse { node_count: 0, cluster_epoch: self.cluster_epoch }))
    }
}
