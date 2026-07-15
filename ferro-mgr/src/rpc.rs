use std::{collections::HashSet, sync::{Arc, Mutex}};

use prost::Message;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::{desired_state::DesiredStateBuilder, enrollment::EnrollmentService, pki::CertificateAuthority, proto::{admin_service_server::AdminService, control_service_server::ControlService, enrollment_service_server::EnrollmentService as EnrollmentRpc, AdminRequest, AdminResponse, AgentMessage, DesiredState, EnrollRequest, EnrollResponse, ManagerMessage}, store::{Enrollment, ManagerStore}};

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

pub struct ControlServiceImpl { builder: Arc<DesiredStateBuilder>, revision: u64, store: Arc<ManagerStore>, active_nodes: Arc<Mutex<HashSet<String>>> }
impl ControlServiceImpl {
    pub fn new(cluster_id: impl Into<String>, epoch: u64, signing_key: Vec<u8>, store: Arc<ManagerStore>) -> Self {
        Self { builder: Arc::new(DesiredStateBuilder::new(cluster_id, epoch, signing_key)), revision: 1, store, active_nodes: Arc::new(Mutex::new(HashSet::new())) }
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
        let store = self.store.clone();
        let active_nodes = self.active_nodes.clone();
        tokio::spawn(async move {
            let mut bound_node = None;
            while let Ok(Some(message)) = inbound.message().await {
                if message.node_id.is_empty() { let _ = sender.send(Ok(ManagerMessage { desired_state: None, error: "node_id is required".into() })).await; continue; }
                if bound_node.as_deref() != Some(message.node_id.as_str()) {
                    if bound_node.is_some() { let _ = sender.send(Ok(ManagerMessage { desired_state: None, error: "node identity changed within stream".into() })).await; break; }
                    let duplicate = match active_nodes.lock() { Ok(mut active) => !active.insert(message.node_id.clone()), Err(_) => true };
                    if duplicate { let _ = sender.send(Ok(ManagerMessage { desired_state: None, error: "node already has an active control stream".into() })).await; break; }
                    bound_node = Some(message.node_id.clone());
                }
                match store.node_is_active(&message.node_id) {
                    Ok(true) => {}
                    Ok(false) | Err(_) => { let _ = sender.send(Ok(ManagerMessage { desired_state: None, error: "node is not enrolled or has been revoked".into() })).await; continue; }
                }
                if message.acknowledged_revision > revision { let _ = sender.send(Ok(ManagerMessage { desired_state: None, error: "acknowledged revision is ahead of manager".into() })).await; continue; }
                let desired_state = match store.latest_revision() {
                    Ok(Some((_, payload))) => match DesiredState::decode(payload.as_slice()) {
                        Ok(state) => state,
                        Err(_) => { let _ = sender.send(Ok(ManagerMessage { desired_state: None, error: "persisted desired state is invalid".into() })).await; continue; }
                    },
                    Ok(None) => builder.snapshot(revision, Vec::new(), chrono_like_now()),
                    Err(_) => { let _ = sender.send(Ok(ManagerMessage { desired_state: None, error: "manager state unavailable".into() })).await; continue; }
                };
                let _ = sender.send(Ok(ManagerMessage { desired_state: Some(desired_state), error: String::new() })).await;
            }
            if let Some(node_id) = bound_node { if let Ok(mut active) = active_nodes.lock() { active.remove(&node_id); } }
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
        let node_count = self.store.node_count().map_err(|_| Status::internal("manager state unavailable"))?;
        Ok(Response::new(AdminResponse { node_count, cluster_epoch: self.cluster_epoch }))
    }
}
