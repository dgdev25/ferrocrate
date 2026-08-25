use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};

use prost::Message;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::{
    admin::AdminAuthorizer,
    controller_authorization::{ControllerAuthorizationError, ControllerGrantIssuer},
    desired_state::DesiredStateBuilder,
    enrollment::EnrollmentService,
    fleet::{build_agent_cli_args, ControlHub, FleetCommandResult},
    pki::CertificateAuthority,
    proto::{
        admin_service_server::AdminService, control_service_server::ControlService,
        enrollment_service_server::EnrollmentService as EnrollmentRpc, AdminRequest, AdminResponse,
        AgentMessage, DesiredState, EnrollRequest, EnrollResponse, FleetCommandRequest,
        FleetCommandResponse, FleetDeployRequest, FleetDeployResponse, FleetRevokeRequest,
        FleetRevokeResponse, FleetRollbackRequest, FleetSnapshotRequest, FleetSnapshotResponse,
        ManagerMessage, PublishDesiredRequest, PublishDesiredResponse,
    },
    store::{Enrollment, FleetDeployment, HostObservation, ManagerStore},
};

pub struct EnrollmentServiceImpl {
    service: Arc<EnrollmentService>,
    authority: Arc<CertificateAuthority>,
}

impl EnrollmentServiceImpl {
    pub fn new(service: Arc<EnrollmentService>, authority: Arc<CertificateAuthority>) -> Self {
        Self { service, authority }
    }
}

#[tonic::async_trait]
impl EnrollmentRpc for EnrollmentServiceImpl {
    async fn enroll(
        &self,
        request: Request<EnrollRequest>,
    ) -> Result<Response<EnrollResponse>, Status> {
        let request = request.into_inner();
        if request.node_id.is_empty()
            || request.public_key.len() != 32
            || request.endpoint.is_empty()
            || request.csr.is_empty()
        {
            return Err(Status::invalid_argument(
                "node_id, endpoint, public_key, and csr are required",
            ));
        }
        let certificate = self
            .service
            .enroll_csr(
                &request.enrollment_token,
                Enrollment {
                    node_id: request.node_id,
                    public_key: request.public_key,
                    endpoint: request.endpoint,
                },
                std::str::from_utf8(&request.csr)
                    .map_err(|_| Status::invalid_argument("csr must be PEM"))?,
                &self.authority,
            )
            .map_err(|_| Status::permission_denied("enrollment rejected"))?;
        Ok(Response::new(EnrollResponse {
            cluster_id: self.service.cluster_id().into(),
            cluster_epoch: 1,
            certificate: certificate.into_bytes(),
            ca_certificate: self.authority.certificate_pem().as_bytes().to_vec(),
        }))
    }
}

pub struct ControlServiceImpl {
    builder: Arc<DesiredStateBuilder>,
    revision: u64,
    store: Arc<ManagerStore>,
    active_nodes: Arc<Mutex<HashSet<String>>>,
    controller: Option<Arc<ControllerGrantIssuer>>,
    fleet_hub: Arc<ControlHub>,
}
impl ControlServiceImpl {
    pub fn new(
        cluster_id: impl Into<String>,
        epoch: u64,
        signing_key: Vec<u8>,
        store: Arc<ManagerStore>,
    ) -> Self {
        let fleet_hub = Arc::new(ControlHub::new(store.clone()));
        Self {
            builder: Arc::new(DesiredStateBuilder::new(cluster_id, epoch, signing_key)),
            revision: 1,
            store,
            active_nodes: Arc::new(Mutex::new(HashSet::new())),
            controller: None,
            fleet_hub,
        }
    }
    pub fn new_authorized(
        cluster_id: impl Into<String>,
        epoch: u64,
        signing_key: Vec<u8>,
        store: Arc<ManagerStore>,
        controller: ControllerGrantIssuer,
    ) -> Self {
        let mut service = Self::new(cluster_id, epoch, signing_key, store);
        service.controller = Some(Arc::new(controller));
        service
    }
    pub fn publish_desired(
        &self,
        node_id: &str,
        overlays: Vec<crate::proto::OverlayState>,
        current: &[String],
        now_unix: i64,
        now_monotonic_millis: u64,
    ) -> Result<u64, String> {
        let controller = self
            .controller
            .as_ref()
            .ok_or_else(|| "controller grant issuer is required".to_string())?;
        if !self
            .store
            .node_is_active(node_id)
            .map_err(|e| e.to_string())?
        {
            return Err("target node is not enrolled or has been revoked".into());
        }
        let revision = self.store.next_revision().map_err(|e| e.to_string())?;
        let desired = self.builder.snapshot(revision, overlays, now_unix);
        let prior = self
            .store
            .latest_authorized_revision(node_id)
            .map_err(|e| e.to_string())?
            .and_then(|(_, payload, _)| DesiredState::decode(payload.as_slice()).ok());
        if prior.is_none() && !current.is_empty() {
            return Err("prior authorized desired state is unavailable".into());
        }
        let overlay_id = desired
            .overlays
            .first()
            .map(|overlay| overlay.overlay_id.clone())
            .or_else(|| {
                prior
                    .as_ref()
                    .and_then(|state| state.overlays.first())
                    .map(|overlay| overlay.overlay_id.clone())
            })
            .ok_or_else(|| "empty desired state has no prior authorized resource".to_string())?;
        let operations = controller
            .issue_exact_diff_from_state(&desired, node_id, prior.as_ref(), now_monotonic_millis)
            .map_err(|e| match e {
                ControllerAuthorizationError::Denied { resource } => {
                    format!("controller policy denied {resource}")
                }
                other => other.to_string(),
            })?;
        let bundle = self
            .builder
            .authorization_bundle(&desired, node_id, operations)
            .map_err(|e| e.to_string())?;
        self.store
            .append_authorized_revision_at(
                revision,
                &overlay_id,
                node_id,
                &desired.encode_to_vec(),
                &bundle,
            )
            .map_err(|e| e.to_string())?;
        Ok(revision)
    }

    pub fn fleet_hub(&self) -> Arc<ControlHub> {
        self.fleet_hub.clone()
    }
}

#[tonic::async_trait]
impl ControlService for ControlServiceImpl {
    type ControlStreamStream = ReceiverStream<Result<ManagerMessage, Status>>;
    async fn control_stream(
        &self,
        request: Request<tonic::Streaming<AgentMessage>>,
    ) -> Result<Response<Self::ControlStreamStream>, Status> {
        let mut inbound = request.into_inner();
        let (sender, receiver) = tokio::sync::mpsc::channel(64);
        let builder = self.builder.clone();
        let revision = self.revision;
        let store = self.store.clone();
        let active_nodes = self.active_nodes.clone();
        let fleet_hub = self.fleet_hub.clone();
        tokio::spawn(async move {
            let mut bound_node = None;
            let mut command_forward = None;
            while let Ok(Some(message)) = inbound.message().await {
                if message.node_id.is_empty() {
                    let _ = sender
                        .send(Ok(ManagerMessage {
                            desired_state: None,
                            error: "node_id is required".into(),
                            desired_authorization_bundle: Vec::new(),
                            command_json: Vec::new(),
                        }))
                        .await;
                    continue;
                }
                if bound_node.as_deref() != Some(message.node_id.as_str()) {
                    if bound_node.is_some() {
                        let _ = sender
                            .send(Ok(ManagerMessage {
                                desired_state: None,
                                error: "node identity changed within stream".into(),
                                desired_authorization_bundle: Vec::new(),
                                command_json: Vec::new(),
                            }))
                            .await;
                        break;
                    }
                    let duplicate = match active_nodes.lock() {
                        Ok(mut active) => !active.insert(message.node_id.clone()),
                        Err(_) => true,
                    };
                    if duplicate {
                        let _ = sender
                            .send(Ok(ManagerMessage {
                                desired_state: None,
                                error: "node already has an active control stream".into(),
                                desired_authorization_bundle: Vec::new(),
                                command_json: Vec::new(),
                            }))
                            .await;
                        break;
                    }
                    bound_node = Some(message.node_id.clone());
                }
                match store.node_is_active(&message.node_id) {
                    Ok(true) => {}
                    Ok(false) | Err(_) => {
                        let _ = sender
                            .send(Ok(ManagerMessage {
                                desired_state: None,
                                error: "node is not enrolled or has been revoked".into(),
                                desired_authorization_bundle: Vec::new(),
                                command_json: Vec::new(),
                            }))
                            .await;
                        continue;
                    }
                }
                if command_forward.is_none() {
                    let Ok(mut connection) = fleet_hub.connect(&message.node_id) else {
                        let _ = sender
                            .send(Ok(ManagerMessage {
                                desired_state: None,
                                error: "node already has an active fleet command stream".into(),
                                desired_authorization_bundle: Vec::new(),
                                command_json: Vec::new(),
                            }))
                            .await;
                        break;
                    };
                    let command_sender = sender.clone();
                    command_forward = Some(tokio::spawn(async move {
                        while let Some(command) = connection.receiver.recv().await {
                            let Ok(command_json) = serde_json::to_vec(&command) else {
                                continue;
                            };
                            if command_sender
                                .send(Ok(ManagerMessage {
                                    desired_state: None,
                                    error: String::new(),
                                    desired_authorization_bundle: Vec::new(),
                                    command_json,
                                }))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }));
                }
                handle_fleet_payload(&fleet_hub, &message);
                if message.acknowledged_revision > revision {
                    let _ = sender
                        .send(Ok(ManagerMessage {
                            desired_state: None,
                            error: "acknowledged revision is ahead of manager".into(),
                            desired_authorization_bundle: Vec::new(),
                            command_json: Vec::new(),
                        }))
                        .await;
                    continue;
                }
                let (desired_state, desired_authorization_bundle) =
                    match store.latest_authorized_revision(&message.node_id) {
                        Ok(Some((_, payload, bundle))) => {
                            match DesiredState::decode(payload.as_slice()) {
                                Ok(state) => (state, bundle),
                                Err(_) => {
                                    let _ = sender
                                        .send(Ok(ManagerMessage {
                                            desired_state: None,
                                            error: "persisted desired state is invalid".into(),
                                            desired_authorization_bundle: Vec::new(),
                                            command_json: Vec::new(),
                                        }))
                                        .await;
                                    continue;
                                }
                            }
                        }
                        Ok(None) => {
                            let state = builder.snapshot(revision, Vec::new(), chrono_like_now());
                            let bundle = match builder.authorization_bundle(
                                &state,
                                &message.node_id,
                                Vec::new(),
                            ) {
                                Ok(bundle) => bundle,
                                Err(_) => continue,
                            };
                            (state, bundle)
                        }
                        Err(_) => {
                            let _ = sender
                                .send(Ok(ManagerMessage {
                                    desired_state: None,
                                    error: "manager state unavailable".into(),
                                    desired_authorization_bundle: Vec::new(),
                                    command_json: Vec::new(),
                                }))
                                .await;
                            continue;
                        }
                    };
                let _ = sender
                    .send(Ok(ManagerMessage {
                        desired_state: Some(desired_state),
                        error: String::new(),
                        desired_authorization_bundle,
                        command_json: Vec::new(),
                    }))
                    .await;
            }
            if let Some(task) = command_forward {
                task.abort();
            }
            if let Some(node_id) = bound_node {
                if let Ok(mut active) = active_nodes.lock() {
                    active.remove(&node_id);
                }
            }
        });
        Ok(Response::new(ReceiverStream::new(receiver)))
    }
}

#[derive(serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum AgentFleetPayload {
    Observation {
        version: String,
        health: String,
        doctor_summary: String,
        containers: serde_json::Value,
        observed_at: i64,
    },
    CommandResult {
        request_id: u64,
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
}

fn handle_fleet_payload(hub: &ControlHub, message: &AgentMessage) {
    if message.payload.is_empty() {
        return;
    }
    let Ok(payload) = serde_json::from_slice::<AgentFleetPayload>(&message.payload) else {
        return;
    };
    match payload {
        AgentFleetPayload::Observation {
            version,
            health,
            doctor_summary,
            containers,
            observed_at,
        } => {
            let _ = hub.record_observation(HostObservation {
                node_id: message.node_id.clone(),
                last_seen_unix: observed_at,
                version,
                health,
                doctor_summary,
                containers_json: serde_json::to_string(&containers)
                    .unwrap_or_else(|_| "[]".into()),
                acknowledged_revision: message.acknowledged_revision,
            });
        }
        AgentFleetPayload::CommandResult {
            request_id,
            exit_code,
            stdout,
            stderr,
        } => hub.complete(
            &message.node_id,
            FleetCommandResult {
                request_id,
                exit_code,
                stdout,
                stderr,
            },
        ),
    }
}

fn chrono_like_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

pub struct AdminServiceImpl {
    store: Arc<ManagerStore>,
    cluster_epoch: u64,
    authorizer: Option<AdminAuthorizer>,
    control: Option<Arc<ControlServiceImpl>>,
    deployment_lock: Arc<tokio::sync::Mutex<()>>,
}
impl AdminServiceImpl {
    pub fn new(store: Arc<ManagerStore>, cluster_epoch: u64) -> Self {
        Self {
            store,
            cluster_epoch,
            authorizer: None,
            control: None,
            deployment_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }
    pub fn new_authorized(
        store: Arc<ManagerStore>,
        cluster_epoch: u64,
        cluster_id: impl Into<String>,
        control: Arc<ControlServiceImpl>,
    ) -> Self {
        Self {
            store,
            cluster_epoch,
            authorizer: Some(AdminAuthorizer::new(cluster_id)),
            control: Some(control),
            deployment_lock: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    fn authorize<T>(&self, request: &Request<T>, method: &str) -> Result<(), Status> {
        let authorizer = self
            .authorizer
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("authenticated admin mode is required"))?;
        let identity = request
            .extensions()
            .get::<crate::pki::CertificateIdentity>()
            .ok_or_else(|| Status::unauthenticated("client certificate identity is required"))?;
        authorizer
            .authorize(identity, method)
            .map(|_| ())
            .map_err(|_| Status::permission_denied("administrator principal is not authorized"))
    }

    fn validate_cluster(&self, cluster_id: &str) -> Result<(), Status> {
        if cluster_id.is_empty() {
            return Err(Status::invalid_argument("cluster_id is required"));
        }
        if self
            .authorizer
            .as_ref()
            .is_none_or(|authorizer| authorizer.cluster_id() != cluster_id)
        {
            return Err(Status::permission_denied("request is for another cluster"));
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl AdminService for AdminServiceImpl {
    async fn inspect(
        &self,
        request: Request<AdminRequest>,
    ) -> Result<Response<AdminResponse>, Status> {
        self.authorize(&request, "Inspect")?;
        let request = request.into_inner();
        if request.cluster_id.is_empty() {
            return Err(Status::invalid_argument("cluster_id is required"));
        }
        let node_count = self
            .store
            .node_count()
            .map_err(|_| Status::internal("manager state unavailable"))?;
        Ok(Response::new(AdminResponse {
            node_count,
            cluster_epoch: self.cluster_epoch,
        }))
    }

    async fn publish_desired(
        &self,
        request: Request<PublishDesiredRequest>,
    ) -> Result<Response<PublishDesiredResponse>, Status> {
        self.authorize(&request, "PublishDesired")?;
        let request = request.into_inner();
        if request.cluster_id.is_empty() || request.node_id.is_empty() {
            return Err(Status::invalid_argument(
                "cluster_id and node_id are required",
            ));
        }
        let authorizer = self.authorizer.as_ref().expect("authorized above");
        if authorizer.cluster_id() != request.cluster_id {
            return Err(Status::permission_denied("request is for another cluster"));
        }
        let revision = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("controller publisher is required"))?
            .publish_desired(
                &request.node_id,
                request.overlays,
                &[],
                chrono_like_now(),
                monotonic_like_now(),
            )
            .map_err(|error| {
                Status::permission_denied(format!("desired update rejected: {error}"))
            })?;
        Ok(Response::new(PublishDesiredResponse { revision }))
    }

    async fn fleet_snapshot(
        &self,
        request: Request<FleetSnapshotRequest>,
    ) -> Result<Response<FleetSnapshotResponse>, Status> {
        self.authorize(&request, "FleetSnapshot")?;
        let request = request.into_inner();
        self.validate_cluster(&request.cluster_id)?;
        let hub = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("fleet control hub is required"))?
            .fleet_hub();
        let hosts = self
            .store
            .list_hosts()
            .map_err(|_| Status::internal("manager state unavailable"))?
            .into_iter()
            .map(|host| {
                serde_json::json!({
                    "node_id": host.node_id,
                    "endpoint": host.endpoint,
                    "enrollment_state": host.enrollment_state,
                    "revocation_reason": host.revocation_reason,
                    "last_seen_unix": host.last_seen_unix,
                    "version": host.version,
                    "health": host.health,
                    "doctor_summary": host.doctor_summary,
                    "containers": serde_json::from_str::<serde_json::Value>(&host.containers_json)
                        .unwrap_or_else(|_| serde_json::Value::Array(Vec::new())),
                    "acknowledged_revision": host.acknowledged_revision,
                    "connected": hub.is_connected(&host.node_id),
                })
            })
            .collect::<Vec<_>>();
        let deploys = self
            .store
            .list_fleet_deployments()
            .map_err(|_| Status::internal("manager deployment state unavailable"))?
            .iter()
            .map(deployment_value)
            .collect::<Vec<_>>();
        let snapshot_json = serde_json::to_string(&serde_json::json!({
            "cluster_epoch": self.cluster_epoch,
            "hosts": hosts,
            "deploys": deploys,
        }))
        .map_err(|_| Status::internal("failed to encode fleet snapshot"))?;
        Ok(Response::new(FleetSnapshotResponse { snapshot_json }))
    }

    async fn fleet_command(
        &self,
        request: Request<FleetCommandRequest>,
    ) -> Result<Response<FleetCommandResponse>, Status> {
        self.authorize(&request, "FleetCommand")?;
        let request = request.into_inner();
        self.validate_cluster(&request.cluster_id)?;
        if request.node_id.is_empty() || request.arguments_json.len() > 64 * 1024 {
            return Err(Status::invalid_argument(
                "node_id and bounded arguments_json are required",
            ));
        }
        let arguments: serde_json::Value = serde_json::from_str(&request.arguments_json)
            .map_err(|_| Status::invalid_argument("arguments_json is invalid"))?;
        build_agent_cli_args(&request.action, &arguments)
            .map_err(Status::invalid_argument)?;
        let result = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("fleet control hub is required"))?
            .fleet_hub()
            .execute(
                &request.node_id,
                &request.action,
                arguments,
                std::time::Duration::from_secs(30),
            )
            .await
            .map_err(Status::unavailable)?;
        Ok(Response::new(FleetCommandResponse {
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
        }))
    }

    async fn revoke_host(
        &self,
        request: Request<FleetRevokeRequest>,
    ) -> Result<Response<FleetRevokeResponse>, Status> {
        self.authorize(&request, "RevokeHost")?;
        let request = request.into_inner();
        self.validate_cluster(&request.cluster_id)?;
        if request.node_id.is_empty() || request.reason.trim().is_empty() {
            return Err(Status::invalid_argument("node_id and reason are required"));
        }
        let revoked = self
            .store
            .node_is_active(&request.node_id)
            .map_err(|_| Status::internal("manager state unavailable"))?;
        if revoked {
            self.store
                .revoke_node(&request.node_id, &request.reason)
                .map_err(|_| Status::internal("manager state unavailable"))?;
        }
        Ok(Response::new(FleetRevokeResponse { revoked }))
    }

    async fn fleet_deploy(
        &self,
        request: Request<FleetDeployRequest>,
    ) -> Result<Response<FleetDeployResponse>, Status> {
        self.authorize(&request, "FleetDeploy")?;
        let request = request.into_inner();
        self.validate_cluster(&request.cluster_id)?;
        let _deployment_guard = self.deployment_lock.lock().await;
        let control = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("fleet control hub is required"))?;
        let hub = control.fleet_hub();
        for node_id in &request.node_ids {
            if !self
                .store
                .node_is_active(node_id)
                .map_err(|_| Status::internal("manager state unavailable"))?
                || !hub.is_connected(node_id)
            {
                return Err(Status::failed_precondition(format!(
                    "fleet host {node_id} is not active and connected"
                )));
            }
        }
        let previous = self
            .store
            .latest_succeeded_fleet_deployment(&request.name)
            .map_err(|_| Status::internal("manager deployment state unavailable"))?;
        let deployment = self
            .store
            .begin_fleet_deployment(
                &request.name,
                &request.image,
                &serde_json::to_string(&request.command)
                    .map_err(|_| Status::invalid_argument("deployment command is invalid"))?,
                &serde_json::to_string(&request.node_ids)
                    .map_err(|_| Status::invalid_argument("deployment hosts are invalid"))?,
                previous.as_ref().map(|value| value.deployment_id.as_str()),
                chrono_like_now(),
            )
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let mut progress = serde_json::Map::new();
        for node_id in &request.node_ids {
            progress.insert(node_id.clone(), serde_json::json!("updating"));
            persist_deployment_progress(&self.store, &deployment, "running", &progress, None)?;
            let update = async {
                if previous.is_some() {
                    execute_checked(
                        &hub,
                        node_id,
                        "remove_container",
                        serde_json::json!({"container":request.name}),
                    )
                    .await?;
                }
                execute_checked(
                    &hub,
                    node_id,
                    "run_container",
                    serde_json::json!({
                        "name":request.name,
                        "image":request.image,
                        "command":request.command,
                    }),
                )
                .await
            }
            .await;
            if let Err(error) = update {
                progress.insert(node_id.clone(), serde_json::json!({"failed":error}));
                persist_deployment_progress(&self.store, &deployment, "failed", &progress, None)?;
                return Err(Status::failed_precondition("fleet rollout failed"));
            }
            progress.insert(node_id.clone(), serde_json::json!("ready"));
        }
        persist_deployment_progress(&self.store, &deployment, "succeeded", &progress, None)?;
        let completed = self
            .store
            .fleet_deployment(&deployment.deployment_id)
            .map_err(|_| Status::internal("manager deployment state unavailable"))?
            .ok_or_else(|| Status::internal("deployment disappeared"))?;
        Ok(Response::new(FleetDeployResponse {
            deployment_json: deployment_value(&completed).to_string(),
        }))
    }

    async fn fleet_rollback(
        &self,
        request: Request<FleetRollbackRequest>,
    ) -> Result<Response<FleetDeployResponse>, Status> {
        self.authorize(&request, "FleetRollback")?;
        let request = request.into_inner();
        self.validate_cluster(&request.cluster_id)?;
        let _deployment_guard = self.deployment_lock.lock().await;
        let deployment = self
            .store
            .fleet_deployment(&request.deployment_id)
            .map_err(|_| Status::internal("manager deployment state unavailable"))?
            .ok_or_else(|| Status::not_found("fleet deployment does not exist"))?;
        if deployment.status != "succeeded" {
            return Err(Status::failed_precondition(
                "only a succeeded deployment can be rolled back",
            ));
        }
        let previous_id = deployment
            .previous_deployment_id
            .as_deref()
            .ok_or_else(|| Status::failed_precondition("deployment has no previous generation"))?;
        let previous = self
            .store
            .fleet_deployment(previous_id)
            .map_err(|_| Status::internal("manager deployment state unavailable"))?
            .ok_or_else(|| Status::failed_precondition("previous deployment is unavailable"))?;
        let nodes: Vec<String> = serde_json::from_str(&deployment.node_ids_json)
            .map_err(|_| Status::internal("deployment host list is invalid"))?;
        let previous_command: Vec<String> = serde_json::from_str(&previous.command_json)
            .map_err(|_| Status::internal("previous deployment command is invalid"))?;
        let hub = self
            .control
            .as_ref()
            .ok_or_else(|| Status::failed_precondition("fleet control hub is required"))?
            .fleet_hub();
        let mut progress = serde_json::Map::new();
        for node_id in nodes {
            execute_checked(
                &hub,
                &node_id,
                "remove_container",
                serde_json::json!({"container":deployment.name}),
            )
            .await
            .map_err(Status::failed_precondition)?;
            execute_checked(
                &hub,
                &node_id,
                "run_container",
                serde_json::json!({
                    "name":previous.name,
                    "image":previous.image,
                    "command":previous_command,
                }),
            )
            .await
            .map_err(Status::failed_precondition)?;
            progress.insert(node_id, serde_json::json!("rolled_back"));
        }
        persist_deployment_progress(
            &self.store,
            &deployment,
            "rolled_back",
            &progress,
            Some(chrono_like_now()),
        )?;
        let completed = self
            .store
            .fleet_deployment(&deployment.deployment_id)
            .map_err(|_| Status::internal("manager deployment state unavailable"))?
            .ok_or_else(|| Status::internal("deployment disappeared"))?;
        Ok(Response::new(FleetDeployResponse {
            deployment_json: deployment_value(&completed).to_string(),
        }))
    }
}

async fn execute_checked(
    hub: &ControlHub,
    node_id: &str,
    action: &str,
    arguments: serde_json::Value,
) -> Result<(), String> {
    let result = hub
        .execute(
            node_id,
            action,
            arguments,
            std::time::Duration::from_secs(30),
        )
        .await?;
    if result.exit_code != 0 {
        return Err(if result.stderr.is_empty() {
            format!("host command exited {}", result.exit_code)
        } else {
            result.stderr
        });
    }
    Ok(())
}

fn persist_deployment_progress(
    store: &ManagerStore,
    deployment: &FleetDeployment,
    status: &str,
    progress: &serde_json::Map<String, serde_json::Value>,
    rolled_back_at: Option<i64>,
) -> Result<(), Status> {
    store
        .update_fleet_deployment(
            &deployment.deployment_id,
            status,
            &serde_json::Value::Object(progress.clone()).to_string(),
            rolled_back_at,
        )
        .map_err(|_| Status::internal("failed to persist deployment progress"))
}

fn deployment_value(deployment: &FleetDeployment) -> serde_json::Value {
    serde_json::json!({
        "deployment_id": deployment.deployment_id,
        "revision": deployment.revision,
        "name": deployment.name,
        "image": deployment.image,
        "command": serde_json::from_str::<serde_json::Value>(&deployment.command_json)
            .unwrap_or_else(|_| serde_json::Value::Array(Vec::new())),
        "node_ids": serde_json::from_str::<serde_json::Value>(&deployment.node_ids_json)
            .unwrap_or_else(|_| serde_json::Value::Array(Vec::new())),
        "previous_deployment_id": deployment.previous_deployment_id,
        "status": deployment.status,
        "progress": serde_json::from_str::<serde_json::Value>(&deployment.progress_json)
            .unwrap_or_else(|_| serde_json::json!({})),
        "created_at": deployment.created_at,
        "rolled_back_at": deployment.rolled_back_at,
    })
}

fn monotonic_like_now() -> u64 {
    use std::sync::OnceLock;
    static START: OnceLock<std::time::Instant> = OnceLock::new();
    START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_millis() as u64
}
