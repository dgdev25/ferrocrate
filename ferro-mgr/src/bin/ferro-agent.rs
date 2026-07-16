use std::{collections::BTreeMap, net::Ipv4Addr, path::PathBuf, sync::Arc, time::{Duration, SystemTime, UNIX_EPOCH}};

use base64::Engine as _;
use ferro_mgr::{agent::{ipam::Ipam, local_api::{LocalApi, OverlayConfig}, netd_client::UnixNetdClient, Agent, AgentError, StateStore}, proto::{control_service_client::ControlServiceClient, AgentMessage}};
use ipnet::Ipv4Net;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

fn required(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is required"))
}

fn now_unix() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_secs() as i64) }

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime_uid = required("FERROCRATE_AGENT_RUNTIME_UID")?.parse::<u32>()?;
    let lease_expiry = required("FERROCRATE_AGENT_LEASE_EXPIRY_UNIX")?.parse::<i64>()?;
    let pool = required("FERROCRATE_AGENT_IPV4_POOL")?.parse::<Ipv4Net>()?;
    let gateway = required("FERROCRATE_AGENT_IPV4_GATEWAY")?.parse::<Ipv4Addr>()?;
    let ipam_state = PathBuf::from(required("FERROCRATE_AGENT_IPAM_STATE")?);
    let socket = PathBuf::from(required("FERROCRATE_AGENT_SOCKET")?);
    let node_id = required("FERROCRATE_NODE_ID")?;
    let cluster_id = required("FERROCRATE_CLUSTER_ID")?;
    let state_path = PathBuf::from(required("FERROCRATE_AGENT_STATE")?);
    let netd_socket = required("FERROCRATE_NETD_SOCKET")?;
    let verifying_key = base64::engine::general_purpose::STANDARD.decode(required("FERROCRATE_NETD_SIGNING_KEY")?)?;
    if verifying_key.len() != 32 { return Err("FERROCRATE_NETD_SIGNING_KEY must decode to 32 bytes".into()); }
    let reserved = std::env::var("FERROCRATE_AGENT_IPV4_RESERVED").unwrap_or_default().split(',').filter(|entry| !entry.is_empty()).map(str::parse).collect::<Result<Vec<Ipv4Addr>, _>>()?;
    let overlays = serde_json::from_str::<BTreeMap<String, OverlayConfig>>(&std::env::var("FERROCRATE_AGENT_OVERLAYS_JSON").unwrap_or_else(|_| "{}".into()))?;
    let ipam = Ipam::with_state(pool, gateway, reserved, ipam_state)?;
    let local_api = Arc::new(LocalApi::new(runtime_uid, lease_expiry, ipam));
    for (overlay_id, config) in overlays { local_api.register_overlay(overlay_id, config)?; }
    let api_for_server = local_api.clone();
    tokio::task::spawn_blocking(move || api_for_server.serve_unix(socket));
    run_control_stream(node_id, cluster_id, verifying_key, state_path, netd_socket, runtime_uid, local_api).await
}

async fn run_control_stream(node_id: String, cluster_id: String, verifying_key: Vec<u8>, state_path: PathBuf, netd_socket: String, runtime_uid: u32, local_api: Arc<LocalApi>) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = required("FERROCRATE_CONTROL_ENDPOINT")?;
    let ca = std::fs::read(required("FERROCRATE_NODE_CA_CERT")?)?;
    let cert = std::fs::read(required("FERROCRATE_AGENT_TLS_CERT")?)?;
    let key = std::fs::read(required("FERROCRATE_AGENT_TLS_KEY")?)?;
    let domain = std::env::var("FERROCRATE_CONTROL_TLS_DOMAIN").unwrap_or_else(|_| "localhost".into());
    let tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(ca)).identity(Identity::from_pem(cert, key)).domain_name(domain);
    let channel: Channel = Endpoint::from_shared(endpoint)?.tls_config(tls)?.connect().await?;
    let agent = Arc::new(Agent::new(cluster_id, verifying_key, StateStore::new(state_path), UnixNetdClient::new(netd_socket).with_node_id(node_id.clone()))?);
    let (sender, receiver) = tokio::sync::mpsc::channel(8);
    sender.send(AgentMessage { node_id: node_id.clone(), acknowledged_revision: agent.state().applied_revision, payload: Vec::new() }).await?;
    let keepalive_sender = sender.clone();
    let keepalive_agent = agent.clone();
    let keepalive_node_id = node_id.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
            interval.tick().await;
            if keepalive_sender.send(AgentMessage {
                node_id: keepalive_node_id.clone(),
                acknowledged_revision: keepalive_agent.state().applied_revision,
                payload: Vec::new(),
            }).await.is_err() {
                break;
            }
        }
    });
    let mut control = ControlServiceClient::new(channel).control_stream(ReceiverStream::new(receiver)).await?.into_inner();
    while let Some(message) = control.message().await? {
        if !message.error.is_empty() { return Err(format!("manager control error: {}", message.error).into()); }
        if let Some(desired) = message.desired_state {
            match agent.reconcile(desired.clone(), now_unix()) {
                Ok(revision) => {
                    local_api.renew_lease(runtime_uid, desired.lease_expires_unix)?;
                    sender.send(AgentMessage { node_id: node_id.clone(), acknowledged_revision: revision, payload: Vec::new() }).await?;
                }
                Err(AgentError::StaleRevision) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Err("manager control stream ended".into())
}
