use std::{
    collections::BTreeMap,
    net::Ipv4Addr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::Engine as _;
use ed25519_dalek::{SigningKey, VerifyingKey};
use ferro_core::authorization::{
    helper_grant::GrantIssuer, AuthorizationMode, AuthorizationServiceMode,
};
use ferro_mgr::{
    agent::{
        ipam::Ipam,
        local_api::{LocalApi, OverlayConfig},
        netd_client::{DelegationBridge, UnixNetdClient},
        netd_sequence::{NetdSequence, SequenceValue},
        Agent, AgentError, StateStore,
    },
    proto::{control_service_client::ControlServiceClient, AgentMessage},
};
use ipnet::Ipv4Net;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

fn required(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is required"))
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as i64)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service_mode = authorization_service_mode()?;
    let runtime_uid = required("FERROCRATE_AGENT_RUNTIME_UID")?.parse::<u32>()?;
    let lease_expiry = required("FERROCRATE_AGENT_LEASE_EXPIRY_UNIX")?.parse::<i64>()?;
    let pool = required("FERROCRATE_AGENT_IPV4_POOL")?.parse::<Ipv4Net>()?;
    let gateway = required("FERROCRATE_AGENT_IPV4_GATEWAY")?.parse::<Ipv4Addr>()?;
    let ipam_state = PathBuf::from(required("FERROCRATE_AGENT_IPAM_STATE")?);
    let socket = match service_mode.mode() {
        AuthorizationMode::Disabled => {
            if std::env::var_os("FERROCRATE_AGENT_SOCKET").is_some() {
                return Err("disabled mode cannot expose the delegated agent socket".into());
            }
            PathBuf::from(required("FERROCRATE_AGENT_LEGACY_SOCKET")?)
        }
        _ => {
            if std::env::var_os("FERROCRATE_AGENT_LEGACY_SOCKET").is_some() {
                return Err("enabled authorization cannot expose the legacy agent socket".into());
            }
            PathBuf::from(required("FERROCRATE_AGENT_SOCKET")?)
        }
    };
    let node_id = required("FERROCRATE_NODE_ID")?;
    let cluster_id = required("FERROCRATE_CLUSTER_ID")?;
    let state_path = PathBuf::from(required("FERROCRATE_AGENT_STATE")?);
    let netd_socket = required("FERROCRATE_NETD_SOCKET")?;
    let persisted_state = StateStore::new(&state_path).load()?;
    let sequence_path = std::env::var_os("FERROCRATE_AGENT_NETD_SEQUENCE")
        .map(PathBuf::from)
        .unwrap_or_else(|| state_path.with_extension("netd-sequence.json"));
    let netd_sequence = NetdSequence::open(
        sequence_path,
        SequenceValue {
            epoch: persisted_state.cluster_epoch,
            revision: persisted_state.applied_revision,
        },
    )?;
    let verifying_key = base64::engine::general_purpose::STANDARD
        .decode(required("FERROCRATE_NETD_SIGNING_KEY")?)?;
    if verifying_key.len() != 32 {
        return Err("FERROCRATE_NETD_SIGNING_KEY must decode to 32 bytes".into());
    }
    let mut controller_keys = vec![verifying_key.clone()];
    if let Ok(encoded) = std::env::var("FERROCRATE_CONTROLLER_VERIFY_OVERLAP_KEYS_JSON") {
        let overlap: Vec<String> = serde_json::from_str(&encoded)?;
        if overlap.len() > 1 {
            return Err("controller verification overlap permits at most one prior key".into());
        }
        for value in overlap {
            let key = base64::engine::general_purpose::STANDARD.decode(value)?;
            if key.len() != 32 {
                return Err("controller overlap key must decode to 32 bytes".into());
            }
            controller_keys.push(key);
        }
    }
    let reserved = std::env::var("FERROCRATE_AGENT_IPV4_RESERVED")
        .unwrap_or_default()
        .split(',')
        .filter(|entry| !entry.is_empty())
        .map(str::parse)
        .collect::<Result<Vec<Ipv4Addr>, _>>()?;
    let overlays = serde_json::from_str::<BTreeMap<String, OverlayConfig>>(
        &std::env::var("FERROCRATE_AGENT_OVERLAYS_JSON").unwrap_or_else(|_| "{}".into()),
    )?;
    let ipam = Ipam::with_state(pool, gateway, reserved, ipam_state)?;
    let local_api = LocalApi::new(runtime_uid, lease_expiry, ipam)
        .with_runtime_executable(required("FERROCRATE_RUNTIME_EXE")?);
    let local_api =
        match service_mode.mode() {
            AuthorizationMode::Disabled => local_api,
            AuthorizationMode::Enforce | AuthorizationMode::Shadow => {
                let parent_key_bytes = base64::engine::general_purpose::STANDARD
                    .decode(required("FERROCRATE_RUNTIME_GRANT_PUBLIC_KEY")?)?;
                let parent_key =
                    VerifyingKey::from_bytes(parent_key_bytes.as_slice().try_into().map_err(
                        |_| "FERROCRATE_RUNTIME_GRANT_PUBLIC_KEY must decode to 32 bytes",
                    )?)?;
                let child_issuer = GrantIssuer::from_key_file(
                    required("FERROCRATE_AGENT_GRANT_KEY_ID")?,
                    std::path::Path::new(&required("FERROCRATE_AGENT_GRANT_SIGNING_KEY_FILE")?),
                    nix::unistd::Uid::effective().as_raw(),
                )?;
                let envelope_key_bytes = read_private_key(&required(
                    "FERROCRATE_AGENT_NETD_ENVELOPE_SIGNING_KEY_FILE",
                )?)?;
                let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                    .trim()
                    .to_owned();
                let bridge = DelegationBridge::new(
                    parent_key,
                    required("FERROCRATE_RUNTIME_GRANT_ISSUER")?,
                    required("FERROCRATE_RUNTIME_GRANT_KEY_ID")?,
                    boot_id,
                    child_issuer,
                    SigningKey::from_bytes(&envelope_key_bytes),
                    cluster_id.clone(),
                    node_id.clone(),
                )
                .with_sequence(netd_sequence.clone());
                local_api.with_delegation_bridge(
                    bridge,
                    UnixNetdClient::new(&netd_socket).with_node_id(node_id.clone()),
                )
            }
        };
    let local_api = Arc::new(local_api);
    for (overlay_id, config) in overlays {
        local_api.register_overlay(overlay_id, config)?;
    }
    let api_for_server = local_api.clone();
    tokio::task::spawn_blocking(move || api_for_server.serve_unix(socket));
    run_control_stream(
        node_id,
        cluster_id,
        controller_keys,
        state_path,
        netd_socket,
        runtime_uid,
        local_api,
        netd_sequence,
        service_mode,
    )
    .await
}

fn authorization_service_mode() -> Result<AuthorizationServiceMode, Box<dyn std::error::Error>> {
    let mode = required("FERROCRATE_AUTHORIZATION_MODE")?;
    let digest = std::env::var("FERROCRATE_AUTHORIZATION_POLICY_DIGEST")
        .ok()
        .map(|value| {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(value)
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "policy digest must be base64",
                    )
                })?;
            bytes.try_into().map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "policy digest must decode to 32 bytes",
                )
            })
        })
        .transpose()?;
    Ok(AuthorizationServiceMode::parse(&mode, digest)?)
}

fn read_private_key(path: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
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
        return Err("netd envelope key must be an owned 0600 regular file".into());
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes
        .try_into()
        .map_err(|_| "netd envelope signing key must contain exactly 32 bytes")?)
}

async fn run_control_stream(
    node_id: String,
    cluster_id: String,
    verifying_keys: Vec<Vec<u8>>,
    state_path: PathBuf,
    netd_socket: String,
    runtime_uid: u32,
    local_api: Arc<LocalApi>,
    netd_sequence: NetdSequence,
    service_mode: AuthorizationServiceMode,
) -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = required("FERROCRATE_CONTROL_ENDPOINT")?;
    let ca = std::fs::read(required("FERROCRATE_NODE_CA_CERT")?)?;
    let cert = std::fs::read(required("FERROCRATE_AGENT_TLS_CERT")?)?;
    let key = std::fs::read(required("FERROCRATE_AGENT_TLS_KEY")?)?;
    let domain =
        std::env::var("FERROCRATE_CONTROL_TLS_DOMAIN").unwrap_or_else(|_| "localhost".into());
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca))
        .identity(Identity::from_pem(cert, key))
        .domain_name(domain);
    let channel: Channel = Endpoint::from_shared(endpoint)?
        .tls_config(tls)?
        .connect()
        .await?;
    let agent = Arc::new(if service_mode.mode() == AuthorizationMode::Disabled {
        Agent::new(
            cluster_id,
            verifying_keys[0].clone(),
            StateStore::new(state_path),
            UnixNetdClient::new(netd_socket).with_node_id(node_id.clone()),
        )?
        .with_netd_sequence(netd_sequence.clone())
    } else {
        Agent::new_enforcing_with_overlap(
            cluster_id,
            verifying_keys,
            StateStore::new(state_path),
            UnixNetdClient::new(netd_socket).with_node_id(node_id.clone()),
        )?
        .with_netd_sequence(netd_sequence.clone())
    });
    let (sender, receiver) = tokio::sync::mpsc::channel(8);
    sender
        .send(AgentMessage {
            node_id: node_id.clone(),
            acknowledged_revision: agent.state().applied_revision,
            payload: Vec::new(),
        })
        .await?;
    let keepalive_sender = sender.clone();
    let keepalive_agent = agent.clone();
    let keepalive_node_id = node_id.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
            interval.tick().await;
            if keepalive_sender
                .send(AgentMessage {
                    node_id: keepalive_node_id.clone(),
                    acknowledged_revision: keepalive_agent.state().applied_revision,
                    payload: Vec::new(),
                })
                .await
                .is_err()
            {
                break;
            }
        }
    });
    let mut control = ControlServiceClient::new(channel)
        .control_stream(ReceiverStream::new(receiver))
        .await?
        .into_inner();
    while let Some(message) = control.message().await? {
        if !message.error.is_empty() {
            return Err(format!("manager control error: {}", message.error).into());
        }
        if let Some(desired) = message.desired_state {
            let reconciliation = if service_mode.mode() == AuthorizationMode::Disabled {
                agent.reconcile(desired.clone(), now_unix())
            } else {
                agent.reconcile_with_bundle(
                    desired.clone(),
                    &message.desired_authorization_bundle,
                    now_unix(),
                )
            };
            match reconciliation {
                Ok(revision) => {
                    local_api.renew_lease(runtime_uid, desired.lease_expires_unix)?;
                    sender
                        .send(AgentMessage {
                            node_id: node_id.clone(),
                            acknowledged_revision: revision,
                            payload: Vec::new(),
                        })
                        .await?;
                }
                Err(AgentError::StaleRevision) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Err("manager control stream ended".into())
}
