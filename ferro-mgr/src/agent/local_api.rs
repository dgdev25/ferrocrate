#[cfg(target_os = "linux")]
use nix::sys::socket::{
    getsockopt, recvmsg, sockopt::PeerCredentials, ControlMessageOwned, MsgFlags,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Mutex};
#[cfg(target_os = "linux")]
use std::{
    fs,
    io::Write,
    os::fd::{AsRawFd, OwnedFd},
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::Path,
};

use thiserror::Error;

use super::delegation_ledger::{
    ChildIdentity, ClaimOutcome, CreationProvenance, DelegationLedger, ParentGrantKey,
};
use super::ipam::{Allocation, Ipam, IpamError};
use super::netd_client::{
    endpoint_live_identity_digest, DelegationBridge, NetdResponse, UnixNetdClient,
};
use ferro_core::authorization::{
    helper_grant::GrantAction, AuthorizationMode, AuthorizationServiceMode,
};
use ferro_core::managed_overlay::{
    DelegatedManagedOverlayRequest, LegacyManagedOverlayRequest, ManagedCleanupProvenance,
    ManagedOverlayCompatibilityMode, ManagedOverlayDelegation, MANAGED_OVERLAY_PROTOCOL_VERSION,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Attachment {
    pub overlay_id: String,
    pub container_id: String,
    pub bridge: String,
    pub netns: String,
    pub ipv4: std::net::Ipv4Addr,
    pub ipv6: Option<std::net::Ipv6Addr>,
    pub gateway: std::net::Ipv4Addr,
    pub prefix: u8,
    pub mtu: u16,
    #[serde(default)]
    pub cleanup_provenance: Option<ManagedCleanupProvenance>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalApiError {
    #[error("caller is not an authorized runtime")]
    Unauthorized,
    #[error("overlay lease is expired")]
    Expired,
    #[error("overlay is not authorized for this node")]
    UnknownOverlay,
    #[error(transparent)]
    Ipam(#[from] IpamError),
    #[error("authorization delegation is required")]
    MissingDelegation,
    #[error("authorization delegation was rejected")]
    InvalidDelegation,
    #[error("privileged network helper rejected the delegated request")]
    NetdRejected,
}

struct DelegatedNetd {
    bridge: DelegationBridge,
    client: UnixNetdClient,
    ledger: DelegationLedger,
}

pub struct LocalApi {
    runtime_uid: u32,
    lease_expiry: Mutex<i64>,
    ipam: Ipam,
    overlays: Mutex<BTreeMap<String, OverlayConfig>>,
    enforce_overlays: Mutex<bool>,
    delegated_netd: Mutex<Option<DelegatedNetd>>,
    runtime_executable: Option<std::path::PathBuf>,
    authorization_identity: Option<(AuthorizationServiceMode, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OverlayConfig {
    pub bridge: String,
    pub gateway: std::net::Ipv4Addr,
    pub prefix: u8,
    pub mtu: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LocalApiRequest {
    AttachContainer {
        overlay_id: String,
        container_id: String,
        now_unix: i64,
    },
    DetachContainer {
        container_id: String,
        now_unix: i64,
    },
    InspectOverlay {
        overlay_id: String,
        now_unix: i64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LocalApiResponse {
    Attached(Attachment),
    Detached {
        released: bool,
    },
    Overlay {
        overlay_id: String,
        bridge: String,
        gateway: std::net::Ipv4Addr,
        prefix: u8,
        mtu: u16,
    },
    Rejected {
        reason: String,
    },
}

pub const MAX_LOCAL_API_FRAME_BYTES: usize = 256 * 1024;

impl LocalApi {
    pub fn new(runtime_uid: u32, lease_expiry: i64, ipam: Ipam) -> Self {
        Self {
            runtime_uid,
            lease_expiry: Mutex::new(lease_expiry),
            ipam,
            overlays: Mutex::new(BTreeMap::new()),
            enforce_overlays: Mutex::new(false),
            delegated_netd: Mutex::new(None),
            runtime_executable: None,
            authorization_identity: None,
        }
    }

    pub fn with_runtime_executable(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.runtime_executable = Some(path.into());
        self
    }

    pub fn with_authorization_identity(
        mut self,
        mode: AuthorizationServiceMode,
        instance_boot: impl Into<String>,
    ) -> Self {
        self.authorization_identity = Some((mode, instance_boot.into()));
        self
    }

    pub fn with_delegation_bridge(self, bridge: DelegationBridge, client: UnixNetdClient) -> Self {
        let path = std::env::var_os("FERROCRATE_AGENT_DELEGATION_LEDGER")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| "/var/lib/ferrocrate/agent-delegations.json".into());
        let ledger = DelegationLedger::open(path).expect("delegation ledger unavailable");
        self.with_delegation_ledger(bridge, client, ledger)
    }

    pub fn with_delegation_ledger(
        self,
        bridge: DelegationBridge,
        client: UnixNetdClient,
        ledger: DelegationLedger,
    ) -> Self {
        *self
            .delegated_netd
            .lock()
            .expect("delegation lock poisoned") = Some(DelegatedNetd {
            bridge,
            client,
            ledger,
        });
        self
    }

    pub fn register_overlay(
        &self,
        overlay_id: impl Into<String>,
        config: OverlayConfig,
    ) -> Result<(), LocalApiError> {
        self.overlays
            .lock()
            .map_err(|_| LocalApiError::UnknownOverlay)?
            .insert(overlay_id.into(), config);
        *self
            .enforce_overlays
            .lock()
            .map_err(|_| LocalApiError::UnknownOverlay)? = true;
        Ok(())
    }

    pub fn attach(
        &self,
        caller_uid: u32,
        overlay_id: impl Into<String>,
        container_id: impl Into<String>,
        now_unix: i64,
    ) -> Result<Attachment, LocalApiError> {
        self.authorize(caller_uid, now_unix)?;
        let overlay_id = overlay_id.into();
        let config = self
            .overlays
            .lock()
            .map_err(|_| LocalApiError::UnknownOverlay)?
            .get(&overlay_id)
            .cloned();
        if *self
            .enforce_overlays
            .lock()
            .map_err(|_| LocalApiError::UnknownOverlay)?
            && config.is_none()
        {
            return Err(LocalApiError::UnknownOverlay);
        }
        let config = config.unwrap_or_else(|| OverlayConfig {
            bridge: overlay_id.clone(),
            gateway: "10.0.0.1".parse().expect("static gateway"),
            prefix: 24,
            mtu: 1500,
        });
        let allocation = self.ipam.allocate(container_id)?;
        let netns = format!("ferro-{}", allocation.container_id);
        Ok(Attachment {
            overlay_id,
            container_id: allocation.container_id,
            bridge: config.bridge,
            netns,
            ipv4: allocation.address,
            ipv6: None,
            gateway: config.gateway,
            prefix: config.prefix,
            mtu: config.mtu,
            cleanup_provenance: None,
        })
    }

    pub fn detach(
        &self,
        caller_uid: u32,
        container_id: &str,
        now_unix: i64,
    ) -> Result<Option<Allocation>, LocalApiError> {
        self.authorize(caller_uid, now_unix)?;
        Ok(self.ipam.release(container_id)?)
    }

    pub fn handle(&self, caller_uid: u32, request: LocalApiRequest) -> LocalApiResponse {
        let result = match request {
            LocalApiRequest::AttachContainer {
                overlay_id,
                container_id,
                now_unix,
            } => self
                .attach(caller_uid, overlay_id, container_id, now_unix)
                .map(LocalApiResponse::Attached),
            LocalApiRequest::DetachContainer {
                container_id,
                now_unix,
            } => self
                .detach(caller_uid, &container_id, now_unix)
                .map(|allocation| LocalApiResponse::Detached {
                    released: allocation.is_some(),
                }),
            LocalApiRequest::InspectOverlay {
                overlay_id,
                now_unix,
            } => self
                .inspect(caller_uid, &overlay_id, now_unix)
                .map(|config| LocalApiResponse::Overlay {
                    overlay_id,
                    bridge: config.bridge,
                    gateway: config.gateway,
                    prefix: config.prefix,
                    mtu: config.mtu,
                }),
        };
        result.unwrap_or_else(|error| LocalApiResponse::Rejected {
            reason: error.to_string(),
        })
    }

    pub fn handle_delegated(
        &self,
        caller_uid: u32,
        delegated: DelegatedManagedOverlayRequest,
        now_monotonic_millis: u64,
    ) -> LocalApiResponse {
        let request = delegated.request;
        let result = match request {
            ferro_core::managed_overlay::ManagedOverlayRequest::AttachContainer {
                overlay_id,
                container_id,
                now_unix,
            } => self.attach_delegated(
                caller_uid,
                overlay_id,
                container_id,
                now_unix,
                now_monotonic_millis,
                &delegated.delegation,
            ),
            ferro_core::managed_overlay::ManagedOverlayRequest::DetachContainer {
                overlay_id,
                container_id,
                now_unix,
            } => self.detach_delegated(
                caller_uid,
                overlay_id,
                container_id,
                now_unix,
                now_monotonic_millis,
                &delegated.delegation,
            ),
            _ => Err(LocalApiError::InvalidDelegation),
        };
        result.unwrap_or_else(|error| LocalApiResponse::Rejected {
            reason: error.to_string(),
        })
    }

    fn detach_delegated(
        &self,
        caller_uid: u32,
        overlay_id: String,
        container_id: String,
        now_unix: i64,
        now_monotonic_millis: u64,
        delegation: &ManagedOverlayDelegation,
    ) -> Result<LocalApiResponse, LocalApiError> {
        self.authorize(caller_uid, now_unix)?;
        let request = ferro_core::managed_overlay::ManagedOverlayRequest::DetachContainer {
            overlay_id: overlay_id.clone(),
            container_id: container_id.clone(),
            now_unix,
        };
        let mut configured = self
            .delegated_netd
            .lock()
            .map_err(|_| LocalApiError::InvalidDelegation)?;
        let delegated = configured
            .as_mut()
            .ok_or(LocalApiError::MissingDelegation)?;
        let provenance = delegated
            .ledger
            .creation_provenance(&container_id)
            .ok_or(LocalApiError::InvalidDelegation)?;
        if provenance.overlay_id != overlay_id || provenance.container_id != container_id {
            return Err(LocalApiError::InvalidDelegation);
        }
        delegated
            .bridge
            .validate_cleanup_parent(
                &request,
                delegation,
                &provenance,
                now_unix
                    .try_into()
                    .map_err(|_| LocalApiError::InvalidDelegation)?,
                now_monotonic_millis,
            )
            .map_err(|_| LocalApiError::InvalidDelegation)?;
        let parent_key = parent_key(delegation);
        let child = proposed_child(&parent_key)?;
        match delegated
            .ledger
            .claim(parent_key.clone(), child.clone())
            .map_err(|_| LocalApiError::InvalidDelegation)?
        {
            ClaimOutcome::Completed { response, .. } => {
                return serde_json::from_slice(&response)
                    .map_err(|_| LocalApiError::InvalidDelegation)
            }
            ClaimOutcome::InProgress(_) => return Err(LocalApiError::InvalidDelegation),
            ClaimOutcome::Fresh(_) => {}
        }
        let envelope = delegated
            .bridge
            .delegate_detach(
                &request,
                delegation,
                &container_id,
                now_unix
                    .try_into()
                    .map_err(|_| LocalApiError::InvalidDelegation)?,
                now_monotonic_millis,
                &child,
                &provenance,
            )
            .map_err(|_| LocalApiError::InvalidDelegation)?;
        match delegated
            .client
            .request_granted(&envelope)
            .map_err(|_| LocalApiError::NetdRejected)?
        {
            NetdResponse::Detached => {
                let response = LocalApiResponse::Detached {
                    released: self.ipam.release(&container_id)?.is_some(),
                };
                delegated
                    .ledger
                    .complete(
                        &parent_key,
                        serde_json::to_vec(&response)
                            .map_err(|_| LocalApiError::InvalidDelegation)?,
                    )
                    .map_err(|_| LocalApiError::InvalidDelegation)?;
                Ok(response)
            }
            NetdResponse::Rejected { reason, .. } => {
                let response = LocalApiResponse::Rejected { reason };
                delegated
                    .ledger
                    .complete(
                        &parent_key,
                        serde_json::to_vec(&response)
                            .map_err(|_| LocalApiError::InvalidDelegation)?,
                    )
                    .map_err(|_| LocalApiError::InvalidDelegation)?;
                Ok(response)
            }
            _ => Err(LocalApiError::NetdRejected),
        }
    }

    fn attach_delegated(
        &self,
        caller_uid: u32,
        overlay_id: String,
        container_id: String,
        now_unix: i64,
        now_monotonic_millis: u64,
        delegation: &ManagedOverlayDelegation,
    ) -> Result<LocalApiResponse, LocalApiError> {
        self.authorize(caller_uid, now_unix)?;
        let request = ferro_core::managed_overlay::ManagedOverlayRequest::AttachContainer {
            overlay_id: overlay_id.clone(),
            container_id: container_id.clone(),
            now_unix,
        };
        let mut configured = self
            .delegated_netd
            .lock()
            .map_err(|_| LocalApiError::InvalidDelegation)?;
        let delegated = configured
            .as_mut()
            .ok_or(LocalApiError::MissingDelegation)?;
        delegated
            .bridge
            .validate_parent(
                &request,
                delegation,
                GrantAction::NetworkAttach,
                now_unix
                    .try_into()
                    .map_err(|_| LocalApiError::InvalidDelegation)?,
                now_monotonic_millis,
            )
            .map_err(|_| LocalApiError::InvalidDelegation)?;
        let parent_key = parent_key(delegation);
        let child = proposed_child(&parent_key)?;
        match delegated
            .ledger
            .claim(parent_key.clone(), child.clone())
            .map_err(|_| LocalApiError::InvalidDelegation)?
        {
            ClaimOutcome::Completed { response, .. } => {
                return serde_json::from_slice(&response)
                    .map_err(|_| LocalApiError::InvalidDelegation)
            }
            ClaimOutcome::InProgress(_) => return Err(LocalApiError::InvalidDelegation),
            ClaimOutcome::Fresh(_) => {}
        }
        let mut attachment = self.attach(
            caller_uid,
            overlay_id.clone(),
            container_id.clone(),
            now_unix,
        )?;
        let envelope = delegated
            .bridge
            .delegate_attach(
                &request,
                delegation,
                &container_id,
                &attachment.netns,
                now_unix
                    .try_into()
                    .map_err(|_| LocalApiError::InvalidDelegation)?,
                now_monotonic_millis,
                &child,
            )
            .map_err(|_| LocalApiError::InvalidDelegation)?;
        let netd_response = match delegated.client.request_granted(&envelope) {
            Ok(response) => response,
            Err(_) => {
                let _ = self.ipam.release(&container_id);
                return Err(LocalApiError::NetdRejected);
            }
        };
        if let NetdResponse::Rejected { reason, .. } = netd_response {
            let _ = self.ipam.release(&container_id);
            let response = LocalApiResponse::Rejected { reason };
            delegated
                .ledger
                .complete(
                    &parent_key,
                    serde_json::to_vec(&response).map_err(|_| LocalApiError::InvalidDelegation)?,
                )
                .map_err(|_| LocalApiError::InvalidDelegation)?;
            return Ok(response);
        }
        if netd_response != NetdResponse::Attached {
            let _ = self.ipam.release(&container_id);
            return Err(LocalApiError::NetdRejected);
        }
        let provenance = CreationProvenance {
            container_id: container_id.clone(),
            overlay_id: overlay_id.clone(),
            resource_uuid: delegation.parent.claims.resource.resource_uuid.clone(),
            resource_generation: delegation.parent.claims.resource.generation,
            origin_request_id: child.request_id.clone(),
            live_identity_digest: endpoint_live_identity_digest(&container_id),
        };
        attachment.cleanup_provenance = Some(ManagedCleanupProvenance {
            origin_request_id: provenance.origin_request_id.clone(),
            live_identity_digest: provenance.live_identity_digest,
            resource_uuid: provenance.resource_uuid.clone(),
            resource_generation: provenance.resource_generation,
        });
        let response = LocalApiResponse::Attached(attachment);
        delegated
            .ledger
            .complete_creation(
                &parent_key,
                serde_json::to_vec(&response).map_err(|_| LocalApiError::InvalidDelegation)?,
                provenance,
            )
            .map_err(|_| LocalApiError::InvalidDelegation)?;
        Ok(response)
    }

    pub fn inspect(
        &self,
        caller_uid: u32,
        overlay_id: &str,
        now_unix: i64,
    ) -> Result<OverlayConfig, LocalApiError> {
        self.authorize(caller_uid, now_unix)?;
        self.overlays
            .lock()
            .map_err(|_| LocalApiError::UnknownOverlay)?
            .get(overlay_id)
            .cloned()
            .ok_or(LocalApiError::UnknownOverlay)
    }

    #[cfg(target_os = "linux")]
    pub fn serve_unix(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        let path = path.as_ref();
        if path.exists() {
            fs::remove_file(path)?;
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(stream) => stream,
                Err(_) => continue,
            };
            let caller_uid = getsockopt(&stream, PeerCredentials).ok();
            let Some(credentials) = caller_uid else {
                continue;
            };
            if credentials.uid() != self.runtime_uid {
                continue;
            }
            let Some(expected_executable) = self.runtime_executable.as_deref() else {
                continue;
            };
            let Ok(peer) = authenticate_peer_process(credentials.pid(), expected_executable) else {
                continue;
            };
            let caller_uid = credentials.uid();
            let mut prefix = [0_u8; 4];
            if receive_without_descriptors(&stream, &mut prefix).is_err() {
                continue;
            }
            let length = u32::from_be_bytes(prefix) as usize;
            if length > MAX_LOCAL_API_FRAME_BYTES {
                continue;
            }
            let mut body = vec![0_u8; length];
            if receive_without_descriptors(&stream, &mut body).is_err() || !peer.still_valid() {
                continue;
            }
            let enforced = self
                .delegated_netd
                .lock()
                .is_ok_and(|value| value.is_some());
            let response = if enforced {
                match serde_json::from_slice::<DelegatedManagedOverlayRequest>(&body) {
                    Ok(request) if self.matches_delegated_identity(&request) => {
                        self.handle_delegated(caller_uid, request, monotonic_millis())
                    }
                    Err(_) => LocalApiResponse::Rejected {
                        reason: LocalApiError::MissingDelegation.to_string(),
                    },
                    Ok(_) => LocalApiResponse::Rejected {
                        reason: LocalApiError::InvalidDelegation.to_string(),
                    },
                }
            } else {
                match decode_disabled_legacy(&body, self.authorization_identity.as_ref()) {
                    Ok(request) => self.handle(caller_uid, request),
                    Err(reason) => LocalApiResponse::Rejected { reason },
                }
            };
            let body = match serde_json::to_vec(&response) {
                Ok(body) => body,
                Err(_) => continue,
            };
            if body.len() > MAX_LOCAL_API_FRAME_BYTES {
                continue;
            }
            let _ = stream
                .write_all(&(body.len() as u32).to_be_bytes())
                .and_then(|_| stream.write_all(&body));
        }
        Ok(())
    }

    fn matches_delegated_identity(&self, request: &DelegatedManagedOverlayRequest) -> bool {
        let Some((expected, boot)) = &self.authorization_identity else {
            return false;
        };
        if expected.mode() == AuthorizationMode::Disabled || request.instance_boot != *boot {
            return false;
        }
        AuthorizationServiceMode::parse(&request.mode, request.policy_digest)
            .is_ok_and(|peer| expected.require_match(peer).is_ok())
    }

    pub fn renew_lease(&self, caller_uid: u32, expiry: i64) -> Result<(), LocalApiError> {
        if caller_uid != self.runtime_uid {
            return Err(LocalApiError::Unauthorized);
        }
        *self.lease_expiry.lock().expect("lease lock poisoned") = expiry;
        Ok(())
    }

    fn authorize(&self, caller_uid: u32, now_unix: i64) -> Result<(), LocalApiError> {
        if caller_uid != self.runtime_uid {
            return Err(LocalApiError::Unauthorized);
        }
        if now_unix >= *self.lease_expiry.lock().expect("lease lock poisoned") {
            return Err(LocalApiError::Expired);
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
struct AuthenticatedPeer {
    _pidfd: OwnedFd,
    pid: i32,
    executable: std::path::PathBuf,
    start_time: String,
}

#[cfg(target_os = "linux")]
impl AuthenticatedPeer {
    fn still_valid(&self) -> bool {
        read_peer_identity(self.pid).is_ok_and(|(executable, start)| {
            executable == self.executable && start == self.start_time
        })
    }
}

#[cfg(target_os = "linux")]
fn authenticate_peer_process(pid: i32, expected: &Path) -> Result<AuthenticatedPeer, ()> {
    let process = rustix::process::Pid::from_raw(pid).ok_or(())?;
    let pidfd = rustix::process::pidfd_open(process, rustix::process::PidfdFlags::empty())
        .map_err(|_| ())?;
    let (executable, start_time) = read_peer_identity(pid)?;
    if executable != expected {
        return Err(());
    }
    Ok(AuthenticatedPeer {
        _pidfd: pidfd,
        pid,
        executable,
        start_time,
    })
}

#[cfg(target_os = "linux")]
fn read_peer_identity(pid: i32) -> Result<(std::path::PathBuf, String), ()> {
    let executable = fs::read_link(format!("/proc/{pid}/exe")).map_err(|_| ())?;
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|_| ())?;
    let start_time = stat
        .rsplit(')')
        .next()
        .and_then(|value| value.split_whitespace().nth(19))
        .ok_or(())?
        .to_owned();
    Ok((executable, start_time))
}

#[cfg(target_os = "linux")]
fn receive_without_descriptors(
    stream: &std::os::unix::net::UnixStream,
    bytes: &mut [u8],
) -> Result<(), ()> {
    let mut offset = 0;
    while offset < bytes.len() {
        let mut iov = [std::io::IoSliceMut::new(&mut bytes[offset..])];
        let mut control = nix::cmsg_space!([std::os::fd::RawFd; 1]);
        let message = recvmsg::<()>(
            stream.as_raw_fd(),
            &mut iov,
            Some(&mut control),
            MsgFlags::empty(),
        )
        .map_err(|_| ())?;
        if message.bytes == 0
            || message
                .cmsgs()
                .map_err(|_| ())?
                .any(|item| matches!(item, ControlMessageOwned::ScmRights(_)))
        {
            return Err(());
        }
        offset += message.bytes;
    }
    Ok(())
}

fn decode_disabled_legacy(
    body: &[u8],
    expected_identity: Option<&(AuthorizationServiceMode, String)>,
) -> Result<LocalApiRequest, String> {
    let legacy: LegacyManagedOverlayRequest = serde_json::from_slice(body)
        .map_err(|error| format!("invalid local API request: {error}"))?;
    if legacy.schema_version != MANAGED_OVERLAY_PROTOCOL_VERSION
        || legacy.mode != ManagedOverlayCompatibilityMode::Disabled
    {
        return Err("unsupported local API compatibility mode".into());
    }
    let Some((expected, boot)) = expected_identity else {
        return Err("authorization service identity is not configured".into());
    };
    let peer = AuthorizationServiceMode::new(AuthorizationMode::Disabled, legacy.policy_digest)
        .map_err(|_| "invalid disabled compatibility identity")?;
    expected
        .require_match(peer)
        .map_err(|_| "local API authorization identity mismatch")?;
    if legacy.instance_boot != *boot {
        return Err("local API instance boot mismatch".into());
    }
    serde_json::from_value(
        serde_json::to_value(legacy.request)
            .map_err(|_| "invalid disabled compatibility request")?,
    )
    .map_err(|_| "invalid disabled compatibility request".into())
}

fn parent_key(delegation: &ManagedOverlayDelegation) -> ParentGrantKey {
    ParentGrantKey {
        request_id: delegation.parent.claims.request_id.clone(),
        operation_id: delegation.parent.claims.operation_id,
        nonce: delegation.parent.claims.nonce,
    }
}

fn proposed_child(parent: &ParentGrantKey) -> Result<ChildIdentity, LocalApiError> {
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce).map_err(|_| LocalApiError::InvalidDelegation)?;
    if nonce == [0; 16] || nonce == parent.nonce {
        return Err(LocalApiError::InvalidDelegation);
    }
    Ok(ChildIdentity {
        request_id: format!(
            "{}:child:{}",
            parent.request_id,
            nonce
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ),
        nonce,
    })
}

#[cfg(unix)]
fn monotonic_millis() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|value| value.split_whitespace().next()?.parse::<f64>().ok())
        .map_or(0, |seconds| (seconds * 1000.0) as u64)
}

#[cfg(test)]
mod compatibility_tests {
    use super::{decode_disabled_legacy, LocalApiRequest};
    use ferro_core::authorization::{AuthorizationMode, AuthorizationServiceMode};
    use ferro_core::managed_overlay::{
        LegacyManagedOverlayRequest, ManagedOverlayCompatibilityMode, ManagedOverlayRequest,
        MANAGED_OVERLAY_PROTOCOL_VERSION,
    };

    #[test]
    fn disabled_compatibility_requires_explicit_versioned_negotiation() {
        let bare = LocalApiRequest::AttachContainer {
            overlay_id: "wg0".into(),
            container_id: "c1".into(),
            now_unix: 1,
        };
        assert!(decode_disabled_legacy(&serde_json::to_vec(&bare).unwrap(), None).is_err());
        let negotiated = LegacyManagedOverlayRequest {
            schema_version: MANAGED_OVERLAY_PROTOCOL_VERSION,
            mode: ManagedOverlayCompatibilityMode::Disabled,
            policy_digest: None,
            instance_boot: "boot-a".into(),
            request: ManagedOverlayRequest::AttachContainer {
                overlay_id: "wg0".into(),
                container_id: "c1".into(),
                now_unix: 1,
            },
        };
        assert!(matches!(
            decode_disabled_legacy(
                &serde_json::to_vec(&negotiated).unwrap(),
                Some(&(
                    AuthorizationServiceMode::new(AuthorizationMode::Disabled, None).unwrap(),
                    "boot-a".into()
                ))
            ),
            Ok(LocalApiRequest::AttachContainer { .. })
        ));
    }

    #[test]
    fn disabled_compatibility_rejects_unknown_versions() {
        let negotiated = LegacyManagedOverlayRequest {
            schema_version: MANAGED_OVERLAY_PROTOCOL_VERSION + 1,
            mode: ManagedOverlayCompatibilityMode::Disabled,
            policy_digest: None,
            instance_boot: "boot-a".into(),
            request: ManagedOverlayRequest::InspectOverlay {
                overlay_id: "wg0".into(),
                now_unix: 1,
            },
        };
        assert!(decode_disabled_legacy(
            &serde_json::to_vec(&negotiated).unwrap(),
            Some(&(
                AuthorizationServiceMode::new(AuthorizationMode::Disabled, None).unwrap(),
                "boot-a".into()
            ))
        )
        .is_err());
    }

    #[test]
    fn disabled_compatibility_rejects_boot_or_policy_contradictions() {
        let request = LegacyManagedOverlayRequest {
            schema_version: MANAGED_OVERLAY_PROTOCOL_VERSION,
            mode: ManagedOverlayCompatibilityMode::Disabled,
            policy_digest: Some([7; 32]),
            instance_boot: "other-boot".into(),
            request: ManagedOverlayRequest::InspectOverlay {
                overlay_id: "wg0".into(),
                now_unix: 1,
            },
        };
        assert!(decode_disabled_legacy(
            &serde_json::to_vec(&request).unwrap(),
            Some(&(
                AuthorizationServiceMode::new(AuthorizationMode::Disabled, None).unwrap(),
                "boot-a".into()
            ))
        )
        .is_err());
    }
}
