#[cfg(unix)]
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Mutex};
#[cfg(unix)]
use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::Path,
};

use thiserror::Error;

use super::ipam::{Allocation, Ipam, IpamError};
use super::netd_client::{DelegationBridge, NetdResponse, UnixNetdClient};
use ferro_core::managed_overlay::{DelegatedManagedOverlayRequest, ManagedOverlayDelegation};

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
}

pub struct LocalApi {
    runtime_uid: u32,
    lease_expiry: Mutex<i64>,
    ipam: Ipam,
    overlays: Mutex<BTreeMap<String, OverlayConfig>>,
    enforce_overlays: Mutex<bool>,
    delegated_netd: Mutex<Option<DelegatedNetd>>,
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
        }
    }

    pub fn with_delegation_bridge(self, bridge: DelegationBridge, client: UnixNetdClient) -> Self {
        *self
            .delegated_netd
            .lock()
            .expect("delegation lock poisoned") = Some(DelegatedNetd { bridge, client });
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
            } => self
                .attach_delegated(
                    caller_uid,
                    overlay_id,
                    container_id,
                    now_unix,
                    now_monotonic_millis,
                    &delegated.delegation,
                )
                .map(LocalApiResponse::Attached),
            ferro_core::managed_overlay::ManagedOverlayRequest::DetachContainer {
                overlay_id,
                container_id,
                now_unix,
            } => self
                .detach_delegated(
                    caller_uid,
                    overlay_id,
                    container_id,
                    now_unix,
                    now_monotonic_millis,
                    &delegated.delegation,
                )
                .map(|released| LocalApiResponse::Detached { released }),
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
    ) -> Result<bool, LocalApiError> {
        self.authorize(caller_uid, now_unix)?;
        let request = ferro_core::managed_overlay::ManagedOverlayRequest::DetachContainer {
            overlay_id,
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
            )
            .map_err(|_| LocalApiError::InvalidDelegation)?;
        match delegated
            .client
            .request_granted(&envelope)
            .map_err(|_| LocalApiError::NetdRejected)?
        {
            NetdResponse::Detached => Ok(self.ipam.release(&container_id)?.is_some()),
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
    ) -> Result<Attachment, LocalApiError> {
        self.authorize(caller_uid, now_unix)?;
        let attachment = self.attach(
            caller_uid,
            overlay_id.clone(),
            container_id.clone(),
            now_unix,
        )?;
        let request = ferro_core::managed_overlay::ManagedOverlayRequest::AttachContainer {
            overlay_id,
            container_id: container_id.clone(),
            now_unix,
        };
        let outcome = (|| {
            let mut configured = self
                .delegated_netd
                .lock()
                .map_err(|_| LocalApiError::InvalidDelegation)?;
            let delegated = configured
                .as_mut()
                .ok_or(LocalApiError::MissingDelegation)?;
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
                )
                .map_err(|_| LocalApiError::InvalidDelegation)?;
            match delegated
                .client
                .request_granted(&envelope)
                .map_err(|_| LocalApiError::NetdRejected)?
            {
                NetdResponse::Attached => Ok(()),
                _ => Err(LocalApiError::NetdRejected),
            }
        })();
        if let Err(error) = outcome {
            let _ = self.ipam.release(&container_id);
            return Err(error);
        }
        Ok(attachment)
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

    #[cfg(unix)]
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
            let caller_uid = getsockopt(&stream, PeerCredentials)
                .map(|cred| cred.uid())
                .unwrap_or(u32::MAX);
            let mut prefix = [0_u8; 4];
            if stream.read_exact(&mut prefix).is_err() {
                continue;
            }
            let length = u32::from_be_bytes(prefix) as usize;
            if length > MAX_LOCAL_API_FRAME_BYTES {
                continue;
            }
            let mut body = vec![0_u8; length];
            if stream.read_exact(&mut body).is_err() {
                continue;
            }
            let enforced = self
                .delegated_netd
                .lock()
                .is_ok_and(|value| value.is_some());
            let response = if enforced {
                match serde_json::from_slice::<DelegatedManagedOverlayRequest>(&body) {
                    Ok(request) => self.handle_delegated(caller_uid, request, monotonic_millis()),
                    Err(_) => LocalApiResponse::Rejected {
                        reason: LocalApiError::MissingDelegation.to_string(),
                    },
                }
            } else {
                match serde_json::from_slice::<LocalApiRequest>(&body) {
                    Ok(request) => self.handle(caller_uid, request),
                    Err(error) => LocalApiResponse::Rejected {
                        reason: format!("invalid local API request: {error}"),
                    },
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

#[cfg(unix)]
fn monotonic_millis() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|value| value.split_whitespace().next()?.parse::<f64>().ok())
        .map_or(0, |seconds| (seconds * 1000.0) as u64)
}
