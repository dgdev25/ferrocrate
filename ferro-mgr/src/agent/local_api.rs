use std::{collections::BTreeMap, sync::Mutex};
#[cfg(unix)]
use std::{fs, io::{Read, Write}, os::unix::{fs::PermissionsExt, net::UnixListener}, path::Path};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

use thiserror::Error;

use super::ipam::{Allocation, Ipam, IpamError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Attachment {
    pub overlay_id: String,
    pub container_id: String,
    pub bridge: String,
    pub netns: String,
    pub ipv4: std::net::Ipv4Addr,
    pub ipv6: Option<std::net::Ipv6Addr>,
    pub gateway: std::net::Ipv4Addr,
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
}

pub struct LocalApi {
    runtime_uid: u32,
    lease_expiry: Mutex<i64>,
    ipam: Ipam,
    overlays: Mutex<BTreeMap<String, OverlayConfig>>,
    enforce_overlays: Mutex<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayConfig {
    pub bridge: String,
    pub gateway: std::net::Ipv4Addr,
    pub mtu: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LocalApiRequest {
    AttachContainer { overlay_id: String, container_id: String, now_unix: i64 },
    DetachContainer { container_id: String, now_unix: i64 },
    InspectOverlay { overlay_id: String, now_unix: i64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LocalApiResponse {
    Attached(Attachment),
    Detached { released: bool },
    Overlay { overlay_id: String, bridge: String, gateway: std::net::Ipv4Addr, mtu: u16 },
    Rejected { reason: String },
}

pub const MAX_LOCAL_API_FRAME_BYTES: usize = 256 * 1024;

impl LocalApi {
    pub fn new(runtime_uid: u32, lease_expiry: i64, ipam: Ipam) -> Self { Self { runtime_uid, lease_expiry: Mutex::new(lease_expiry), ipam, overlays: Mutex::new(BTreeMap::new()), enforce_overlays: Mutex::new(false) } }

    pub fn register_overlay(&self, overlay_id: impl Into<String>, config: OverlayConfig) -> Result<(), LocalApiError> {
        self.overlays.lock().map_err(|_| LocalApiError::UnknownOverlay)?.insert(overlay_id.into(), config);
        *self.enforce_overlays.lock().map_err(|_| LocalApiError::UnknownOverlay)? = true;
        Ok(())
    }

    pub fn attach(&self, caller_uid: u32, overlay_id: impl Into<String>, container_id: impl Into<String>, now_unix: i64) -> Result<Attachment, LocalApiError> {
        self.authorize(caller_uid, now_unix)?;
        let overlay_id = overlay_id.into();
        let config = self.overlays.lock().map_err(|_| LocalApiError::UnknownOverlay)?.get(&overlay_id).cloned();
        if *self.enforce_overlays.lock().map_err(|_| LocalApiError::UnknownOverlay)? && config.is_none() { return Err(LocalApiError::UnknownOverlay); }
        let config = config.unwrap_or_else(|| OverlayConfig { bridge: overlay_id.clone(), gateway: "10.0.0.1".parse().expect("static gateway"), mtu: 1500 });
        let allocation = self.ipam.allocate(container_id)?;
        let netns = format!("ferro-{}", allocation.container_id);
        Ok(Attachment { overlay_id, container_id: allocation.container_id, bridge: config.bridge, netns, ipv4: allocation.address, ipv6: None, gateway: config.gateway, mtu: config.mtu })
    }

    pub fn detach(&self, caller_uid: u32, container_id: &str, now_unix: i64) -> Result<Option<Allocation>, LocalApiError> {
        self.authorize(caller_uid, now_unix)?;
        Ok(self.ipam.release(container_id)?)
    }

    pub fn handle(&self, caller_uid: u32, request: LocalApiRequest) -> LocalApiResponse {
        let result = match request {
            LocalApiRequest::AttachContainer { overlay_id, container_id, now_unix } => self.attach(caller_uid, overlay_id, container_id, now_unix).map(LocalApiResponse::Attached),
            LocalApiRequest::DetachContainer { container_id, now_unix } => self.detach(caller_uid, &container_id, now_unix).map(|allocation| LocalApiResponse::Detached { released: allocation.is_some() }),
            LocalApiRequest::InspectOverlay { overlay_id, now_unix } => self.inspect(caller_uid, &overlay_id, now_unix).map(|config| LocalApiResponse::Overlay { overlay_id, bridge: config.bridge, gateway: config.gateway, mtu: config.mtu }),
        };
        result.unwrap_or_else(|error| LocalApiResponse::Rejected { reason: error.to_string() })
    }

    pub fn inspect(&self, caller_uid: u32, overlay_id: &str, now_unix: i64) -> Result<OverlayConfig, LocalApiError> {
        self.authorize(caller_uid, now_unix)?;
        self.overlays.lock().map_err(|_| LocalApiError::UnknownOverlay)?.get(overlay_id).cloned().ok_or(LocalApiError::UnknownOverlay)
    }

    #[cfg(unix)]
    pub fn serve_unix(&self, path: impl AsRef<Path>) -> std::io::Result<()> {
        let path = path.as_ref();
        if path.exists() { fs::remove_file(path)?; }
        if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
        let listener = UnixListener::bind(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
        for stream in listener.incoming() {
            let mut stream = match stream { Ok(stream) => stream, Err(_) => continue };
            let caller_uid = getsockopt(&stream, PeerCredentials).map(|cred| cred.uid()).unwrap_or(u32::MAX);
            let mut prefix = [0_u8; 4];
            if stream.read_exact(&mut prefix).is_err() { continue; }
            let length = u32::from_be_bytes(prefix) as usize;
            if length > MAX_LOCAL_API_FRAME_BYTES { continue; }
            let mut body = vec![0_u8; length];
            if stream.read_exact(&mut body).is_err() { continue; }
            let response = match serde_json::from_slice::<LocalApiRequest>(&body) {
                Ok(request) => self.handle(caller_uid, request),
                Err(error) => LocalApiResponse::Rejected { reason: format!("invalid local API request: {error}") },
            };
            let body = match serde_json::to_vec(&response) { Ok(body) => body, Err(_) => continue };
            if body.len() > MAX_LOCAL_API_FRAME_BYTES { continue; }
            let _ = stream.write_all(&(body.len() as u32).to_be_bytes()).and_then(|_| stream.write_all(&body));
        }
        Ok(())
    }

    pub fn renew_lease(&self, caller_uid: u32, expiry: i64) -> Result<(), LocalApiError> {
        if caller_uid != self.runtime_uid { return Err(LocalApiError::Unauthorized); }
        *self.lease_expiry.lock().expect("lease lock poisoned") = expiry;
        Ok(())
    }

    fn authorize(&self, caller_uid: u32, now_unix: i64) -> Result<(), LocalApiError> {
        if caller_uid != self.runtime_uid { return Err(LocalApiError::Unauthorized); }
        if now_unix >= *self.lease_expiry.lock().expect("lease lock poisoned") { return Err(LocalApiError::Expired); }
        Ok(())
    }
}
