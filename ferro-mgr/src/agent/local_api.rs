use std::sync::Mutex;

use thiserror::Error;

use super::ipam::{Allocation, Ipam, IpamError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub overlay_id: String,
    pub container_id: String,
    pub ipv4: std::net::Ipv4Addr,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalApiError {
    #[error("caller is not an authorized runtime")]
    Unauthorized,
    #[error("overlay lease is expired")]
    Expired,
    #[error(transparent)]
    Ipam(#[from] IpamError),
}

pub struct LocalApi {
    runtime_uid: u32,
    lease_expiry: Mutex<i64>,
    ipam: Ipam,
}

impl LocalApi {
    pub fn new(runtime_uid: u32, lease_expiry: i64, ipam: Ipam) -> Self { Self { runtime_uid, lease_expiry: Mutex::new(lease_expiry), ipam } }

    pub fn attach(&self, caller_uid: u32, overlay_id: impl Into<String>, container_id: impl Into<String>, now_unix: i64) -> Result<Attachment, LocalApiError> {
        self.authorize(caller_uid, now_unix)?;
        let overlay_id = overlay_id.into();
        let allocation = self.ipam.allocate(container_id)?;
        Ok(Attachment { overlay_id, container_id: allocation.container_id, ipv4: allocation.address })
    }

    pub fn detach(&self, caller_uid: u32, container_id: &str, now_unix: i64) -> Result<Option<Allocation>, LocalApiError> {
        self.authorize(caller_uid, now_unix)?;
        Ok(self.ipam.release(container_id)?)
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
