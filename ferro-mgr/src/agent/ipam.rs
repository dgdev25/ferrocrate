use std::{collections::HashMap, fs::{self, OpenOptions}, io::Write, net::Ipv4Addr, os::unix::fs::{MetadataExt, OpenOptionsExt}, path::PathBuf, sync::Mutex};

use ipnet::Ipv4Net;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Allocation {
    pub container_id: String,
    pub address: Ipv4Addr,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IpamError {
    #[error("container already has an address")]
    DuplicateContainer,
    #[error("overlay address pool is exhausted")]
    Exhausted,
    #[error("invalid address pool")]
    InvalidPool,
    #[error("failed to persist IPAM state: {0}")]
    Persistence(String),
}

pub struct Ipam {
    pool: Ipv4Net,
    gateway: Ipv4Addr,
    reserved: Vec<Ipv4Addr>,
    allocations: Mutex<HashMap<String, Ipv4Addr>>,
    state_path: Option<PathBuf>,
}

impl Ipam {
    pub fn new(pool: Ipv4Net, gateway: Ipv4Addr, reserved: Vec<Ipv4Addr>) -> Result<Self, IpamError> {
        if !pool.contains(&gateway) || gateway == pool.network() || gateway == pool.broadcast() { return Err(IpamError::InvalidPool); }
        Ok(Self { pool, gateway, reserved, allocations: Mutex::new(HashMap::new()), state_path: None })
    }

    pub fn with_state(pool: Ipv4Net, gateway: Ipv4Addr, reserved: Vec<Ipv4Addr>, path: impl Into<PathBuf>) -> Result<Self, IpamError> {
        let path = path.into();
        let mut instance = Self::new(pool, gateway, reserved)?;
        if path.exists() {
            let metadata = fs::symlink_metadata(&path).map_err(|error| IpamError::Persistence(error.to_string()))?;
            if !metadata.file_type().is_file() || metadata.mode() & 0o077 != 0 || metadata.uid() != nix::unistd::geteuid().as_raw() { return Err(IpamError::Persistence("insecure IPAM state path".into())); }
            let bytes = fs::read(&path).map_err(|error| IpamError::Persistence(error.to_string()))?;
            instance.allocations = Mutex::new(serde_json::from_slice(&bytes).map_err(|error| IpamError::Persistence(error.to_string()))?);
        }
        instance.state_path = Some(path);
        Ok(instance)
    }

    pub fn allocate(&self, container_id: impl Into<String>) -> Result<Allocation, IpamError> {
        let container_id = container_id.into();
        let mut allocations = self.allocations.lock().expect("IPAM lock poisoned");
        if allocations.contains_key(&container_id) { return Err(IpamError::DuplicateContainer); }
        let used: std::collections::HashSet<Ipv4Addr> = allocations.values().copied().collect();
        let start = u32::from(self.pool.network()).saturating_add(1);
        let end = u32::from(self.pool.broadcast());
        for value in start..end {
            let address = Ipv4Addr::from(value);
            if address == self.gateway || self.reserved.contains(&address) || used.contains(&address) { continue; }
            allocations.insert(container_id.clone(), address);
            if let Err(error) = self.persist(&allocations) { allocations.remove(&container_id); return Err(error); }
            return Ok(Allocation { container_id, address });
        }
        Err(IpamError::Exhausted)
    }

    pub fn release(&self, container_id: &str) -> Result<Option<Allocation>, IpamError> {
        let mut allocations = self.allocations.lock().map_err(|_| IpamError::Persistence("IPAM lock poisoned".into()))?;
        let allocation = allocations.remove(container_id).map(|address| Allocation { container_id: container_id.into(), address });
        if let Err(error) = self.persist(&allocations) { if let Some(allocation) = &allocation { allocations.insert(allocation.container_id.clone(), allocation.address); } return Err(error); }
        Ok(allocation)
    }

    fn persist(&self, allocations: &HashMap<String, Ipv4Addr>) -> Result<(), IpamError> {
        let Some(path) = &self.state_path else { return Ok(()); };
        let temporary = path.with_extension("tmp");
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temporary).map_err(|error| IpamError::Persistence(error.to_string()))?;
        file.write_all(&serde_json::to_vec(allocations).map_err(|error| IpamError::Persistence(error.to_string()))?).map_err(|error| IpamError::Persistence(error.to_string()))?;
        file.sync_all().map_err(|error| IpamError::Persistence(error.to_string()))?;
        fs::rename(temporary, path).map_err(|error| IpamError::Persistence(error.to_string()))
    }
}
