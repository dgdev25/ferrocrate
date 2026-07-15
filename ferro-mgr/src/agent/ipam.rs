use std::{collections::HashMap, net::Ipv4Addr, sync::Mutex};

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
}

pub struct Ipam {
    pool: Ipv4Net,
    gateway: Ipv4Addr,
    reserved: Vec<Ipv4Addr>,
    allocations: Mutex<HashMap<String, Ipv4Addr>>,
}

impl Ipam {
    pub fn new(pool: Ipv4Net, gateway: Ipv4Addr, reserved: Vec<Ipv4Addr>) -> Result<Self, IpamError> {
        if !pool.contains(&gateway) || gateway == pool.network() || gateway == pool.broadcast() { return Err(IpamError::InvalidPool); }
        Ok(Self { pool, gateway, reserved, allocations: Mutex::new(HashMap::new()) })
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
            return Ok(Allocation { container_id, address });
        }
        Err(IpamError::Exhausted)
    }

    pub fn release(&self, container_id: &str) -> Option<Allocation> {
        self.allocations.lock().ok()?.remove(container_id).map(|address| Allocation { container_id: container_id.into(), address })
    }
}
