use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use thiserror::Error;

use crate::store::{ManagerStore, StoreError};

#[derive(Debug, Error)]
pub enum RevocationError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("revocation service lock poisoned")]
    Poisoned,
}

pub struct RevocationService {
    store: Arc<ManagerStore>,
    revoked: Mutex<HashSet<String>>,
}

impl RevocationService {
    pub fn new(store: Arc<ManagerStore>) -> Self { Self { store, revoked: Mutex::new(HashSet::new()) } }

    pub fn revoke_node(&self, node_id: &str, reason: &str) -> Result<bool, RevocationError> {
        let mut revoked = self.revoked.lock().map_err(|_| RevocationError::Poisoned)?;
        if !revoked.insert(node_id.into()) { return Ok(false); }
        if let Err(error) = self.store.revoke_node(node_id, reason) {
            revoked.remove(node_id);
            return Err(error.into());
        }
        Ok(true)
    }

    pub fn is_revoked(&self, node_id: &str) -> Result<bool, RevocationError> { Ok(self.revoked.lock().map_err(|_| RevocationError::Poisoned)?.contains(node_id)) }
}
