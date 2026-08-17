//! Deterministic service endpoint publication and lookup.
//!
//! This catalog is deliberately local and authorization-neutral. The controller
//! is responsible for authorizing durable endpoint changes; consumers receive
//! only healthy, non-expired endpoints in stable order.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_SNAPSHOT_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub task_id: String,
    pub address: String,
    pub port: u16,
    pub healthy: bool,
    pub expires_at_unix: i64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CatalogError {
    #[error("service name must not be empty")]
    EmptyService,
    #[error("endpoint task id must not be empty")]
    EmptyTask,
    #[error("endpoint address must not be empty")]
    EmptyAddress,
    #[error("endpoint lease must be in the future")]
    ExpiredLease,
    #[error("service snapshot exceeds the size limit")]
    Oversized,
    #[error("service snapshot is invalid: {0}")]
    Snapshot(String),
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceCatalog {
    services: BTreeMap<String, BTreeMap<String, Endpoint>>,
}

impl ServiceCatalog {
    /// Serialize the catalog in deterministic key order for durable state.
    pub fn snapshot(&self) -> Result<Vec<u8>, CatalogError> {
        let bytes =
            serde_json::to_vec(self).map_err(|error| CatalogError::Snapshot(error.to_string()))?;
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(CatalogError::Oversized);
        }
        Ok(bytes)
    }

    /// Restore a catalog snapshot, dropping endpoints whose leases have expired.
    pub fn from_snapshot(bytes: &[u8], now_unix: i64) -> Result<Self, CatalogError> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(CatalogError::Oversized);
        }
        let mut catalog: Self = serde_json::from_slice(bytes)
            .map_err(|error| CatalogError::Snapshot(error.to_string()))?;
        for (service, endpoints) in &catalog.services {
            if service.trim().is_empty()
                || endpoints.values().any(|endpoint| {
                    endpoint.task_id.trim().is_empty() || endpoint.address.trim().is_empty()
                })
            {
                return Err(CatalogError::Snapshot("empty service identity".into()));
            }
        }
        for endpoints in catalog.services.values_mut() {
            endpoints.retain(|_, endpoint| endpoint.expires_at_unix > now_unix);
        }
        catalog
            .services
            .retain(|_, endpoints| !endpoints.is_empty());
        Ok(catalog)
    }

    pub fn publish(
        &mut self,
        service: impl Into<String>,
        endpoint: Endpoint,
        now_unix: i64,
    ) -> Result<(), CatalogError> {
        let service = service.into();
        if service.trim().is_empty() {
            return Err(CatalogError::EmptyService);
        }
        if endpoint.task_id.trim().is_empty() {
            return Err(CatalogError::EmptyTask);
        }
        if endpoint.address.trim().is_empty() {
            return Err(CatalogError::EmptyAddress);
        }
        if endpoint.expires_at_unix <= now_unix {
            return Err(CatalogError::ExpiredLease);
        }
        self.services
            .entry(service)
            .or_default()
            .insert(endpoint.task_id.clone(), endpoint);
        Ok(())
    }

    pub fn remove(&mut self, service: &str, task_id: &str) -> bool {
        let removed = self
            .services
            .get_mut(service)
            .map(|endpoints| endpoints.remove(task_id).is_some())
            .unwrap_or(false);
        if self.services.get(service).is_some_and(BTreeMap::is_empty) {
            self.services.remove(service);
        }
        removed
    }

    pub fn resolve(&mut self, service: &str, now_unix: i64) -> Vec<Endpoint> {
        let Some(endpoints) = self.services.get_mut(service) else {
            return Vec::new();
        };
        endpoints.retain(|_, endpoint| endpoint.expires_at_unix > now_unix);
        endpoints
            .values()
            .filter(|endpoint| endpoint.healthy)
            .cloned()
            .collect()
    }

    pub fn mark_health(&mut self, service: &str, task_id: &str, healthy: bool) -> bool {
        let Some(endpoint) = self
            .services
            .get_mut(service)
            .and_then(|items| items.get_mut(task_id))
        else {
            return false;
        };
        endpoint.healthy = healthy;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(task_id: &str, address: &str, expires_at_unix: i64) -> Endpoint {
        Endpoint {
            task_id: task_id.into(),
            address: address.into(),
            port: 8080,
            healthy: true,
            expires_at_unix,
        }
    }

    #[test]
    fn resolve_is_stable_and_filters_unhealthy_endpoints() {
        let mut catalog = ServiceCatalog::default();
        catalog
            .publish("web", endpoint("task-b", "10.0.0.2", 100), 1)
            .unwrap();
        catalog
            .publish("web", endpoint("task-a", "10.0.0.1", 100), 1)
            .unwrap();
        assert!(catalog.mark_health("web", "task-b", false));
        assert_eq!(catalog.resolve("web", 2)[0].task_id, "task-a");
    }

    #[test]
    fn expired_leases_are_removed_on_lookup() {
        let mut catalog = ServiceCatalog::default();
        catalog
            .publish("web", endpoint("task-a", "10.0.0.1", 10), 1)
            .unwrap();
        assert!(catalog.resolve("web", 10).is_empty());
        assert!(!catalog.remove("web", "task-a"));
    }

    #[test]
    fn invalid_publication_is_rejected() {
        let mut catalog = ServiceCatalog::default();
        assert_eq!(
            catalog.publish("", endpoint("task-a", "10.0.0.1", 10), 1),
            Err(CatalogError::EmptyService)
        );
        assert_eq!(
            catalog.publish("web", endpoint("task-a", "10.0.0.1", 1), 1),
            Err(CatalogError::ExpiredLease)
        );
    }

    #[test]
    fn removal_is_idempotent_and_cleans_empty_services() {
        let mut catalog = ServiceCatalog::default();
        catalog
            .publish("web", endpoint("task-a", "10.0.0.1", 10), 1)
            .unwrap();
        assert!(catalog.remove("web", "task-a"));
        assert!(!catalog.remove("web", "task-a"));
        assert!(catalog.resolve("web", 2).is_empty());
    }

    #[test]
    fn snapshot_round_trip_is_deterministic_and_expires_entries() {
        let mut catalog = ServiceCatalog::default();
        catalog
            .publish("web", endpoint("task-b", "10.0.0.2", 20), 1)
            .unwrap();
        catalog
            .publish("web", endpoint("task-a", "10.0.0.1", 5), 1)
            .unwrap();
        let first = catalog.snapshot().unwrap();
        let second = catalog.snapshot().unwrap();
        assert_eq!(first, second);
        let mut restored = ServiceCatalog::from_snapshot(&first, 5).unwrap();
        assert_eq!(restored.resolve("web", 5).len(), 1);
        assert_eq!(restored.resolve("web", 5)[0].task_id, "task-b");
    }

    #[test]
    fn snapshot_rejects_oversized_or_malformed_data() {
        let oversized = vec![b'x'; MAX_SNAPSHOT_BYTES + 1];
        assert_eq!(
            ServiceCatalog::from_snapshot(&oversized, 0),
            Err(CatalogError::Oversized)
        );
        assert!(matches!(
            ServiceCatalog::from_snapshot(b"not-json", 0),
            Err(CatalogError::Snapshot(_))
        ));
    }
}
