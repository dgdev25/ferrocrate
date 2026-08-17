//! Deterministic service endpoint publication and lookup.
//!
//! This catalog is deliberately local and authorization-neutral. The controller
//! is responsible for authorizing durable endpoint changes; consumers receive
//! only healthy, non-expired endpoints in stable order.

use std::collections::BTreeMap;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
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
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ServiceCatalog {
    services: BTreeMap<String, BTreeMap<String, Endpoint>>,
}

impl ServiceCatalog {
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
}
