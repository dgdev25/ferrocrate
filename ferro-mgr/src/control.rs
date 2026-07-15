use std::{collections::HashSet, sync::Mutex};

use thiserror::Error;

use crate::{config::MAX_PENDING_REVISIONS, proto::{AgentMessage, DesiredState, ManagerMessage}};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ControlError {
    #[error("node already has an active control stream")]
    DuplicateSession,
    #[error("control stream cluster identity is invalid")]
    WrongCluster,
    #[error("control stream epoch is stale")]
    StaleEpoch,
    #[error("acknowledged revision is ahead of the manager")]
    FutureRevision,
    #[error("control stream queue is full")]
    QueueFull,
}

pub struct ControlServiceImpl {
    cluster_id: String,
    cluster_epoch: u64,
    latest_revision: Mutex<u64>,
    active_nodes: Mutex<HashSet<String>>,
}

pub struct ControlSession<'a> {
    service: &'a ControlServiceImpl,
    node_id: String,
}

impl ControlServiceImpl {
    pub fn new(cluster_id: impl Into<String>, cluster_epoch: u64) -> Self {
        Self { cluster_id: cluster_id.into(), cluster_epoch, latest_revision: Mutex::new(0), active_nodes: Mutex::new(HashSet::new()) }
    }

    pub fn publish_revision(&self, revision: u64) {
        if let Ok(mut latest) = self.latest_revision.lock() { *latest = (*latest).max(revision); }
    }

    pub fn connect(&self, node_id: impl Into<String>, cluster_id: &str, epoch: u64) -> Result<ControlSession<'_>, ControlError> {
        if cluster_id != self.cluster_id { return Err(ControlError::WrongCluster); }
        if epoch != self.cluster_epoch { return Err(ControlError::StaleEpoch); }
        let node_id = node_id.into();
        let mut active = self.active_nodes.lock().expect("control session lock poisoned");
        if !active.insert(node_id.clone()) { return Err(ControlError::DuplicateSession); }
        Ok(ControlSession { service: self, node_id })
    }
}

impl<'a> ControlSession<'a> {
    pub fn receive(&self, message: &AgentMessage) -> Result<Option<ManagerMessage>, ControlError> {
        let latest = *self.service.latest_revision.lock().expect("revision lock poisoned");
        if message.acknowledged_revision > latest { return Err(ControlError::FutureRevision); }
        if message.payload.len() > crate::config::MAX_MESSAGE_BYTES { return Err(ControlError::QueueFull); }
        if latest.saturating_sub(message.acknowledged_revision) as usize > MAX_PENDING_REVISIONS {
            return Err(ControlError::QueueFull);
        }
        Ok(None)
    }
}

impl Drop for ControlSession<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.service.active_nodes.lock() { active.remove(&self.node_id); }
    }
}

#[allow(dead_code)]
fn _typed_state(state: DesiredState) -> ManagerMessage { ManagerMessage { desired_state: Some(state), error: String::new() } }
