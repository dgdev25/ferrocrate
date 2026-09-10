use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, Weak,
    },
    time::Duration,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};

use crate::store::{HostObservation, ManagerStore};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FleetCommand {
    pub request_id: u64,
    pub action: String,
    pub arguments: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetCommandResult {
    pub request_id: u64,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

struct ConnectedNode {
    generation: u64,
    sender: mpsc::Sender<FleetCommand>,
}

pub struct ControlHub {
    store: Arc<ManagerStore>,
    nodes: Mutex<HashMap<String, ConnectedNode>>,
    pending: Mutex<HashMap<(String, u64), oneshot::Sender<FleetCommandResult>>>,
    next_request: AtomicU64,
    next_generation: AtomicU64,
}

pub struct ControlConnection {
    pub receiver: mpsc::Receiver<FleetCommand>,
    node_id: String,
    generation: u64,
    hub: Weak<ControlHub>,
}

impl ControlHub {
    pub fn new(store: Arc<ManagerStore>) -> Self {
        Self {
            store,
            nodes: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            next_request: AtomicU64::new(0),
            next_generation: AtomicU64::new(0),
        }
    }

    pub fn connect(self: &Arc<Self>, node_id: &str) -> Result<ControlConnection, String> {
        if node_id.trim().is_empty() {
            return Err("node id is required".into());
        }
        let (sender, receiver) = mpsc::channel(32);
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed) + 1;
        let mut nodes = self
            .nodes
            .lock()
            .map_err(|_| "control hub lock poisoned".to_string())?;
        if nodes.contains_key(node_id) {
            return Err("node already has an active control stream".into());
        }
        nodes.insert(node_id.into(), ConnectedNode { generation, sender });
        Ok(ControlConnection {
            receiver,
            node_id: node_id.into(),
            generation,
            hub: Arc::downgrade(self),
        })
    }

    pub fn is_connected(&self, node_id: &str) -> bool {
        self.nodes
            .lock()
            .is_ok_and(|nodes| nodes.contains_key(node_id))
    }

    pub fn record_observation(&self, observation: HostObservation) -> Result<(), String> {
        self.store
            .record_host_observation(observation)
            .map_err(|error| error.to_string())
    }

    pub async fn execute(
        &self,
        node_id: &str,
        action: &str,
        arguments: Value,
        timeout: Duration,
    ) -> Result<FleetCommandResult, String> {
        if action.trim().is_empty() {
            return Err("fleet action is required".into());
        }
        let request_id = self.next_request.fetch_add(1, Ordering::Relaxed) + 1;
        let sender = self
            .nodes
            .lock()
            .map_err(|_| "control hub lock poisoned".to_string())?
            .get(node_id)
            .map(|node| node.sender.clone())
            .ok_or_else(|| format!("host {node_id} is not connected"))?;
        let (result_sender, result_receiver) = oneshot::channel();
        self.pending
            .lock()
            .map_err(|_| "control result lock poisoned".to_string())?
            .insert((node_id.into(), request_id), result_sender);
        if sender
            .send(FleetCommand {
                request_id,
                action: action.into(),
                arguments,
            })
            .await
            .is_err()
        {
            self.remove_pending(node_id, request_id);
            return Err(format!("host {node_id} control stream ended"));
        }
        match tokio::time::timeout(timeout, result_receiver).await {
            Ok(Ok(result)) => Ok(result),
            Ok(Err(_)) => Err(format!("host {node_id} disconnected before replying")),
            Err(_) => {
                self.remove_pending(node_id, request_id);
                Err(format!("host {node_id} command timed out"))
            }
        }
    }

    pub fn complete(&self, node_id: &str, result: FleetCommandResult) {
        let sender = self
            .pending
            .lock()
            .ok()
            .and_then(|mut pending| pending.remove(&(node_id.to_string(), result.request_id)));
        if let Some(sender) = sender {
            let _ = sender.send(result);
        }
    }

    fn remove_pending(&self, node_id: &str, request_id: u64) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.remove(&(node_id.to_string(), request_id));
        }
    }

    fn disconnect(&self, node_id: &str, generation: u64) {
        if let Ok(mut nodes) = self.nodes.lock() {
            if nodes
                .get(node_id)
                .is_some_and(|node| node.generation == generation)
            {
                nodes.remove(node_id);
            }
        }
        if let Ok(mut pending) = self.pending.lock() {
            pending.retain(|(pending_node, _), _| pending_node != node_id);
        }
    }
}

impl Drop for ControlConnection {
    fn drop(&mut self) {
        if let Some(hub) = self.hub.upgrade() {
            hub.disconnect(&self.node_id, self.generation);
        }
    }
}
