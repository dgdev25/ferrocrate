//! Node lifecycle supervisor: the single-node convergence loop.
//!
//! The supervisor ties together the pieces the manager already owns:
//!
//! * identity — [`super::identity`] provides the stable node record used to
//!   bind every mutation authorization.
//! * desired state — [`super::workload`] stores the versioned workload.
//! * scheduling — [`crate::scheduler::place`] is the admission check that a
//!   workload fits the node's capability record.
//! * rolling updates — [`crate::rollout::plan`] produces the step shape;
//!   this module adds health gates, the revision floor, and rollback.
//! * service discovery — the [`crate::service_discovery::ServiceCatalog`]
//!   snapshot is rebuilt from healthy instances after every pass.
//! * journal — [`super::journal`] records intent/outcome around every effect
//!   so a crash at any boundary converges on restart.
//!
//! Scope: single node. The controller signing key lives in-process; a
//! multi-node deployment would move it to the manager service.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    rollout,
    scheduler::{self, Task},
    service_discovery::{CatalogError, Endpoint, ServiceCatalog},
};

use super::{
    executor::{
        ExecutorError, InstanceView, MutationAction, MutationAuthorization, MutationIntent,
        WorkloadExecutor,
    },
    identity::NodeIdentity,
    journal::{AmbiguousIntent, JournalError, LifecycleJournal},
    workload::{DesiredWorkload, ServiceSpec, WorkloadError, WorkloadStore},
};

/// Consecutive-failure threshold crossing triggers at most this many
/// restarts per instance before the instance is left for an operator.
pub const RESTART_BUDGET: u32 = 3;

/// Endpoint lease published into the service catalog.
pub const ENDPOINT_LEASE_SECONDS: i64 = 300;

/// Crash boundaries a test can inject, mirroring the witness-journal fault
/// machinery in `ferro-core`. Reaching an armed point aborts the pass; the
/// next pass must converge from whatever was durably recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LifecycleFaultPoint {
    AfterIntentRecord,
    AfterEffect,
    AfterOutcomeRecord,
    AfterCatalogUpdate,
}

#[derive(Default)]
pub struct LifecycleFaults(Mutex<HashSet<LifecycleFaultPoint>>);

impl LifecycleFaults {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn fail_once(&self, point: LifecycleFaultPoint) {
        self.0.lock().unwrap().insert(point);
    }

    fn trip(&self, point: LifecycleFaultPoint) {
        if self.0.lock().unwrap().remove(&point) {
            panic!("lifecycle fault point {point:?}");
        }
    }
}

/// Per-instance health bookkeeping, persisted across restarts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthTrack {
    pub consecutive_failures: u32,
    pub restarts: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisorState {
    pub applied_revision: u64,
    pub health: BTreeMap<String, HealthTrack>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    pub started: Vec<String>,
    pub stopped: Vec<String>,
    pub restarted: Vec<String>,
    pub rolled_back: Vec<String>,
    pub recovered_ambiguous: usize,
}

/// A rolling update that failed its health gate and was rolled back.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("update of `{service}` aborted and rolled back: {reason}")]
pub struct UpdateAborted {
    pub service: String,
    pub reason: String,
}

/// Instances touched by a completed rolling update.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateOutcome {
    pub started: Vec<String>,
    pub stopped: Vec<String>,
}

#[derive(Debug, Error)]
pub enum SupervisorError {
    #[error(transparent)]
    Workload(#[from] WorkloadError),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error("executor failed: {0}")]
    Executor(String),
    #[error("workload does not fit this node: {0}")]
    Unschedulable(String),
    #[error("state persistence failed: {0}")]
    State(String),
    #[error("service catalog error: {0}")]
    Catalog(String),
}

pub struct NodeSupervisor<E: WorkloadExecutor> {
    identity: NodeIdentity,
    controller_key: SigningKey,
    workload_store: WorkloadStore,
    journal: LifecycleJournal,
    executor: Arc<E>,
    state_path: PathBuf,
    catalog_path: PathBuf,
    state: Mutex<SupervisorState>,
    catalog: Mutex<ServiceCatalog>,
    faults: LifecycleFaults,
}

impl<E: WorkloadExecutor> NodeSupervisor<E> {
    /// Build a supervisor whose durable state lives under `root`.
    pub fn new(
        identity: NodeIdentity,
        root: impl AsRef<Path>,
        executor: Arc<E>,
        controller_key: SigningKey,
    ) -> Result<Self, SupervisorError> {
        let root = root.as_ref();
        let workload_store = WorkloadStore::new(root.join("workload.json"));
        let journal = LifecycleJournal::new(root.join("journal.jsonl"));
        let state_path = root.join("supervisor-state.json");
        let catalog_path = root.join("catalog.json");
        let state = if state_path.exists() {
            let bytes =
                fs::read(&state_path).map_err(|error| SupervisorError::State(error.to_string()))?;
            serde_json::from_slice(&bytes)
                .map_err(|error| SupervisorError::State(error.to_string()))?
        } else {
            SupervisorState::default()
        };
        let catalog = if catalog_path.exists() {
            let bytes = fs::read(&catalog_path)
                .map_err(|error| SupervisorError::Catalog(error.to_string()))?;
            let now = unix_now();
            ServiceCatalog::from_snapshot(&bytes, now)
                .map_err(|error: CatalogError| SupervisorError::Catalog(error.to_string()))?
        } else {
            ServiceCatalog::default()
        };
        Ok(Self {
            identity,
            controller_key,
            workload_store,
            journal,
            executor,
            state_path,
            catalog_path,
            state: Mutex::new(state),
            catalog: Mutex::new(catalog),
            faults: LifecycleFaults::new(),
        })
    }

    pub fn faults(&self) -> &LifecycleFaults {
        &self.faults
    }

    /// Validate, admit, and durably publish a desired workload.
    ///
    /// Admission reuses the scheduler placement check: the whole workload
    /// must fit the node's capability record in one deterministic pass.
    pub fn publish_desired(&self, workload: DesiredWorkload) -> Result<(), SupervisorError> {
        workload.validate()?;
        let capabilities = &self.identity.capabilities;
        let node = scheduler::Node {
            id: self.identity.node_id.clone(),
            labels: capabilities.labels.clone(),
            cpu_millis: capabilities.cpu_millis,
            memory_bytes: capabilities.memory_bytes,
            task_limit: capabilities.task_limit,
            running_tasks: 0,
            healthy: true,
        };
        let tasks: Vec<Task> = workload
            .services
            .iter()
            .flat_map(|service| {
                (0..service.instances).map(move |index| {
                    let instance =
                        DesiredWorkload::instance_id(&service.name, workload.revision, index);
                    Task {
                        id: instance,
                        cpu_millis: service.cpu_millis_per_instance,
                        memory_bytes: service.memory_bytes_per_instance,
                        required_labels: BTreeMap::new(),
                    }
                })
            })
            .collect();
        scheduler::place(&[node], &tasks)
            .map_err(|error| SupervisorError::Unschedulable(error.to_string()))?;
        self.workload_store.save(&workload)?;
        Ok(())
    }

    /// Query the service catalog for healthy endpoints.
    pub fn resolve(&self, service: &str, now_unix: i64) -> Vec<Endpoint> {
        self.catalog.lock().unwrap().resolve(service, now_unix)
    }

    /// One convergence pass: recover ambiguous journal records, converge
    /// observed state to the desired workload, and republish discovery.
    pub fn reconcile(&self, now_unix: i64) -> Result<ReconcileReport, SupervisorError> {
        let mut report = ReconcileReport::default();
        report.recovered_ambiguous = self.recover_ambiguous(now_unix)?;

        let desired = self.workload_store.load()?;
        let observed = self
            .executor
            .list()
            .map_err(|error| SupervisorError::Executor(error.to_string()))?;

        let Some(desired) = desired else {
            for view in &observed {
                self.apply_mutation(
                    MutationAction::Stop,
                    &view.instance_id,
                    &view.service,
                    &view.image,
                    view.revision,
                    now_unix,
                )?;
                report.stopped.push(view.instance_id.clone());
            }
            self.publish_catalog(&observed, now_unix)?;
            self.save_state(0)?;
            return Ok(report);
        };

        let mut managed: BTreeMap<String, Vec<InstanceView>> = BTreeMap::new();
        for view in observed {
            managed.entry(view.service.clone()).or_default().push(view);
        }

        for spec in &desired.services {
            let service_instances = managed.get(&spec.name).cloned().unwrap_or_default();
            let stale: Vec<InstanceView> = service_instances
                .into_iter()
                .filter(|view| view.revision != desired.revision)
                .collect();

            if !stale.is_empty() {
                match self.rolling_update(spec, desired.revision, &stale, now_unix)? {
                    Ok(outcome) => {
                        report.started.extend(outcome.started);
                        report.stopped.extend(outcome.stopped);
                    }
                    Err(aborted) => {
                        report.rolled_back.push(aborted.service);
                        continue;
                    }
                }
            }

            // Re-observe after the update and converge the instance count.
            let current: Vec<InstanceView> = self
                .executor
                .list()
                .map_err(|error| SupervisorError::Executor(error.to_string()))?
                .into_iter()
                .filter(|view| view.service == spec.name && view.revision == desired.revision)
                .collect();
            let running: BTreeSet<String> = current
                .iter()
                .map(|view| view.instance_id.clone())
                .collect();
            let target: BTreeSet<String> =
                spec.instance_ids(desired.revision).into_iter().collect();
            for instance in target.difference(&running) {
                self.apply_mutation(
                    MutationAction::Start,
                    instance,
                    &spec.name,
                    &spec.image,
                    desired.revision,
                    now_unix,
                )?;
                report.started.push(instance.clone());
            }
            for instance in running.difference(&target) {
                self.apply_mutation(
                    MutationAction::Stop,
                    instance,
                    &spec.name,
                    &spec.image,
                    desired.revision,
                    now_unix,
                )?;
                report.stopped.push(instance.clone());
            }
        }

        // Orphaned services: running but no longer desired.
        let desired_names: BTreeSet<&str> = desired
            .services
            .iter()
            .map(|spec| spec.name.as_str())
            .collect();
        let post_observed = self
            .executor
            .list()
            .map_err(|error| SupervisorError::Executor(error.to_string()))?;
        for view in &post_observed {
            if !desired_names.contains(view.service.as_str()) {
                self.apply_mutation(
                    MutationAction::Stop,
                    &view.instance_id,
                    &view.service,
                    &view.image,
                    view.revision,
                    now_unix,
                )?;
                report.stopped.push(view.instance_id.clone());
            }
        }

        report.restarted = self.enforce_health(&desired, now_unix)?;

        let observed = self
            .executor
            .list()
            .map_err(|error| SupervisorError::Executor(error.to_string()))?;
        self.publish_catalog(&observed, now_unix)?;

        let applied = if report.rolled_back.is_empty() {
            desired.revision
        } else {
            self.state.lock().unwrap().applied_revision
        };
        self.save_state(applied)?;
        Ok(report)
    }

    /// Close ambiguous journal records by inspecting what really happened.
    fn recover_ambiguous(&self, now_unix: i64) -> Result<usize, SupervisorError> {
        let entries = self.journal.load()?;
        let ambiguous: Vec<AmbiguousIntent> = self.journal.ambiguous(&entries);
        if ambiguous.is_empty() {
            return Ok(0);
        }
        let observed = self
            .executor
            .list()
            .map_err(|error| SupervisorError::Executor(error.to_string()))?;
        let running: BTreeMap<&str, &InstanceView> = observed
            .iter()
            .map(|view| (view.instance_id.as_str(), view))
            .collect();
        for ambiguous in &ambiguous {
            let record = &ambiguous.record;
            let outcome = match record.action {
                MutationAction::Start => {
                    if running.contains_key(record.instance_id.as_str()) {
                        (true, "recovered: effect present")
                    } else {
                        (false, "recovered: effect absent; reconcile reapplies")
                    }
                }
                MutationAction::Stop => {
                    if running.contains_key(record.instance_id.as_str()) {
                        (false, "recovered: effect absent; reconcile reapplies")
                    } else {
                        (true, "recovered: effect present")
                    }
                }
            };
            self.journal
                .append_outcome(record.seq, outcome.0, outcome.1, now_unix)?;
        }
        Ok(ambiguous.len())
    }

    /// Apply one authorized, journaled mutation.
    fn apply_mutation(
        &self,
        action: MutationAction,
        instance_id: &str,
        service: &str,
        image: &str,
        target_revision: u64,
        now_unix: i64,
    ) -> Result<(), SupervisorError> {
        let intent = MutationIntent {
            node_id: self.identity.node_id.clone(),
            action,
            instance_id: instance_id.to_string(),
            service: service.to_string(),
            image: image.to_string(),
            target_revision,
            issued_unix: now_unix,
        };
        let authorization = MutationAuthorization::sign(intent, &self.controller_key);
        let seq =
            self.journal
                .append_intent(action, instance_id, service, target_revision, now_unix)?;
        self.faults.trip(LifecycleFaultPoint::AfterIntentRecord);
        let result = match action {
            MutationAction::Start => self.executor.start(&authorization),
            MutationAction::Stop => self.executor.stop(&authorization),
        };
        self.faults.trip(LifecycleFaultPoint::AfterEffect);
        let (ok, detail) = match &result {
            Ok(()) => (true, "applied".to_string()),
            Err(error) => (false, error.to_string()),
        };
        self.journal.append_outcome(seq, ok, &detail, now_unix)?;
        self.faults.trip(LifecycleFaultPoint::AfterOutcomeRecord);
        result.map_err(|error| SupervisorError::Executor(error.to_string()))
    }

    /// Rolling update with health gates, revision floor, and rollback.
    ///
    /// Step shape comes from [`crate::rollout::plan`]; this function adds
    /// the two safety conditions the planner cannot see: a started
    /// replacement must become healthy within the attempt budget, and an
    /// old instance is only stopped while healthy capacity stays at or
    /// above the revision floor.
    fn rolling_update(
        &self,
        spec: &ServiceSpec,
        new_revision: u64,
        stale: &[InstanceView],
        now_unix: i64,
    ) -> Result<Result<UpdateOutcome, UpdateAborted>, SupervisorError> {
        let old_revision = stale
            .iter()
            .map(|view| view.revision)
            .max()
            .unwrap_or(new_revision);
        let old_ids: Vec<String> = stale.iter().map(|view| view.instance_id.clone()).collect();
        let steps = rollout::plan(
            &old_ids,
            &spec.instance_ids(new_revision),
            rollout::RolloutPolicy {
                max_surge: spec.update.max_surge,
                max_unavailable: spec.update.max_unavailable,
            },
        )
        .map_err(|error| SupervisorError::Unschedulable(error.to_string()))?;

        let mut outcome = UpdateOutcome::default();
        let abort = |reason: String| UpdateAborted {
            service: spec.name.clone(),
            reason,
        };
        for step in steps {
            for instance in &step.start {
                if let Err(SupervisorError::Executor(detail)) = self.apply_mutation(
                    MutationAction::Start,
                    instance,
                    &spec.name,
                    &spec.image,
                    new_revision,
                    now_unix,
                ) {
                    self.rollback(spec, old_revision, new_revision, now_unix)?;
                    return Ok(Err(abort(format!("start of {instance} failed: {detail}"))));
                }
                outcome.started.push(instance.clone());
            }
            for instance in &step.start {
                if !self
                    .wait_until_healthy(instance, spec.update.health_attempts)
                    .map_err(|error| SupervisorError::Executor(error.to_string()))?
                {
                    self.rollback(spec, old_revision, new_revision, now_unix)?;
                    return Ok(Err(abort(format!("{instance} never became healthy"))));
                }
            }
            for instance in &step.stop {
                let observed = self
                    .executor
                    .list()
                    .map_err(|error| SupervisorError::Executor(error.to_string()))?;
                let healthy: usize = observed
                    .iter()
                    .filter(|view| view.service == spec.name && view.healthy)
                    .count();
                let target_healthy = observed
                    .iter()
                    .any(|view| &view.instance_id == instance && view.healthy);
                // Stop only while healthy capacity stays at or above the
                // revision floor. Deferred stops are picked up by the next pass.
                if healthy - usize::from(target_healthy) >= spec.update.revision_floor {
                    self.apply_mutation(
                        MutationAction::Stop,
                        instance,
                        &spec.name,
                        &spec.image,
                        new_revision,
                        now_unix,
                    )?;
                    outcome.stopped.push(instance.clone());
                }
            }
        }
        Ok(Ok(outcome))
    }

    /// Stop every instance of the failed revision and restore the previous
    /// revision to the desired instance count.
    fn rollback(
        &self,
        spec: &ServiceSpec,
        old_revision: u64,
        new_revision: u64,
        now_unix: i64,
    ) -> Result<(), SupervisorError> {
        let observed = self
            .executor
            .list()
            .map_err(|error| SupervisorError::Executor(error.to_string()))?;
        for view in observed.iter().filter(|view| view.revision == new_revision) {
            self.apply_mutation(
                MutationAction::Stop,
                &view.instance_id,
                &view.service,
                &view.image,
                new_revision,
                now_unix,
            )?;
        }
        let remaining_old: BTreeSet<String> = observed
            .iter()
            .filter(|view| view.revision == old_revision)
            .map(|view| view.instance_id.clone())
            .collect();
        for index in 0..spec.instances {
            let instance = DesiredWorkload::instance_id(&spec.name, old_revision, index);
            if !remaining_old.contains(&instance) {
                self.apply_mutation(
                    MutationAction::Start,
                    &instance,
                    &spec.name,
                    &spec.image,
                    old_revision,
                    now_unix,
                )?;
            }
        }
        Ok(())
    }

    /// Poll the executor until the instance reports healthy or attempts run
    /// out. Returns whether the instance became healthy.
    fn wait_until_healthy(&self, instance_id: &str, attempts: u32) -> Result<bool, ExecutorError> {
        for _ in 0..attempts {
            let observed = self.executor.list()?;
            if observed
                .iter()
                .any(|view| view.instance_id == instance_id && view.healthy)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Restart instances whose health collapsed, bounded by the restart
    /// budget. Returns the restarted instance IDs.
    fn enforce_health(
        &self,
        desired: &DesiredWorkload,
        now_unix: i64,
    ) -> Result<Vec<String>, SupervisorError> {
        let observed = self
            .executor
            .list()
            .map_err(|error| SupervisorError::Executor(error.to_string()))?;
        let mut restart: Vec<InstanceView> = Vec::new();
        {
            let mut state = self.state.lock().unwrap();
            // Drop health tracking for instances that no longer exist.
            state
                .health
                .retain(|instance, _| observed.iter().any(|view| &view.instance_id == instance));

            for view in &observed {
                let Some(spec) = desired
                    .services
                    .iter()
                    .find(|spec| spec.name == view.service)
                else {
                    continue;
                };
                if view.revision != desired.revision {
                    continue;
                }
                let track = state.health.entry(view.instance_id.clone()).or_default();
                if view.healthy {
                    track.consecutive_failures = 0;
                    continue;
                }
                track.consecutive_failures += 1;
                if track.consecutive_failures < spec.health.retries
                    || track.restarts >= RESTART_BUDGET
                {
                    continue;
                }
                track.consecutive_failures = 0;
                track.restarts += 1;
                restart.push(view.clone());
            }
        }
        let mut restarted = Vec::new();
        for view in restart {
            self.apply_mutation(
                MutationAction::Stop,
                &view.instance_id,
                &view.service,
                &view.image,
                view.revision,
                now_unix,
            )?;
            self.apply_mutation(
                MutationAction::Start,
                &view.instance_id,
                &view.service,
                &view.image,
                view.revision,
                now_unix,
            )?;
            restarted.push(view.instance_id);
        }
        Ok(restarted)
    }

    /// Rebuild the service catalog from currently healthy instances and
    /// persist the snapshot.
    fn publish_catalog(
        &self,
        observed: &[InstanceView],
        now_unix: i64,
    ) -> Result<(), SupervisorError> {
        let mut catalog = ServiceCatalog::default();
        for view in observed.iter().filter(|view| view.running && view.healthy) {
            if let Some(address) = &view.address {
                catalog
                    .publish(
                        &view.service,
                        Endpoint {
                            task_id: view.instance_id.clone(),
                            address: address.clone(),
                            port: view.port,
                            healthy: true,
                            expires_at_unix: now_unix + ENDPOINT_LEASE_SECONDS,
                        },
                        now_unix,
                    )
                    .map_err(|error| SupervisorError::Catalog(error.to_string()))?;
            }
        }
        let snapshot = catalog
            .snapshot()
            .map_err(|error| SupervisorError::Catalog(error.to_string()))?;
        if let Some(parent) = self.catalog_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| SupervisorError::Catalog(error.to_string()))?;
        }
        fs::write(&self.catalog_path, snapshot)
            .map_err(|error| SupervisorError::Catalog(error.to_string()))?;
        *self.catalog.lock().unwrap() = catalog;
        self.faults.trip(LifecycleFaultPoint::AfterCatalogUpdate);
        Ok(())
    }

    fn save_state(&self, applied_revision: u64) -> Result<(), SupervisorError> {
        let mut state = self.state.lock().unwrap();
        state.applied_revision = applied_revision;
        let bytes = serde_json::to_vec(&*state)
            .map_err(|error| SupervisorError::State(error.to_string()))?;
        fs::write(&self.state_path, bytes)
            .map_err(|error| SupervisorError::State(error.to_string()))?;
        Ok(())
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::{
        executor::{RecordedOutcome, RecordingExecutor},
        identity::{IdentityStore, NodeCapabilities, NodeIdentity},
        workload::{DesiredWorkload, HealthPolicy, ServiceSpec, UpdatePolicy},
    };
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::Arc;

    fn capabilities() -> NodeCapabilities {
        NodeCapabilities {
            labels: BTreeMap::new(),
            cpu_millis: 4_000,
            memory_bytes: 8 * 1024 * 1024 * 1024,
            task_limit: 16,
        }
    }

    fn service(name: &str, instances: u32) -> ServiceSpec {
        ServiceSpec {
            name: name.into(),
            image: "registry.local/demo:1".into(),
            instances,
            cpu_millis_per_instance: 500,
            memory_bytes_per_instance: 64 * 1024 * 1024,
            port: 8080,
            update: UpdatePolicy {
                max_surge: 1,
                max_unavailable: 1,
                revision_floor: 1,
                health_attempts: 3,
            },
            health: HealthPolicy { retries: 2 },
        }
    }

    fn workload(revision: u64, services: Vec<ServiceSpec>) -> DesiredWorkload {
        DesiredWorkload { revision, services }
    }

    struct Harness {
        _directory: tempfile::TempDir,
        root: PathBuf,
        identity: NodeIdentity,
        executor: Arc<RecordingExecutor>,
        key: SigningKey,
        supervisor: NodeSupervisor<RecordingExecutor>,
    }

    impl Harness {
        fn new() -> Self {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path().to_path_buf();
            let identity = IdentityStore::new(root.join("identity.json"))
                .load_or_enroll(capabilities(), unix_now())
                .unwrap();
            let key = SigningKey::from_bytes(&[9; 32]);
            let executor = Arc::new(RecordingExecutor::new(&identity.node_id, &key));
            let supervisor =
                NodeSupervisor::new(identity.clone(), &root, Arc::clone(&executor), key.clone())
                    .unwrap();
            Self {
                _directory: directory,
                root,
                identity,
                executor,
                key,
                supervisor,
            }
        }

        fn reopen(&self) -> NodeSupervisor<RecordingExecutor> {
            NodeSupervisor::new(
                self.identity.clone(),
                &self.root,
                Arc::clone(&self.executor),
                self.key.clone(),
            )
            .unwrap()
        }
    }

    #[test]
    fn reconcile_is_idempotent_and_publishes_discovery() {
        let harness = Harness::new();
        let now = unix_now();
        harness
            .supervisor
            .publish_desired(workload(1, vec![service("web", 2)]))
            .unwrap();
        let first = harness.supervisor.reconcile(now).unwrap();
        assert_eq!(first.started.len(), 2);
        assert!(first.stopped.is_empty());
        let second = harness.supervisor.reconcile(now).unwrap();
        assert!(second.started.is_empty());
        assert!(second.stopped.is_empty());
        assert_eq!(harness.executor.running_count(), 2);
        let endpoints = harness.supervisor.resolve("web", now);
        assert_eq!(endpoints.len(), 2);
        assert!(endpoints.iter().all(|endpoint| endpoint.healthy));
    }

    #[test]
    fn stale_revisions_are_rejected_and_do_not_mutate() {
        let harness = Harness::new();
        harness
            .supervisor
            .publish_desired(workload(3, vec![service("web", 1)]))
            .unwrap();
        match harness
            .supervisor
            .publish_desired(workload(3, vec![service("web", 1)]))
        {
            Err(SupervisorError::Workload(WorkloadError::StaleRevision(3, 3))) => {}
            other => panic!("expected stale revision, got {other:?}"),
        }
        assert_eq!(harness.executor.running_count(), 0);
    }

    #[test]
    fn unschedulable_workloads_fail_closed_before_mutation() {
        let harness = Harness::new();
        let mut heavy = service("web", 1);
        heavy.cpu_millis_per_instance = 99_000;
        match harness.supervisor.publish_desired(workload(1, vec![heavy])) {
            Err(SupervisorError::Unschedulable(_)) => {}
            other => panic!("expected unschedulable, got {other:?}"),
        }
        assert_eq!(harness.executor.running_count(), 0);
    }

    #[test]
    fn rolling_update_replaces_stale_revision_instances() {
        let harness = Harness::new();
        let now = unix_now();
        harness
            .supervisor
            .publish_desired(workload(1, vec![service("web", 1)]))
            .unwrap();
        harness.supervisor.reconcile(now).unwrap();
        assert!(harness.executor.instance("web-r1-0").is_some());

        harness
            .supervisor
            .publish_desired(workload(2, vec![service("web", 1)]))
            .unwrap();
        let report = harness.supervisor.reconcile(now).unwrap();
        assert!(report.started.contains(&"web-r2-0".to_string()));
        assert!(report.stopped.contains(&"web-r1-0".to_string()));
        assert!(harness.executor.instance("web-r1-0").is_none());
        assert!(harness.executor.instance("web-r2-0").is_some());
    }

    #[test]
    fn failed_update_rolls_back_to_the_previous_revision() {
        let harness = Harness::new();
        let now = unix_now();
        harness
            .supervisor
            .publish_desired(workload(1, vec![service("web", 1)]))
            .unwrap();
        harness.supervisor.reconcile(now).unwrap();
        harness.executor.fail_starts_for("web-r2-0");
        harness
            .supervisor
            .publish_desired(workload(2, vec![service("web", 1)]))
            .unwrap();
        let report = harness.supervisor.reconcile(now).unwrap();
        assert!(report.rolled_back.contains(&"web".to_string()));
        assert!(harness.executor.instance("web-r1-0").is_some());
        assert!(harness.executor.instance("web-r2-0").is_none());
    }

    #[test]
    fn health_retries_then_restarts_within_budget() {
        let harness = Harness::new();
        let now = unix_now();
        harness
            .supervisor
            .publish_desired(workload(1, vec![service("web", 1)]))
            .unwrap();
        harness.supervisor.reconcile(now).unwrap();
        harness.executor.set_unhealthy("web-r1-0");

        let first = harness.supervisor.reconcile(now).unwrap();
        assert!(first.restarted.is_empty(), "retries must not restart yet");
        let second = harness.supervisor.reconcile(now).unwrap();
        assert_eq!(second.restarted, vec!["web-r1-0".to_string()]);
        let stop_then_start = harness
            .executor
            .recorded()
            .into_iter()
            .rev()
            .take(2)
            .map(|record| (record.action, record.outcome))
            .collect::<Vec<_>>();
        assert_eq!(
            stop_then_start,
            vec![
                (MutationAction::Start, RecordedOutcome::Applied),
                (MutationAction::Stop, RecordedOutcome::Applied),
            ]
        );
    }

    #[test]
    fn crash_after_intent_recovers_and_replays_to_desired_state() {
        let harness = Harness::new();
        let now = unix_now();
        harness
            .supervisor
            .publish_desired(workload(1, vec![service("web", 1)]))
            .unwrap();
        harness
            .supervisor
            .faults()
            .fail_once(LifecycleFaultPoint::AfterIntentRecord);
        let panicked = catch_unwind(AssertUnwindSafe(|| {
            let _ = harness.supervisor.reconcile(now);
        }));
        assert!(panicked.is_err());
        assert_eq!(harness.executor.running_count(), 0);

        let recovered = harness.reopen();
        let report = recovered.reconcile(now).unwrap();
        assert!(report.recovered_ambiguous >= 1);
        assert_eq!(harness.executor.running_count(), 1);
        assert!(harness.executor.instance("web-r1-0").is_some());
    }

    #[test]
    fn crash_after_effect_does_not_duplicate_start() {
        let harness = Harness::new();
        let now = unix_now();
        harness
            .supervisor
            .publish_desired(workload(1, vec![service("web", 1)]))
            .unwrap();
        harness
            .supervisor
            .faults()
            .fail_once(LifecycleFaultPoint::AfterEffect);
        let panicked = catch_unwind(AssertUnwindSafe(|| {
            let _ = harness.supervisor.reconcile(now);
        }));
        assert!(panicked.is_err());
        assert_eq!(harness.executor.running_count(), 1);

        let recovered = harness.reopen();
        let report = recovered.reconcile(now).unwrap();
        assert!(report.recovered_ambiguous >= 1);
        assert!(report.started.is_empty());
        assert_eq!(harness.executor.running_count(), 1);
        let starts = harness
            .executor
            .recorded()
            .into_iter()
            .filter(|record| record.action == MutationAction::Start)
            .count();
        assert_eq!(
            starts, 1,
            "recovery must close the journal from observed state and not start twice"
        );
    }
}
