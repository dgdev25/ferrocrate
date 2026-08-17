//! Deterministic, authorization-neutral workload placement primitives.
//!
//! The controller owns authorization and durable desired-state publication. This
//! module only answers the scheduling question: which eligible node can host a
//! task while respecting labels and remaining capacity? Keeping that decision
//! pure makes it safe to test and to bind to a revision/intent in the caller.

use std::collections::BTreeMap;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub id: String,
    pub labels: BTreeMap<String, String>,
    pub cpu_millis: u64,
    pub memory_bytes: u64,
    pub task_limit: usize,
    pub running_tasks: usize,
    pub healthy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    pub id: String,
    pub cpu_millis: u64,
    pub memory_bytes: u64,
    pub required_labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    pub task_id: String,
    pub node_id: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScheduleError {
    #[error("task `{task_id}` has no eligible node: {reason}")]
    Unschedulable { task_id: String, reason: String },
}

/// Place all tasks deterministically, returning a placement for each task.
///
/// Tasks are considered by id, and candidate nodes are considered by id. The
/// least-loaded candidate wins (ties are resolved by node id), so the result is
/// independent of the input vector ordering. Reservations made while placing
/// earlier tasks are respected by later tasks in the same call.
pub fn place(nodes: &[Node], tasks: &[Task]) -> Result<Vec<Placement>, ScheduleError> {
    let mut ordered_tasks = tasks.to_vec();
    ordered_tasks.sort_by(|left, right| left.id.cmp(&right.id));

    let mut available = nodes.to_vec();
    available.sort_by(|left, right| left.id.cmp(&right.id));

    let mut placements = Vec::with_capacity(ordered_tasks.len());
    for task in ordered_tasks {
        let candidate = available
            .iter_mut()
            .filter(|node| node.healthy)
            .filter(|node| node.running_tasks < node.task_limit)
            .filter(|node| node.cpu_millis >= task.cpu_millis)
            .filter(|node| node.memory_bytes >= task.memory_bytes)
            .filter(|node| {
                task.required_labels
                    .iter()
                    .all(|(key, value)| node.labels.get(key) == Some(value))
            })
            .min_by(|left, right| {
                let left_load = load_key(left);
                let right_load = load_key(right);
                left_load
                    .cmp(&right_load)
                    .then_with(|| left.id.cmp(&right.id))
            });

        let node = candidate.ok_or_else(|| ScheduleError::Unschedulable {
            task_id: task.id.clone(),
            reason: "no healthy node satisfies labels and remaining capacity".into(),
        })?;
        node.cpu_millis -= task.cpu_millis;
        node.memory_bytes -= task.memory_bytes;
        node.running_tasks += 1;
        placements.push(Placement {
            task_id: task.id,
            node_id: node.id.clone(),
        });
    }

    Ok(placements)
}

fn load_key(node: &Node) -> (usize, u64, u64) {
    // Compare task occupancy first, then remaining resources. The inverted
    // values make a node with more headroom sort first without floating point.
    (
        node.running_tasks,
        u64::MAX - node.cpu_millis,
        u64::MAX - node.memory_bytes,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, labels: &[(&str, &str)]) -> Node {
        Node {
            id: id.into(),
            labels: labels
                .iter()
                .map(|(key, value)| ((*key).into(), (*value).into()))
                .collect(),
            cpu_millis: 2_000,
            memory_bytes: 2_000,
            task_limit: 4,
            running_tasks: 0,
            healthy: true,
        }
    }

    fn task(id: &str) -> Task {
        Task {
            id: id.into(),
            cpu_millis: 500,
            memory_bytes: 500,
            required_labels: BTreeMap::new(),
        }
    }

    #[test]
    fn placement_is_independent_of_input_order() {
        let mut first = task("b");
        first.required_labels.insert("zone".into(), "west".into());
        let second = task("a");
        let nodes = [
            node("node-b", &[("zone", "east")]),
            node("node-a", &[("zone", "west")]),
        ];

        let placements = place(&nodes, &[first.clone(), second.clone()]).unwrap();
        let reversed = place(&nodes, &[second, first]).unwrap();
        assert_eq!(placements, reversed);
        assert_eq!(placements[0].task_id, "a");
        assert_eq!(placements[0].node_id, "node-a");
        assert_eq!(placements[1].node_id, "node-a");
    }

    #[test]
    fn labels_and_health_are_hard_constraints() {
        let mut task = task("gpu-job");
        task.required_labels
            .insert("accelerator".into(), "gpu".into());
        let mut unhealthy = node("node-a", &[("accelerator", "gpu")]);
        unhealthy.healthy = false;
        let result = place(&[unhealthy, node("node-b", &[])], &[task]);
        assert!(matches!(result, Err(ScheduleError::Unschedulable { .. })));
    }

    #[test]
    fn reservations_prevent_overcommit() {
        let mut only = node("node-a", &[]);
        only.cpu_millis = 500;
        only.memory_bytes = 500;
        assert!(place(&[only], &[task("a"), task("b")]).is_err());
    }

    #[test]
    fn existing_tasks_consume_task_slots() {
        let mut only = node("node-a", &[]);
        only.task_limit = 1;
        only.running_tasks = 1;
        assert!(place(&[only], &[task("a")]).is_err());
    }

    #[test]
    fn empty_workload_is_a_valid_noop() {
        assert_eq!(place(&[node("node-a", &[])], &[]).unwrap(), Vec::new());
    }
}
