use ferro_mgr::{agent::{Agent, NetdClient, StateStore}, desired_state::DesiredStateBuilder, metrics::ManagerMetrics, proto::DesiredState};
use ed25519_dalek::SigningKey;
use tempfile::tempdir;

struct NoopNetd;
impl NetdClient for NoopNetd { fn apply(&self, _: &DesiredState) -> Result<(), String> { Ok(()) } }

#[test]
fn agents_256_converge_to_one_revision_without_secret_metrics() {
    let directory = tempdir().unwrap();
    let builder = DesiredStateBuilder::new("cluster-a", 1, vec![5; 32]);
    let desired = builder.snapshot(42, Vec::new(), 100);
    let mut agents = Vec::with_capacity(256);
    for index in 0..256 {
        let agent = Agent::new("cluster-a", SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes().to_vec(), StateStore::new(directory.path().join(format!("agent-{index}.json"))), NoopNetd).unwrap();
        agents.push(agent);
    }
    for agent in &agents { assert_eq!(agent.reconcile(desired.clone(), 101).unwrap(), 42); }
    assert!(agents.iter().all(|agent| agent.state().applied_revision == 42));
    let metrics = ManagerMetrics { connected_nodes: 256, desired_revision: 42, applied_revision: 42, rotation_state: "Committed".into(), ..Default::default() };
    let rendered = metrics.render_prometheus();
    assert!(rendered.contains("ferro_manager_connected_nodes 256"));
    assert!(!rendered.contains("555555"));
}
