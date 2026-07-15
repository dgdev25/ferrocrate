#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ManagerMetrics {
    pub connected_nodes: u16,
    pub degraded_nodes: u16,
    pub desired_revision: u64,
    pub applied_revision: u64,
    pub queued_bytes: usize,
    pub rejected_enrollments: u64,
    pub reconciliation_failures: u64,
    pub lease_expiries: u64,
    pub rotation_state: String,
    pub revocations: u64,
}

impl ManagerMetrics {
    pub fn render_prometheus(&self) -> String {
        format!(
            "ferro_manager_connected_nodes {}\nferro_manager_degraded_nodes {}\nferro_manager_desired_revision {}\nferro_manager_applied_revision {}\nferro_manager_queued_bytes {}\nferro_manager_rejected_enrollments {}\nferro_manager_reconciliation_failures {}\nferro_manager_lease_expiries {}\nferro_manager_revocations {}\n",
            self.connected_nodes, self.degraded_nodes, self.desired_revision, self.applied_revision,
            self.queued_bytes, self.rejected_enrollments, self.reconciliation_failures,
            self.lease_expiries, self.revocations,
        )
    }
}
