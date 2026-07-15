#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPlan {
    pub restored_database_path: String,
    pub next_epoch: u64,
    pub rotate_issuing_ca: bool,
    pub expire_all_credentials: bool,
}

impl RecoveryPlan {
    pub fn restore_and_rekey(restored_database_path: impl Into<String>, current_epoch: u64) -> Self {
        Self {
            restored_database_path: restored_database_path.into(),
            next_epoch: current_epoch.saturating_add(1),
            rotate_issuing_ca: true,
            expire_all_credentials: true,
        }
    }
}
