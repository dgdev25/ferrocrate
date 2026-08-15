use std::{
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use super::Action;

#[derive(Clone, Debug)]
pub struct MutationAdmission {
    evidence: AdmissionEvidence,
    max_age: Duration,
    grace: Duration,
}

#[derive(Clone, Debug)]
enum AdmissionEvidence {
    Timestamp {
        checkpoint: PathBuf,
    },
    Verified {
        journal: PathBuf,
        journal_id: [u8; 16],
        trust: crate::witness::TrustBundle,
        minimum: crate::witness::Checkpoint,
        checkpoints: Vec<crate::witness::Checkpoint>,
    },
}

impl MutationAdmission {
    pub fn checkpoint(checkpoint: PathBuf, max_age: Duration, grace: Duration) -> Self {
        Self {
            evidence: AdmissionEvidence::Timestamp { checkpoint },
            max_age,
            grace,
        }
    }

    pub fn verified(
        journal: PathBuf,
        journal_id: [u8; 16],
        trust: crate::witness::TrustBundle,
        minimum: crate::witness::Checkpoint,
        checkpoints: Vec<crate::witness::Checkpoint>,
        max_age: Duration,
        grace: Duration,
    ) -> Self {
        Self {
            evidence: AdmissionEvidence::Verified {
                journal,
                journal_id,
                trust,
                minimum,
                checkpoints,
            },
            max_age,
            grace,
        }
    }

    pub fn admit(&self, action: Action) -> Result<(), MutationAdmissionError> {
        if matches!(
            action,
            Action::ContainerStop
                | Action::ContainerDelete
                | Action::CheckpointPublish
                | Action::CheckpointRecover
                | Action::KeyRotate
        ) {
            return Ok(());
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        match &self.evidence {
            AdmissionEvidence::Timestamp { checkpoint: path } => {
                let bytes = std::fs::read(path).map_err(|_| MutationAdmissionError)?;
                let checkpoint = crate::witness::Checkpoint::decode(&bytes)
                    .map_err(|_| MutationAdmissionError)?;
                crate::witness::CheckpointCoordinator::new(path, self.max_age, self.grace)
                    .allows_user_mutation(checkpoint.created_at_secs, now)
                    .then_some(())
                    .ok_or(MutationAdmissionError)
            }
            AdmissionEvidence::Verified {
                journal,
                journal_id,
                trust,
                minimum,
                checkpoints,
            } => {
                let mut reader =
                    crate::witness::WitnessReader::open_read_only(journal, *journal_id)
                        .map_err(|_| MutationAdmissionError)?;
                let report = crate::witness::CheckpointVerifier::new(
                    trust.clone().with_minimum(minimum.clone()),
                )
                .verify_iter(
                    reader.records(),
                    checkpoints,
                    now,
                    self.max_age.saturating_add(self.grace),
                )
                .map_err(|_| MutationAdmissionError)?;
                reader.finish().map_err(|_| MutationAdmissionError)?;
                (report.integrity
                    && report.lifecycle_consistent
                    && report.completeness_through_checkpoint == Some(true)
                    && matches!(
                        report.checkpoint_age,
                        Some(crate::witness::CheckpointAge::Current { .. })
                    ))
                .then_some(())
                .ok_or(MutationAdmissionError)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error(
    "mutation admission denied: checkpoint evidence is missing, invalid, future-dated, or stale"
)]
pub struct MutationAdmissionError;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::witness::{
        Checkpoint, CheckpointKind, FlushedHead, Invocation, JournalConfig, JournalMode,
        PrincipalSummary, ResourceSummary, TrustBundle, WitnessAction, WitnessJournal,
        WitnessOutcome, WitnessRecord, WitnessResourceKind, WitnessStage,
    };
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};

    #[test]
    fn verified_admission_rejects_wrong_key_journal_future_and_stale_evidence() {
        let root = tempfile::tempdir().unwrap();
        let id = [0x51; 16];
        let journal =
            WitnessJournal::open(JournalConfig::new(root.path(), id, JournalMode::Required))
                .unwrap();
        let key = SigningKey::from_bytes(&[0x52; 32]);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let checkpoint = Checkpoint::sign(
            FlushedHead::new(id, 1, 0, [0; 32]),
            now,
            &key,
            CheckpointKind::Periodic,
        )
        .unwrap();
        let digest: [u8; 32] = Sha256::digest(checkpoint.encode()).into();
        journal
            .append_checkpoint_publication(
                digest,
                WitnessRecord {
                    epoch: 1,
                    sequence: 1,
                    previous_hash: [0; 32],
                    event_id: [1; 16],
                    request_id: [2; 16],
                    runtime_instance_id: [3; 16],
                    boot_id: [4; 16],
                    principal: PrincipalSummary::pseudonymize(&[5; 32], b"coordinator").unwrap(),
                    invocation: Invocation::Manager,
                    action: WitnessAction::CheckpointPublish,
                    resource_kind: WitnessResourceKind::Administrative,
                    resource: ResourceSummary::pseudonymize(&[6; 32], b"checkpoint").unwrap(),
                    resource_generation: 1,
                    policy_version: 0,
                    policy_digest: [0; 32],
                    decision_id: None,
                    rule: None,
                    decision: None,
                    reason: None,
                    request_digest: digest,
                    result_digest: Some(digest),
                    wall_time_ns: 0,
                    monotonic_ns: 0,
                    stage: WitnessStage::CheckpointPublished,
                    outcome: WitnessOutcome::Succeeded,
                    recovery_link: None,
                    path_class: None,
                    device_class: None,
                    correlation_digest: None,
                },
            )
            .unwrap();
        let admission = |trust_key, cp: Checkpoint, journal_id| {
            MutationAdmission::verified(
                root.path().to_owned(),
                journal_id,
                TrustBundle::new(journal_id, trust_key),
                cp.clone(),
                vec![cp],
                Duration::from_secs(30),
                Duration::ZERO,
            )
        };
        assert!(admission(key.verifying_key(), checkpoint.clone(), id)
            .admit(Action::ContainerRun)
            .is_ok());

        let wrong = SigningKey::from_bytes(&[0x53; 32]);
        assert!(admission(wrong.verifying_key(), checkpoint.clone(), id)
            .admit(Action::ImagePull)
            .is_err());
        assert!(
            admission(key.verifying_key(), checkpoint.clone(), [0x54; 16])
                .admit(Action::VolumeCreate)
                .is_err()
        );

        let future = Checkpoint::sign(
            FlushedHead::new(id, 1, 0, [0; 32]),
            now + 1,
            &key,
            CheckpointKind::Periodic,
        )
        .unwrap();
        assert!(admission(key.verifying_key(), future, id)
            .admit(Action::NetworkCreate)
            .is_err());
        let stale = Checkpoint::sign(
            FlushedHead::new(id, 1, 0, [0; 32]),
            now - 31,
            &key,
            CheckpointKind::Periodic,
        )
        .unwrap();
        assert!(admission(key.verifying_key(), stale, id)
            .admit(Action::PolicyReload)
            .is_err());
    }

    #[test]
    fn every_user_surface_is_admission_gated_while_repair_and_cleanup_are_scoped() {
        let admission = MutationAdmission::checkpoint(
            PathBuf::from("/definitely/missing/checkpoint"),
            Duration::from_secs(1),
            Duration::ZERO,
        );
        for action in [
            Action::ContainerCreate,
            Action::ContainerRun,
            Action::ContainerExec,
            Action::ImagePull,
            Action::ImageDelete,
            Action::ImageBuild,
            Action::ImageTag,
            Action::ImageReferenceWrite,
            Action::VolumeCreate,
            Action::VolumeDelete,
            Action::VolumeMount,
            Action::VolumeUnmount,
            Action::NetworkCreate,
            Action::NetworkDelete,
            Action::NetworkAttach,
            Action::NetworkDetach,
            Action::DeviceUse,
            Action::PolicyReload,
            Action::PolicyRollback,
        ] {
            assert!(
                admission.admit(action).is_err(),
                "{action:?} bypassed admission"
            );
        }
        for action in [
            Action::ContainerStop,
            Action::ContainerDelete,
            Action::CheckpointPublish,
            Action::CheckpointRecover,
            Action::KeyRotate,
        ] {
            assert!(
                admission.admit(action).is_ok(),
                "{action:?} recovery path was blocked"
            );
        }
    }
}
