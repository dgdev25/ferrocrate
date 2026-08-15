use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationState {
    Preparing,
    Ready,
    Committed,
    Aborted,
}

pub struct KeyRotation {
    state: RotationState,
    reachable: HashSet<String>,
    acknowledgements: HashSet<String>,
    pending_public_key: Vec<u8>,
}

impl KeyRotation {
    pub fn prepare(
        reachable: impl IntoIterator<Item = String>,
        pending_public_key: Vec<u8>,
    ) -> Self {
        Self {
            state: RotationState::Preparing,
            reachable: reachable.into_iter().collect(),
            acknowledgements: HashSet::new(),
            pending_public_key,
        }
    }

    pub fn acknowledge(&mut self, node_id: impl Into<String>) {
        if self.state == RotationState::Preparing {
            self.acknowledgements.insert(node_id.into());
        }
        if self.acknowledgements.is_superset(&self.reachable) {
            self.state = RotationState::Ready;
        }
    }

    pub fn commit(&mut self) -> bool {
        if self.state != RotationState::Ready {
            return false;
        }
        self.state = RotationState::Committed;
        true
    }

    pub fn abort(&mut self) {
        if self.state != RotationState::Committed {
            self.state = RotationState::Aborted;
        }
    }
    pub fn state(&self) -> &RotationState {
        &self.state
    }
    pub fn pending_public_key(&self) -> &[u8] {
        &self.pending_public_key
    }
}
