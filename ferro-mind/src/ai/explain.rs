use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub struct DecisionTrace {
    pub id: String,
    pub summary: String,
    pub evidence: BTreeMap<String, String>,
}

impl DecisionTrace {
    pub fn new(id: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            summary: summary.into(),
            evidence: BTreeMap::new(),
        }
    }

    pub fn with_evidence(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.evidence.insert(key.into(), value.into());
        self
    }
}
