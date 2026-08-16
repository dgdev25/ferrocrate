use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize)]
pub struct DecisionTrace {
    pub id: String,
    pub summary: String,
    pub model: Option<String>,
    pub model_version: Option<String>,
    pub decision: Option<String>,
    pub evidence: BTreeMap<String, String>,
}

impl DecisionTrace {
    pub fn new(id: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            summary: summary.into(),
            model: None,
            model_version: None,
            decision: None,
            evidence: BTreeMap::new(),
        }
    }

    pub fn with_model(mut self, model: impl Into<String>, version: impl Into<String>) -> Self {
        self.model = Some(model.into());
        self.model_version = Some(version.into());
        self
    }

    pub fn with_decision(mut self, decision: impl Into<String>) -> Self {
        self.decision = Some(decision.into());
        self
    }

    pub fn with_evidence(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.evidence.insert(key.into(), value.into());
        self
    }
}
