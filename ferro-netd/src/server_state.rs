use crate::{grants_recovery::RecoveryObservation, server::NetdServer};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
};

#[derive(Debug, Serialize, Deserialize)]
struct PersistedState {
    overlays: BTreeSet<String>,
    endpoints: BTreeMap<String, String>,
    #[serde(default)]
    routes: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    effect_receipts: BTreeMap<String, crate::effect_receipt::EffectReceipt>,
}

impl NetdServer {
    pub fn load_journal(mut self, path: PathBuf) -> Result<Self, String> {
        if path.exists() {
            let state: PersistedState =
                serde_json::from_slice(&fs::read(&path).map_err(|error| error.to_string())?)
                    .map_err(|error| error.to_string())?;
            self.overlays = state.overlays;
            self.endpoints = state.endpoints;
            self.routes = state.routes;
            self.effect_receipts = state.effect_receipts;
        }
        self.journal = Some(path);
        self.overlays
            .retain(|overlay| self.kernel.observe_link(overlay));
        self.endpoints
            .retain(|endpoint, _| self.kernel.observe_link(endpoint));
        self.persist()?;
        if let Some(grants) = self.grants.as_mut() {
            let overlays = &self.overlays;
            let endpoints = &self.endpoints;
            let receipts = &self.effect_receipts;
            let kernel = &self.kernel;
            grants
                .reconcile_unknown(|receipt| {
                    let identity = receipt.identity();
                    let (name, owned) = identity
                        .strip_prefix("overlay:")
                        .map(|name| (name, overlays.contains(name)))
                        .or_else(|| {
                            identity
                                .strip_prefix("endpoint:")
                                .map(|name| (name, endpoints.contains_key(name)))
                        })
                        .unwrap_or(("", false));
                    let receipt_matches = if receipt.expected_exists() {
                        receipts.get(&identity) == Some(receipt)
                    } else {
                        !receipts.contains_key(&identity)
                    };
                    if name.is_empty() || kernel.observe_link(name) != owned || !receipt_matches {
                        RecoveryObservation::Conflict
                    } else {
                        RecoveryObservation::Consistent(owned)
                    }
                })
                .map_err(|error| error.to_string())?;
        }
        Ok(self)
    }

    pub(crate) fn persist(&self) -> Result<(), String> {
        #[cfg(any(test, feature = "test-support"))]
        if self
            .test_faults
            .take(crate::test_support::FaultPoint::StatePersist)
        {
            return Err("injected state persistence failure".into());
        }
        let Some(path) = &self.journal else {
            return Ok(());
        };
        let temporary = path.with_extension("tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
        file.write_all(
            &serde_json::to_vec(&PersistedState {
                overlays: self.overlays.clone(),
                endpoints: self.endpoints.clone(),
                routes: self.routes.clone(),
                effect_receipts: self.effect_receipts.clone(),
            })
            .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        fs::rename(temporary, path).map_err(|error| error.to_string())
    }
}
