#![cfg(target_os = "linux")]

use ferro_core::authorization::gate::{
    AuthorizationGate, AuthorizedRequest, CanonicalRequest, Denial,
};
use ferro_core::authorization::inventory::MUTATION_INVENTORY;
use ferro_core::authorization::inventory::{
    validate_inventory, InventoryError, MutationInventoryEntry,
};

#[test]
fn authorization_gate_exposes_the_proof_contract() {
    fn assert_contract(
        gate: &AuthorizationGate,
        request: CanonicalRequest,
    ) -> Result<AuthorizedRequest, Denial> {
        gate.authorize(request)
    }

    let _ = assert_contract;
}

#[test]
fn authorization_inventory_rejects_missing_and_duplicate_evidence() {
    let base = MUTATION_INVENTORY[0];
    let missing = MutationInventoryEntry {
        mediation_test: "",
        ..base
    };
    assert_eq!(
        validate_inventory(&[missing]),
        Err(InventoryError::EmptyField)
    );
    let duplicate_id = MutationInventoryEntry {
        mediation_test: "other_test",
        ..base
    };
    assert_eq!(
        validate_inventory(&[base, duplicate_id]),
        Err(InventoryError::DuplicateId)
    );
    let duplicate_test = MutationInventoryEntry {
        id: "mutation.other",
        ..base
    };
    assert_eq!(
        validate_inventory(&[base, duplicate_test]),
        Err(InventoryError::DuplicateTest)
    );
}

#[test]
fn authorization_gate_inventory_has_stable_unique_surface_ids() {
    let actual = MUTATION_INVENTORY
        .iter()
        .map(|entry| entry.id)
        .collect::<Vec<_>>();

    assert_eq!(
        actual,
        vec![
            "mutation.runtime.run",
            "mutation.runtime.exec",
            "mutation.runtime.pause",
            "mutation.runtime.resume",
            "mutation.runtime.stop",
            "mutation.runtime.kill",
            "mutation.runtime.restart",
            "mutation.runtime.remove",
            "mutation.cli",
            "mutation.docker",
            "mutation.compose",
            "mutation.cri",
            "mutation.runtime-background",
            "mutation.images",
            "mutation.volumes",
            "mutation.networks",
            "mutation.rootless-mapping",
            "mutation.helper-calls",
        ]
    );
    let unique = actual
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(unique.len(), actual.len());
    assert!(MUTATION_INVENTORY.iter().all(|entry| {
        !entry.executor.is_empty()
            && !entry.gate_call_site.is_empty()
            && !entry.mediation_test.is_empty()
    }));
}
