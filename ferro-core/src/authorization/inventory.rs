//! Machine-readable inventory of mutation surfaces.

/// One mutation surface and the architecture test that proves its mediation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationInventoryEntry {
    pub id: &'static str,
    pub executor: &'static str,
    pub gate_call_site: &'static str,
    pub mediation_test: &'static str,
}

/// Closed inventory consumed by complete-mediation architecture tests.
pub const MUTATION_INVENTORY: &[MutationInventoryEntry] = &[
    entry(
        "mutation.runtime.run",
        "ContainerRuntime::run_with_store_authorized",
        "ContainerRuntime::run_with_store",
        "every_allowed_lifecycle_method_has_one_decision_and_terminal_receipt",
    ),
    entry(
        "mutation.runtime.exec",
        "ContainerRuntime::exec_authorized",
        "ContainerRuntime::exec",
        "exec_exposes_every_durable_crash_boundary_in_order",
    ),
    entry(
        "mutation.runtime.pause",
        "ContainerRuntime::pause_authorized",
        "ContainerRuntime::pause",
        "every_allowed_lifecycle_method_has_one_decision_and_terminal_receipt",
    ),
    entry(
        "mutation.runtime.resume",
        "ContainerRuntime::resume_authorized",
        "ContainerRuntime::resume",
        "every_allowed_lifecycle_method_has_one_decision_and_terminal_receipt",
    ),
    entry(
        "mutation.runtime.stop",
        "ContainerRuntime::stop_authorized",
        "ContainerRuntime::stop",
        "every_allowed_lifecycle_method_has_one_decision_and_terminal_receipt",
    ),
    entry(
        "mutation.runtime.kill",
        "ContainerRuntime::kill_authorized",
        "ContainerRuntime::kill",
        "every_allowed_lifecycle_method_has_one_decision_and_terminal_receipt",
    ),
    entry(
        "mutation.runtime.restart",
        "ContainerRuntime::restart_authorized",
        "ContainerRuntime::restart",
        "restart_effect_records_old_and_new_execution_generations",
    ),
    entry(
        "mutation.runtime.remove",
        "ContainerRuntime::remove_authorized",
        "ContainerRuntime::remove",
        "delete_keeps_operation_tombstone_until_terminal_ack",
    ),
    entry(
        "mutation.cli",
        "CLI commands",
        "AuthorizationGate::authorize",
        "mediation_cli",
    ),
    entry(
        "mutation.docker",
        "Docker API",
        "AuthorizationGate::authorize",
        "mediation_docker",
    ),
    entry(
        "mutation.compose",
        "Compose children",
        "AuthorizationGate::authorize",
        "mediation_compose",
    ),
    entry(
        "mutation.cri",
        "CRI service",
        "AuthorizationGate::authorize",
        "mediation_cri",
    ),
    entry(
        "mutation.runtime-background",
        "runtime background work",
        "AuthorizationGate::authorize",
        "mediation_runtime_background",
    ),
    entry(
        "mutation.images",
        "image store",
        "AuthorizationGate::authorize",
        "mediation_images",
    ),
    entry(
        "mutation.volumes",
        "volume store",
        "AuthorizationGate::authorize",
        "mediation_volumes",
    ),
    entry(
        "mutation.networks",
        "network manager",
        "AuthorizationGate::authorize",
        "mediation_networks",
    ),
    entry(
        "mutation.helper-calls",
        "privileged helper calls",
        "AuthorizationGate::authorize",
        "mediation_helper_calls",
    ),
];

const fn entry(
    id: &'static str,
    executor: &'static str,
    gate_call_site: &'static str,
    mediation_test: &'static str,
) -> MutationInventoryEntry {
    MutationInventoryEntry {
        id,
        executor,
        gate_call_site,
        mediation_test,
    }
}
