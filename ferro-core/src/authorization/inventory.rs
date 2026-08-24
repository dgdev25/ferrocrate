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
        "required_run_success_is_witnessed",
    ),
    entry(
        "mutation.runtime.exec",
        "ContainerRuntime::exec_authorized",
        "ContainerRuntime::exec",
        "required_exec_success_is_witnessed",
    ),
    entry(
        "mutation.runtime.pause",
        "ContainerRuntime::pause_authorized",
        "ContainerRuntime::pause",
        "required_pause_success_is_witnessed",
    ),
    entry(
        "mutation.runtime.resume",
        "ContainerRuntime::resume_authorized",
        "ContainerRuntime::resume",
        "required_resume_success_is_witnessed",
    ),
    entry(
        "mutation.runtime.stop",
        "ContainerRuntime::stop_authorized",
        "ContainerRuntime::stop",
        "required_stop_success_is_witnessed",
    ),
    entry(
        "mutation.runtime.kill",
        "ContainerRuntime::kill_authorized",
        "ContainerRuntime::kill",
        "required_kill_success_is_witnessed",
    ),
    entry(
        "mutation.runtime.restart",
        "ContainerRuntime::restart_authorized",
        "ContainerRuntime::restart",
        "required_restart_success_is_witnessed",
    ),
    entry(
        "mutation.runtime.remove",
        "ContainerRuntime::remove_authorized",
        "ContainerRuntime::remove",
        "required_remove_success_is_witnessed",
    ),
    entry("mutation.cli", "ferro-cli direct runtime mutation", "CLI effective RequestOrigin -> ContainerRuntime mediated method", "cli_identity_uses_effective_authority_not_sudo_environment"),
    entry("mutation.docker", "Docker Unix peer -> private runtime executor", "authenticate before read_http_request -> RequestOrigin -> ContainerRuntime mediated method", "docker_authentication_happens_from_socket_not_headers"),
    entry("mutation.compose", "verified dependent FanoutPlan child -> proof-consuming image/volume/runtime executor", "verify_child + durable replay claim -> child RequestOrigin -> SurfaceAuthorization or ContainerRuntime", "dependent_prerequisites_advance_only_through_committed_graph"),
    entry("mutation.cri", "CRI image mutation executor with effective identity", "authenticated Unix connect info -> immutable image binding -> SurfaceAuthorization::authorize_image_binding -> proof-consuming image executor", "metadata_is_telemetry_only_and_signed_delegation_becomes_gate_origin"),
    entry("mutation.runtime-background", "runtime-owned recovery and cleanup", "RuntimeAuthorization internal recovery", "quota_preserves_cleanup_reserve_and_exhaustion_stops_cleanup"),
    entry("mutation.images", "pull_image_with_store_authorized / pull_manifest_only_with_store_authorized / execute_dockerfile_build_authorized / execute_image_tag_authorized / LocalImageStore authorized reference executors", "authenticated origin -> immutable fetch/build/tag plan -> durable SurfacePermit", "image_fetch::tests::planned_pull_rejects_manifest_swap_before_store_mutation"),
    entry("mutation.volumes", "LocalVolumeStore::create_with_driver_authorized / remove_authorized / backup_authorized / restore_authorized", "authenticated origin -> action-specific VolumeCreate/VolumeDelete/VolumeBackup/VolumeRestore binding -> durable SurfacePermit", "authorization::tests::volume_archive_actions_have_distinct_policy_vocabulary"),
    entry(
        "mutation.networks",
        "execute_network_create / execute_network_remove",
        "handle_network_authorized (CLI NetworkCommands and Docker POST/DELETE /networks*) -> SurfaceAuthorization::authorize_named -> create_authorized / delete_authorized",
        "docker_compat_network_create_list_delete_routes_work",
    ),
    entry("mutation.rootless-mapping", "apply_user_namespace_mappings_authorized", "authenticated origin -> exact rootless.mapping SurfacePermit -> private procfs mapper", "rootless_configuration_mutates_the_real_runtime_namespaces"),
    entry("mutation.helper-calls", "privileged helper mutation executors", "GrantVerifier::verify -> request-bound grant", "accepts_once_and_correlates_the_result"),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InventoryError {
    EmptyField,
    DuplicateId,
    DuplicateTest,
}

pub fn validate_inventory(entries: &[MutationInventoryEntry]) -> Result<(), InventoryError> {
    let mut ids = std::collections::HashSet::new();
    let mut tests = std::collections::HashSet::new();
    for entry in entries {
        if entry.id.is_empty()
            || entry.executor.is_empty()
            || entry.gate_call_site.is_empty()
            || entry.mediation_test.is_empty()
        {
            return Err(InventoryError::EmptyField);
        }
        if !ids.insert(entry.id) {
            return Err(InventoryError::DuplicateId);
        }
        if !tests.insert(entry.mediation_test) {
            return Err(InventoryError::DuplicateTest);
        }
    }
    Ok(())
}

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
