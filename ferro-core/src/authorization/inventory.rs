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
    entry("mutation.compose", "verified FanoutPlan child -> private runtime executor", "verify_child -> child RequestOrigin -> ContainerRuntime mediated method", "children_bind_parent_order_action_digest_deadline_and_attempt"),
    entry("mutation.cri", "CRI image mutation executor with effective identity", "authenticated Unix connect info -> immutable image binding -> SurfaceAuthorization::authorize_image_binding -> proof-consuming image executor", "transport_is_authoritative_by_default_and_metadata_cannot_elevate"),
    entry("mutation.runtime-background", "runtime-owned recovery and cleanup", "RuntimeAuthorization internal recovery", "required_cleanup_reserve_survives_enospc"),
    entry("mutation.images", "pull_image_with_store_authorized / LocalImageStore::remove_reference_authorized / LocalImageStore::prune_references_authorized", "authenticated origin -> immutable image binding -> durable SurfacePermit", "required_surface_decision_is_durable_before_permit_is_returned"),
    entry("mutation.volumes", "LocalVolumeStore::create_with_driver_authorized / LocalVolumeStore::remove_authorized / LocalVolumeStore::restore_authorized", "authenticated origin -> canonical resource -> durable SurfacePermit", "completing_surface_permit_clears_pending_recovery"),
    entry("mutation.networks", "private execute_network_create / execute_network_remove", "CLI or authenticated Docker origin -> SurfaceAuthorization::authorize_named", "docker_compat_network_create_list_delete_routes_work"),
    entry("mutation.helper-calls", "privileged helper mutation executors", "GrantVerifier::verify -> request-bound grant", "helper_grant_is_single_use"),
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
