use std::fs;
use std::net::SocketAddr;
use std::path::{Component, PathBuf};
use std::sync::Arc;

use ferro_web::{CommandDispatcher, CommandRequest, EventHub, Server, StaticAssets};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use super::*;

pub(crate) type WebEventHub = EventHub;

#[derive(Clone)]
struct DirectoryAssets {
    root: PathBuf,
}

impl StaticAssets for DirectoryAssets {
    fn get(&self, path: &str) -> Option<(Vec<u8>, &'static str)> {
        let relative = PathBuf::from(path);
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_) | Component::CurDir))
        {
            return None;
        }
        let path = self.root.join(relative);
        let bytes = fs::read(&path).ok()?;
        let mime = match mime_guess::from_path(path)
            .first_or_octet_stream()
            .essence_str()
        {
            "text/html" => "text/html; charset=utf-8",
            "text/css" => "text/css; charset=utf-8",
            "text/javascript" | "application/javascript" => "text/javascript; charset=utf-8",
            "application/json" => "application/json; charset=utf-8",
            "image/svg+xml" => "image/svg+xml",
            "image/png" => "image/png",
            "image/jpeg" => "image/jpeg",
            "image/webp" => "image/webp",
            "font/woff2" => "font/woff2",
            _ => "application/octet-stream",
        };
        Some((bytes, mime))
    }
}

#[derive(Clone)]
struct DesktopDispatcher;

fn decode_action<T: DeserializeOwned>(value: Value) -> Result<T, String> {
    serde_json::from_value(value).map_err(|error| format!("invalid command arguments: {error}"))
}

fn encode<T: Serialize>(value: T) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|error| format!("failed to encode command result: {error}"))
}

fn encode_result<T: Serialize>(value: Result<T, String>) -> Result<Value, String> {
    encode(value?)
}

impl CommandDispatcher for DesktopDispatcher {
    fn dispatch(&self, request: CommandRequest, events: EventHub) -> Result<Value, String> {
        match request {
            CommandRequest::GetDesktopSnapshot => encode(get_desktop_snapshot()),
            CommandRequest::GetContainerStats(args) => encode(get_container_stats(args.ids)),
            CommandRequest::GetVolumes => encode_result(get_volumes()),
            CommandRequest::GetNetworks => encode_result(get_networks()),
            CommandRequest::GetContainerDetail(args) => {
                encode_result(get_container_detail(args.target))
            }
            CommandRequest::GetComposeSnapshot(args) => {
                encode_result(get_compose_snapshot(args.file))
            }
            CommandRequest::BuildImage(args) => encode_result(build_image_impl(
                EventSink::Web(events),
                args.context,
                args.tag,
                args.build_id,
            )),
            CommandRequest::RunDesktopAction(args) => {
                encode(run_desktop_action(decode_action(args.action)?, args.target))
            }
            CommandRequest::RunComposeAction(args) => {
                encode_result(run_compose_action(args.file, decode_action(args.action)?))
            }
            CommandRequest::RunVolumeAction(args) => {
                encode_result(run_volume_action(decode_action(args.action)?, args.target))
            }
            CommandRequest::RunNetworkAction(args) => encode_result(run_network_action(
                decode_action(args.action)?,
                args.target,
                args.subnet,
            )),
            CommandRequest::UpdateContainerResources(args) => {
                encode_result(update_container_resources(
                    args.target,
                    args.memory,
                    args.cpu_quota,
                    args.cpu_period,
                ))
            }
            CommandRequest::RunNewContainer(args) => encode_result(run_new_container(
                args.image,
                args.name,
                args.command,
                args.ports,
                args.volumes,
                args.pull_if_missing,
                args.environment,
                args.memory,
                args.cpu_quota,
                args.cpu_period,
            )),
            CommandRequest::GetRegistryAuthStatus(args) => {
                encode_result(get_registry_auth_status(args.registry))
            }
            CommandRequest::LoginRegistry(args) => {
                encode_result(login_registry(args.registry, args.username, args.password))
            }
            CommandRequest::LogoutRegistry(args) => encode_result(logout_registry(args.registry)),
            CommandRequest::StartLogFollow { target } => {
                encode_result(start_log_follow_impl(EventSink::Web(events), target))
            }
            CommandRequest::StopLogFollow => encode_result(stop_log_follow()),
            CommandRequest::StartTerminal(args) => encode_result(start_terminal_impl(
                EventSink::Web(events),
                args.target,
                args.shell,
                args.env,
                args.user,
                args.workdir,
            )),
            CommandRequest::WriteTerminal(args) => encode_result(write_terminal(args.data)),
            CommandRequest::ResizeTerminal(args) => {
                encode_result(resize_terminal(args.columns, args.rows))
            }
            CommandRequest::CloseTerminal => encode_result(close_terminal()),
            CommandRequest::GetPaidAuthState => encode_result(get_paid_auth_state()),
            CommandRequest::SavePaidBackendConfig(args) => encode_result(save_paid_backend_config(
                args.release_base_url,
                args.token_endpoint,
                args.issuance_endpoint,
            )),
            CommandRequest::SetPaidSessionToken(args) => {
                encode_result(set_paid_session_token(args.token))
            }
            CommandRequest::AcquirePaidSession(args) => {
                encode_result(acquire_paid_session(args.customer_id, args.access_token))
            }
            CommandRequest::ClearPaidSession => encode_result(clear_paid_session()),
            CommandRequest::RunPaidFullStackInstall(args) => {
                encode_result(run_paid_full_stack_install(args.confirm, args.dry_run))
            }
            CommandRequest::RunDoctorAction(args) => encode_result(run_doctor_action(
                args.fix,
                args.bootstrap,
                args.dry_run,
                args.confirm,
            )),
        }
    }
}

pub(crate) async fn run_web_bridge(addr: SocketAddr, dist: PathBuf) -> Result<(), String> {
    let token = ferro_web::generate_session_token()?;
    let server = Server::spawn_loopback(
        addr,
        token.clone(),
        Arc::new(DirectoryAssets { root: dist }),
        Arc::new(DesktopDispatcher),
    )
    .await?;
    println!(
        "web bridge ready at http://{}/#token={token}",
        server.addr()
    );
    server.wait().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_assets_reject_parent_traversal() {
        let assets = DirectoryAssets {
            root: PathBuf::from("/tmp"),
        };
        assert!(assets.get("../etc/passwd").is_none());
        assert!(assets.get("/etc/passwd").is_none());
    }

    #[test]
    fn dispatcher_implements_shared_command_contract() {
        fn assert_dispatcher(_: &dyn CommandDispatcher) {}
        assert_dispatcher(&DesktopDispatcher);
    }
}
