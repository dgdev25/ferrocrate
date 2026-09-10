use std::{future::Future, path::Path, pin::Pin};

use ferro_web::StaticAssets;
use rust_embed::RustEmbed;
use serde_json::{json, Value};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use crate::proto::{
    admin_service_client::AdminServiceClient, FleetCommandRequest, FleetDeployRequest,
    FleetRevokeRequest, FleetRollbackRequest, FleetSnapshotRequest, IssueEnrollmentTokenRequest,
};

use super::FleetUiBackend;

#[derive(RustEmbed)]
#[folder = "$OUT_DIR/ferrocrate-fleet-dist"]
pub struct FleetAssets;

impl StaticAssets for FleetAssets {
    fn get(&self, path: &str) -> Option<(Vec<u8>, &'static str)> {
        let path = Path::new(path);
        if path.components().any(|component| {
            !matches!(
                component,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        }) {
            return None;
        }
        let path = path.to_str()?;
        let mut bytes = <Self as RustEmbed>::get(path)?.data.into_owned();
        if path == "index.html" {
            let html = String::from_utf8(bytes).ok()?;
            bytes = html
                .replace(
                    "</head>",
                    "<script>window.__FERROCRATE_FLEET__=true</script></head>",
                )
                .into_bytes();
        }
        let mime = match mime_guess::from_path(path)
            .first_or_octet_stream()
            .essence_str()
        {
            "text/html" => "text/html; charset=utf-8",
            "text/css" => "text/css; charset=utf-8",
            "text/javascript" | "application/javascript" => "text/javascript; charset=utf-8",
            "image/svg+xml" => "image/svg+xml",
            "image/png" => "image/png",
            "font/woff2" => "font/woff2",
            _ => "application/octet-stream",
        };
        Some((bytes, mime))
    }
}

#[derive(Clone)]
pub struct TonicFleetBackend {
    client: AdminServiceClient<Channel>,
    cluster_id: String,
}

impl TonicFleetBackend {
    pub async fn connect(
        endpoint: String,
        domain: String,
        server_ca_pem: Vec<u8>,
        operator_cert_pem: Vec<u8>,
        operator_key_pem: Vec<u8>,
        cluster_id: impl Into<String>,
    ) -> Result<Self, String> {
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(server_ca_pem))
            .identity(Identity::from_pem(operator_cert_pem, operator_key_pem))
            .domain_name(domain);
        let channel = Endpoint::from_shared(endpoint)
            .map_err(|error| format!("invalid admin endpoint: {error}"))?
            .tls_config(tls)
            .map_err(|error| format!("invalid admin TLS configuration: {error}"))?
            .connect()
            .await
            .map_err(|error| format!("failed to connect to admin gRPC: {error}"))?;
        Ok(Self {
            client: AdminServiceClient::new(channel),
            cluster_id: cluster_id.into(),
        })
    }
}

impl FleetUiBackend for TonicFleetBackend {
    fn snapshot(&self) -> Pin<Box<dyn Future<Output = Result<Value, String>> + Send + '_>> {
        let mut client = self.client.clone();
        let cluster_id = self.cluster_id.clone();
        Box::pin(async move {
            let response = client
                .fleet_snapshot(FleetSnapshotRequest { cluster_id })
                .await
                .map_err(|error| format!("admin fleet snapshot failed: {error}"))?
                .into_inner();
            serde_json::from_str(&response.snapshot_json)
                .map_err(|error| format!("admin fleet snapshot was invalid: {error}"))
        })
    }

    fn operate(
        &self,
        command: &str,
        arguments: Value,
    ) -> Pin<Box<dyn Future<Output = Result<Value, String>> + Send + '_>> {
        let mut client = self.client.clone();
        let cluster_id = self.cluster_id.clone();
        let command = command.to_string();
        Box::pin(async move {
            match command.as_str() {
                "fleet_command" => {
                    let node_id = string_field(&arguments, "node_id")?;
                    let action = string_field(&arguments, "action")?;
                    let command_arguments = arguments
                        .get("arguments")
                        .cloned()
                        .unwrap_or_else(|| json!({}));
                    let response = client
                        .fleet_command(FleetCommandRequest {
                            cluster_id,
                            node_id,
                            action,
                            arguments_json: command_arguments.to_string(),
                        })
                        .await
                        .map_err(|error| format!("admin fleet command failed: {error}"))?
                        .into_inner();
                    Ok(json!({
                        "exit_code": response.exit_code,
                        "stdout": response.stdout,
                        "stderr": response.stderr,
                    }))
                }
                "fleet_revoke" => {
                    let response = client
                        .revoke_host(FleetRevokeRequest {
                            cluster_id,
                            node_id: string_field(&arguments, "node_id")?,
                            reason: string_field(&arguments, "reason")?,
                        })
                        .await
                        .map_err(|error| format!("admin host revocation failed: {error}"))?
                        .into_inner();
                    Ok(json!({"revoked":response.revoked}))
                }
                "fleet_deploy" => {
                    let command_values = arguments
                        .get("command")
                        .and_then(Value::as_array)
                        .ok_or_else(|| "fleet deploy requires command".to_string())?;
                    let command = command_values
                        .iter()
                        .map(|value| {
                            value
                                .as_str()
                                .map(str::to_string)
                                .ok_or_else(|| "fleet deploy command must contain strings".into())
                        })
                        .collect::<Result<Vec<String>, String>>()?;
                    let node_ids = arguments
                        .get("node_ids")
                        .and_then(Value::as_array)
                        .ok_or_else(|| "fleet deploy requires node_ids".to_string())?
                        .iter()
                        .map(|value| {
                            value
                                .as_str()
                                .map(str::to_string)
                                .ok_or_else(|| "fleet deploy node_ids must contain strings".into())
                        })
                        .collect::<Result<Vec<String>, String>>()?;
                    let response = client
                        .fleet_deploy(FleetDeployRequest {
                            cluster_id,
                            name: string_field(&arguments, "name")?,
                            image: string_field(&arguments, "image")?,
                            command,
                            node_ids,
                        })
                        .await
                        .map_err(|error| format!("admin fleet deploy failed: {error}"))?
                        .into_inner();
                    serde_json::from_str(&response.deployment_json)
                        .map_err(|error| format!("admin deployment response was invalid: {error}"))
                }
                "fleet_rollback" => {
                    let response = client
                        .fleet_rollback(FleetRollbackRequest {
                            cluster_id,
                            deployment_id: string_field(&arguments, "deployment_id")?,
                        })
                        .await
                        .map_err(|error| format!("admin fleet rollback failed: {error}"))?
                        .into_inner();
                    serde_json::from_str(&response.deployment_json)
                        .map_err(|error| format!("admin rollback response was invalid: {error}"))
                }
                "fleet_enrollment_token" => {
                    let response = client
                        .issue_enrollment_token(IssueEnrollmentTokenRequest {
                            cluster_id,
                            node_id: string_field(&arguments, "node_id")?,
                            endpoint: string_field(&arguments, "endpoint")?,
                            overlay_scope: arguments
                                .get("overlay_scope")
                                .and_then(Value::as_str)
                                .unwrap_or("fleet")
                                .to_string(),
                        })
                        .await
                        .map_err(|error| format!("admin enrollment token failed: {error}"))?
                        .into_inner();
                    Ok(json!({
                        "enrollment_token": response.enrollment_token,
                        "expires_at": response.expires_at,
                    }))
                }
                _ => Err("unknown fleet operation".into()),
            }
        })
    }
}

fn string_field(value: &Value, name: &str) -> Result<String, String> {
    value
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("fleet operation requires {name}"))
}
