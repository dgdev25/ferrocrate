#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const KEYRING_SERVICE: &str = "ferrocrate-desktop-ui";
const KEYRING_ACCOUNT: &str = "paid_session_token";

#[derive(Debug, Serialize)]
struct CommandResult {
    ok: bool,
    code: i32,
    stdout: String,
    stderr: String,
}

#[derive(Debug, Serialize)]
struct DesktopSnapshot {
    runtime: CommandResult,
    containers: CommandResult,
    images: CommandResult,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PaidBackendConfig {
    release_base_url: String,
    token_endpoint: String,
    #[serde(default)]
    issuance_endpoint: Option<String>,
}

#[derive(Debug, Serialize)]
struct SessionSummary {
    token_present: bool,
    subject: Option<String>,
    plan: Option<String>,
    expires_at: Option<u64>,
    expired: Option<bool>,
}

#[derive(Debug, Serialize)]
struct EntitlementSummary {
    status: String,
    plan: Option<String>,
    subject: Option<String>,
    expires_at: Option<u64>,
    features: Vec<String>,
    message: Option<String>,
}

#[derive(Debug, Serialize)]
struct DoctorSummary {
    ok: bool,
    raw: JsonValue,
}

#[derive(Debug, Serialize)]
struct PaidAuthState {
    config: Option<PaidBackendConfig>,
    session: SessionSummary,
    entitlement: Option<EntitlementSummary>,
}

#[derive(Debug, Serialize)]
struct InstallerRunSummary {
    dry_run: bool,
    ok: bool,
    command: String,
    result: Option<CommandResult>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DesktopAction {
    VmStart,
    VmStop,
    PullImage,
    RemoveImage,
    StartContainer,
    StopContainer,
    RemoveContainer,
    ContainerLogs,
    ImagePrune,
}

fn run_command(binary: &str, args: &[&str]) -> CommandResult {
    match Command::new(binary).args(args).output() {
        Ok(output) => CommandResult {
            ok: output.status.success(),
            code: output.status.code().unwrap_or(1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        },
        Err(err) => CommandResult {
            ok: false,
            code: 127,
            stdout: String::new(),
            stderr: format!("failed to run `{binary}`: {err}"),
        },
    }
}

fn run_command_env(binary: &str, args: &[&str], envs: &[(&str, String)]) -> CommandResult {
    let mut command = Command::new(binary);
    command.args(args);
    for (k, v) in envs {
        command.env(k, v);
    }
    match command.output() {
        Ok(output) => CommandResult {
            ok: output.status.success(),
            code: output.status.code().unwrap_or(1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        },
        Err(err) => CommandResult {
            ok: false,
            code: 127,
            stdout: String::new(),
            stderr: format!("failed to run `{binary}`: {err}"),
        },
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn config_path() -> Result<PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    let dir = PathBuf::from(home).join(".ferrocrate");
    fs::create_dir_all(&dir).map_err(|err| format!("failed to create config dir: {err}"))?;
    Ok(dir.join("desktop-ui-auth.json"))
}

fn read_paid_backend_config() -> Result<Option<PaidBackendConfig>, String> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path).map_err(|err| format!("failed to read config: {err}"))?;
    let parsed = serde_json::from_str::<PaidBackendConfig>(&raw)
        .map_err(|err| format!("invalid config JSON: {err}"))?;
    Ok(Some(parsed))
}

fn write_paid_backend_config(cfg: &PaidBackendConfig) -> Result<(), String> {
    let path = config_path()?;
    let raw = serde_json::to_string_pretty(cfg)
        .map_err(|err| format!("failed to encode config: {err}"))?;
    fs::write(&path, raw).map_err(|err| format!("failed to write config: {err}"))
}

fn keyring_entry() -> Result<keyring::Entry, String> {
    keyring::Entry::new(KEYRING_SERVICE, KEYRING_ACCOUNT)
        .map_err(|err| format!("keyring init failed: {err}"))
}

fn get_session_token() -> Result<Option<String>, String> {
    let entry = keyring_entry()?;
    match entry.get_password() {
        Ok(value) => {
            if value.trim().is_empty() {
                Ok(None)
            } else {
                Ok(Some(value))
            }
        }
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(err) => Err(format!("failed to read session token from keyring: {err}")),
    }
}

fn set_session_token(token: &str) -> Result<(), String> {
    let entry = keyring_entry()?;
    entry
        .set_password(token)
        .map_err(|err| format!("failed to write session token to keyring: {err}"))
}

fn clear_session_token() -> Result<(), String> {
    let entry = keyring_entry()?;
    match entry.delete_credential() {
        Ok(_) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(err) => Err(format!("failed to clear session token from keyring: {err}")),
    }
}

fn parse_jwt_claims(token: &str) -> Option<JsonValue> {
    let mut parts = token.split('.');
    let _header = parts.next()?;
    let payload = parts.next()?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload))
        .ok()?;
    serde_json::from_slice::<JsonValue>(&payload).ok()
}

fn session_summary_from_token(token: Option<String>) -> SessionSummary {
    let Some(token) = token else {
        return SessionSummary {
            token_present: false,
            subject: None,
            plan: None,
            expires_at: None,
            expired: None,
        };
    };
    let claims = parse_jwt_claims(&token);
    let expires_at = claims
        .as_ref()
        .and_then(|v| v.get("exp"))
        .and_then(|v| v.as_u64());
    let expired = expires_at.map(|exp| now_unix() >= exp);
    SessionSummary {
        token_present: true,
        subject: claims
            .as_ref()
            .and_then(|v| v.get("sub"))
            .and_then(|v| v.as_str())
            .map(ToString::to_string),
        plan: claims
            .as_ref()
            .and_then(|v| v.get("plan"))
            .and_then(|v| v.as_str())
            .map(ToString::to_string),
        expires_at,
        expired,
    }
}

fn query_entitlement_from_session(
    config: &PaidBackendConfig,
    session_token: &str,
) -> Result<EntitlementSummary, String> {
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&config.token_endpoint)
        .header("Authorization", format!("Bearer {session_token}"))
        .header("X-Ferrocrate-Tag", "latest")
        .send()
        .map_err(|err| format!("token endpoint request failed: {err}"))?;

    let status = resp.status();
    let body = resp
        .text()
        .map_err(|err| format!("token endpoint read failed: {err}"))?;
    if !status.is_success() {
        return Err(format!("token endpoint rejected session: {body}"));
    }
    let parsed = serde_json::from_str::<JsonValue>(&body)
        .map_err(|err| format!("token endpoint invalid JSON: {err}"))?;
    let plan = parsed
        .get("plan")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    let message = parsed
        .get("error")
        .and_then(|v| v.as_str())
        .map(ToString::to_string);
    Ok(EntitlementSummary {
        status: "ok".to_string(),
        plan,
        subject: None,
        expires_at: parsed.get("expires_at").and_then(|v| v.as_u64()),
        features: Vec::new(),
        message,
    })
}

#[tauri::command]
fn get_desktop_snapshot() -> DesktopSnapshot {
    let runtime = run_command("ferro-desktop", &["vm", "status", "--json"]);
    let containers = run_command("ferrocrate", &["ps"]);
    let images = run_command("ferrocrate", &["images"]);

    DesktopSnapshot {
        runtime,
        containers,
        images,
    }
}

#[tauri::command]
fn get_paid_auth_state() -> Result<PaidAuthState, String> {
    let config = read_paid_backend_config()?;
    let token = get_session_token()?;
    let session = session_summary_from_token(token.clone());
    let entitlement = match (&config, token) {
        (Some(cfg), Some(token_value)) => query_entitlement_from_session(cfg, &token_value).ok(),
        _ => None,
    };
    Ok(PaidAuthState {
        config,
        session,
        entitlement,
    })
}

#[tauri::command]
fn save_paid_backend_config(
    release_base_url: String,
    token_endpoint: String,
    issuance_endpoint: Option<String>,
) -> Result<(), String> {
    if release_base_url.trim().is_empty() || token_endpoint.trim().is_empty() {
        return Err("release_base_url and token_endpoint are required".to_string());
    }
    write_paid_backend_config(&PaidBackendConfig {
        release_base_url,
        token_endpoint,
        issuance_endpoint,
    })
}

#[tauri::command]
fn set_paid_session_token(token: String) -> Result<SessionSummary, String> {
    if token.trim().is_empty() {
        return Err("session token is required".to_string());
    }
    set_session_token(token.trim())?;
    Ok(session_summary_from_token(Some(token)))
}

#[tauri::command]
fn acquire_paid_session(
    customer_id: String,
    access_token: Option<String>,
) -> Result<SessionSummary, String> {
    if customer_id.trim().is_empty() {
        return Err("customer_id is required".to_string());
    }
    let cfg =
        read_paid_backend_config()?.ok_or_else(|| "paid backend config missing".to_string())?;
    let issuance = cfg
        .issuance_endpoint
        .ok_or_else(|| "issuance_endpoint is not configured".to_string())?;

    let client = reqwest::blocking::Client::new();
    let mut req = client
        .post(issuance)
        .json(&serde_json::json!({ "customer_id": customer_id.trim() }));
    if let Some(token) = access_token {
        if !token.trim().is_empty() {
            req = req.header("Authorization", format!("Bearer {}", token.trim()));
        }
    }
    let resp = req
        .send()
        .map_err(|err| format!("session issuance request failed: {err}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .map_err(|err| format!("session issuance response read failed: {err}"))?;
    if !status.is_success() {
        return Err(format!("session issuance failed: {body}"));
    }
    let parsed = serde_json::from_str::<JsonValue>(&body)
        .map_err(|err| format!("session issuance invalid JSON: {err}"))?;
    let token = parsed
        .get("session_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "session issuance response missing session_token".to_string())?;
    set_session_token(token)?;
    Ok(session_summary_from_token(Some(token.to_string())))
}

#[tauri::command]
fn clear_paid_session() -> Result<(), String> {
    clear_session_token()
}

#[tauri::command]
fn run_paid_full_stack_install(
    confirm: bool,
    dry_run: bool,
) -> Result<InstallerRunSummary, String> {
    let cfg =
        read_paid_backend_config()?.ok_or_else(|| "paid backend config missing".to_string())?;
    let token = get_session_token()?
        .ok_or_else(|| "paid session token missing (login required)".to_string())?;
    let command = "scripts/install-macos.sh --channel paid --full-stack".to_string();
    if dry_run {
        return Ok(InstallerRunSummary {
            dry_run: true,
            ok: true,
            command,
            result: None,
        });
    }
    if !confirm {
        return Err("install requires explicit confirmation (set confirm=true)".to_string());
    }
    let result = run_command_env(
        "bash",
        &[
            "scripts/install-macos.sh",
            "--channel",
            "paid",
            "--full-stack",
        ],
        &[
            ("PAID_RELEASE_BASE_URL", cfg.release_base_url),
            ("PAID_RELEASE_TOKEN_ENDPOINT", cfg.token_endpoint),
            ("PAID_SESSION_TOKEN", token),
        ],
    );
    Ok(InstallerRunSummary {
        dry_run: false,
        ok: result.ok,
        command,
        result: Some(result),
    })
}

#[tauri::command]
fn run_doctor_action(
    fix: bool,
    bootstrap: bool,
    dry_run: bool,
    confirm: bool,
) -> Result<DoctorSummary, String> {
    let mut args = vec!["doctor", "--json"];
    if fix {
        args.push("--fix");
    }
    if bootstrap {
        args.push("--bootstrap");
    }
    if dry_run {
        args.push("--dry-run");
    }
    if confirm {
        args.push("--yes");
    }
    let result = run_command("ferrocrate", &args);
    let payload = serde_json::from_str::<JsonValue>(&result.stdout).unwrap_or_else(|_| {
        serde_json::json!({
            "healthy": false,
            "error": "invalid doctor json output",
            "stdout": result.stdout,
            "stderr": result.stderr
        })
    });
    Ok(DoctorSummary {
        ok: result.ok,
        raw: payload,
    })
}

#[tauri::command]
fn run_desktop_action(action: DesktopAction, target: Option<String>) -> CommandResult {
    let target = target.unwrap_or_default().trim().to_string();
    match action {
        DesktopAction::VmStart => run_command("ferro-desktop", &["vm", "start"]),
        DesktopAction::VmStop => run_command("ferro-desktop", &["vm", "stop"]),
        DesktopAction::PullImage => {
            if target.is_empty() {
                return CommandResult {
                    ok: false,
                    code: 2,
                    stdout: String::new(),
                    stderr: "target image is required".to_string(),
                };
            }
            run_command("ferrocrate", &["pull", &target])
        }
        DesktopAction::RemoveImage => {
            if target.is_empty() {
                return CommandResult {
                    ok: false,
                    code: 2,
                    stdout: String::new(),
                    stderr: "target image is required".to_string(),
                };
            }
            run_command("ferrocrate", &["rmi", &target])
        }
        DesktopAction::StartContainer => {
            if target.is_empty() {
                return CommandResult {
                    ok: false,
                    code: 2,
                    stdout: String::new(),
                    stderr: "target container is required".to_string(),
                };
            }
            run_command("ferrocrate", &["restart", &target])
        }
        DesktopAction::StopContainer => {
            if target.is_empty() {
                return CommandResult {
                    ok: false,
                    code: 2,
                    stdout: String::new(),
                    stderr: "target container is required".to_string(),
                };
            }
            run_command("ferrocrate", &["stop", &target])
        }
        DesktopAction::RemoveContainer => {
            if target.is_empty() {
                return CommandResult {
                    ok: false,
                    code: 2,
                    stdout: String::new(),
                    stderr: "target container is required".to_string(),
                };
            }
            run_command("ferrocrate", &["rm", &target])
        }
        DesktopAction::ContainerLogs => {
            if target.is_empty() {
                return CommandResult {
                    ok: false,
                    code: 2,
                    stdout: String::new(),
                    stderr: "target container is required".to_string(),
                };
            }
            run_command("ferrocrate", &["logs", &target])
        }
        DesktopAction::ImagePrune => run_command("ferrocrate", &["image-prune"]),
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_desktop_snapshot,
            run_desktop_action,
            get_paid_auth_state,
            save_paid_backend_config,
            set_paid_session_token,
            acquire_paid_session,
            clear_paid_session,
            run_paid_full_stack_install,
            run_doctor_action
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
