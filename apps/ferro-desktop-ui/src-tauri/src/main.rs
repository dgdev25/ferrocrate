#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::Serialize;
use std::process::Command;

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

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![get_desktop_snapshot])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
