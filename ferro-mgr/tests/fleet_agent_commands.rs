#![cfg(target_os = "linux")]

use ferro_mgr::fleet::build_agent_cli_args;
use serde_json::json;

#[test]
fn agent_builds_allowlisted_container_commands_without_a_shell() {
    assert_eq!(
        build_agent_cli_args("list_containers", &json!({})).unwrap(),
        ["ps", "--all", "--format", "json"]
    );
    assert_eq!(
        build_agent_cli_args(
            "run_container",
            &json!({
                "image":"alpine:latest",
                "name":"fleet-lab",
                "command":["sh","-c","echo fleet-ready"]
            })
        )
        .unwrap(),
        [
            "run",
            "--detach",
            "--name",
            "fleet-lab",
            "--network",
            "none",
            "alpine:latest",
            "sh",
            "-c",
            "echo fleet-ready"
        ]
    );
    assert_eq!(
        build_agent_cli_args("container_logs", &json!({"container":"fleet-lab"})).unwrap(),
        ["logs", "fleet-lab", "--format", "text"]
    );
    assert_eq!(
        build_agent_cli_args("inspect_container", &json!({"container":"fleet-lab"})).unwrap(),
        ["inspect", "fleet-lab", "--format", "json"]
    );
}

#[test]
fn agent_rejects_unknown_actions_and_unsafe_or_oversized_values() {
    assert!(build_agent_cli_args("shell", &json!({"command":"id"})).is_err());
    assert!(build_agent_cli_args("container_logs", &json!({"container":"bad\nname"})).is_err());
    assert!(build_agent_cli_args(
        "run_container",
        &json!({"image":"alpine", "name":"x", "command":["x".repeat(5000)]})
    )
    .is_err());
}

#[test]
fn rollback_primitives_are_explicit_and_bounded() {
    assert_eq!(
        build_agent_cli_args("remove_container", &json!({"container":"fleet-lab"})).unwrap(),
        ["rm", "--force", "fleet-lab"]
    );
    assert_eq!(
        build_agent_cli_args("doctor", &json!({})).unwrap(),
        ["doctor", "--json"]
    );
}
