use crate::container_store::HealthConfig;
use serde_json::Value;

const DEFAULT_HEALTH_INTERVAL_SECS: u64 = 30;
const DEFAULT_HEALTH_TIMEOUT_SECS: u64 = 5;
const DEFAULT_HEALTH_RETRIES: u32 = 3;
const DEFAULT_HEALTH_START_PERIOD_SECS: u64 = 0;

pub fn healthcheck_from_config(json: &str) -> Option<HealthConfig> {
    let value: Value = serde_json::from_str(json).ok()?;
    let health = value
        .get("config")
        .and_then(|cfg| cfg.get("Healthcheck"))?;

    let test = health.get("Test")?.as_array()?;
    if test.is_empty() {
        return None;
    }

    let first = test[0].as_str()?.to_uppercase();
    if first == "NONE" {
        return None;
    }

    let cmd = match first.as_str() {
        "CMD" => test
            .iter()
            .skip(1)
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect::<Vec<_>>(),
        "CMD-SHELL" => {
            let body = test
                .iter()
                .skip(1)
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            vec!["/bin/sh".to_string(), "-c".to_string(), body]
        }
        _ => return None,
    };

    if cmd.is_empty() {
        return None;
    }

    Some(HealthConfig {
        cmd,
        interval_secs: nanos_to_secs(health.get("Interval"))
            .unwrap_or(DEFAULT_HEALTH_INTERVAL_SECS),
        timeout_secs: nanos_to_secs(health.get("Timeout"))
            .unwrap_or(DEFAULT_HEALTH_TIMEOUT_SECS),
        retries: health
            .get("Retries")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .unwrap_or(DEFAULT_HEALTH_RETRIES),
        start_period_secs: nanos_to_secs(health.get("StartPeriod"))
            .unwrap_or(DEFAULT_HEALTH_START_PERIOD_SECS),
    })
}

pub fn command_from_config(json: &str) -> Option<Vec<String>> {
    let value: Value = serde_json::from_str(json).ok()?;
    let config = value.get("config")?;
    let entrypoint = parse_string_array(config.get("Entrypoint"));
    let cmd = parse_string_array(config.get("Cmd"));

    let mut out = Vec::new();
    if let Some(entrypoint) = entrypoint {
        out.extend(entrypoint);
    }
    if let Some(cmd) = cmd { out.extend(cmd); }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

pub fn env_from_config(json: &str) -> Vec<String> {
    let value: Value = match serde_json::from_str(json) {
        Ok(value) => value,
        Err(_) => return Vec::new(),
    };
    let config = match value.get("config") {
        Some(config) => config,
        None => return Vec::new(),
    };
    parse_string_array(config.get("Env")).unwrap_or_default()
}

pub fn working_dir_from_config(json: &str) -> Option<String> {
    let value: Value = serde_json::from_str(json).ok()?;
    let config = value.get("config")?;
    config.get("WorkingDir")?.as_str().map(|s| s.to_string())
}

pub fn user_from_config(json: &str) -> Option<String> {
    let value: Value = serde_json::from_str(json).ok()?;
    let config = value.get("config")?;
    config.get("User")?.as_str().map(|s| s.to_string())
}

fn parse_string_array(value: Option<&Value>) -> Option<Vec<String>> {
    let value = value?;
    let array = value.as_array()?;
    let out = array
        .iter()
        .filter_map(|item| item.as_str().map(|s| s.to_string()))
        .collect::<Vec<_>>();
    if out.is_empty() { None } else { Some(out) }
}

fn nanos_to_secs(value: Option<&Value>) -> Option<u64> {
    let nanos = value?.as_u64()?;
    if nanos == 0 {
        return Some(0);
    }
    let secs = nanos / 1_000_000_000;
    if secs == 0 { Some(1) } else { Some(secs) }
}

#[cfg(test)]
mod tests {
    use super::{
        command_from_config, env_from_config, healthcheck_from_config, user_from_config,
        working_dir_from_config,
    };

    #[test]
    fn parses_cmd_healthcheck() {
        let json = r#"{
            "config": {
                "Healthcheck": {
                    "Test": ["CMD", "echo", "ok"],
                    "Interval": 30000000000,
                    "Timeout": 5000000000,
                    "Retries": 2,
                    "StartPeriod": 1000000000
                }
            }
        }"#;
        let health = healthcheck_from_config(json).expect("health");
        assert_eq!(health.cmd, vec!["echo".to_string(), "ok".to_string()]);
        assert_eq!(health.interval_secs, 30);
        assert_eq!(health.timeout_secs, 5);
        assert_eq!(health.retries, 2);
        assert_eq!(health.start_period_secs, 1);
    }

    #[test]
    fn parses_cmd_shell_healthcheck() {
        let json = r#"{
            "config": {
                "Healthcheck": {
                    "Test": ["CMD-SHELL", "echo ok"]
                }
            }
        }"#;
        let health = healthcheck_from_config(json).expect("health");
        assert_eq!(health.cmd[0], "/bin/sh");
        assert_eq!(health.cmd[1], "-c");
    }

    #[test]
    fn ignores_none_healthcheck() {
        let json = r#"{
            "config": {
                "Healthcheck": { "Test": ["NONE"] }
            }
        }"#;
        assert!(healthcheck_from_config(json).is_none());
    }

    #[test]
    fn parses_entrypoint_and_cmd() {
        let json = r#"{
            "config": {
                "Entrypoint": ["/bin/sh", "-c"],
                "Cmd": ["echo", "ok"]
            }
        }"#;
        let cmd = command_from_config(json).expect("cmd");
        assert_eq!(cmd, vec!["/bin/sh".to_string(), "-c".to_string(), "echo".to_string(), "ok".to_string()]);
    }

    #[test]
    fn parses_cmd_only() {
        let json = r#"{
            "config": {
                "Cmd": ["sleep", "1"]
            }
        }"#;
        let cmd = command_from_config(json).expect("cmd");
        assert_eq!(cmd, vec!["sleep".to_string(), "1".to_string()]);
    }

    #[test]
    fn parses_env_workdir_user() {
        let json = r#"{
            "config": {
                "Env": ["A=1", "B=2"],
                "WorkingDir": "/app",
                "User": "1001:1002"
            }
        }"#;
        assert_eq!(env_from_config(json), vec!["A=1".to_string(), "B=2".to_string()]);
        assert_eq!(working_dir_from_config(json), Some("/app".to_string()));
        assert_eq!(user_from_config(json), Some("1001:1002".to_string()));
    }
}
