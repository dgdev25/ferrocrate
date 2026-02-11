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
    use super::healthcheck_from_config;

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
}
