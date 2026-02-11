use crate::registry::{RegistryAuth, parse_image_reference};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DockerAuthError {
    #[error("failed to read docker config: {0}")]
    Read(String),
    #[error("failed to parse docker config: {0}")]
    Parse(String),
    #[error("invalid auth entry for registry {0}")]
    InvalidAuth(String),
}

#[derive(Debug, Deserialize)]
struct DockerConfig {
    auths: Option<HashMap<String, DockerAuthEntry>>,
}

#[derive(Debug, Deserialize)]
struct DockerAuthEntry {
    auth: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

pub fn resolve_registry_auth(image: &str) -> Result<Option<RegistryAuth>, DockerAuthError> {
    let parsed = parse_image_reference(image)
        .map_err(|err| DockerAuthError::InvalidAuth(err.to_string()))?;
    resolve_auth_for_registry(&parsed.registry)
}

pub fn resolve_auth_for_registry(registry: &str) -> Result<Option<RegistryAuth>, DockerAuthError> {
    let config_path = docker_config_path();
    let Some(config_path) = config_path else {
        return Ok(None);
    };

    if !config_path.exists() {
        return Ok(None);
    }

    let content = fs::read_to_string(&config_path)
        .map_err(|err| DockerAuthError::Read(err.to_string()))?;
    let config: DockerConfig = serde_json::from_str(&content)
        .map_err(|err| DockerAuthError::Parse(err.to_string()))?;

    let auths = match config.auths {
        Some(auths) => auths,
        None => return Ok(None),
    };

    let target = normalize_registry_key(registry);
    for (key, entry) in auths {
        if normalize_registry_key(&key) == target {
            return decode_auth_entry(&target, &entry).map(Some);
        }
    }

    Ok(None)
}

fn decode_auth_entry(registry: &str, entry: &DockerAuthEntry) -> Result<RegistryAuth, DockerAuthError> {
    if let (Some(username), Some(password)) = (&entry.username, &entry.password) {
        return Ok(RegistryAuth {
            username: username.clone(),
            password: password.clone(),
        });
    }

    if let Some(auth) = &entry.auth {
        let decoded = STANDARD
            .decode(auth.as_bytes())
            .map_err(|_| DockerAuthError::InvalidAuth(registry.to_string()))?;
        let decoded = String::from_utf8_lossy(&decoded);
        if let Some((user, pass)) = decoded.split_once(':') {
            return Ok(RegistryAuth {
                username: user.to_string(),
                password: pass.to_string(),
            });
        }
    }

    Err(DockerAuthError::InvalidAuth(registry.to_string()))
}

fn docker_config_path() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("DOCKER_CONFIG") {
        let path = PathBuf::from(dir).join("config.json");
        return Some(path);
    }

    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".docker").join("config.json"))
}

fn normalize_registry_key(raw: &str) -> String {
    let mut key = raw.trim().to_string();
    if let Some(stripped) = key.strip_prefix("https://") {
        key = stripped.to_string();
    } else if let Some(stripped) = key.strip_prefix("http://") {
        key = stripped.to_string();
    }

    while key.ends_with('/') {
        key.pop();
    }

    if let Some(stripped) = key.strip_suffix("/v1") {
        key = stripped.to_string();
    }

    if key == "index.docker.io" {
        return "registry-1.docker.io".to_string();
    }

    key
}

#[cfg(test)]
mod tests {
    use super::{DockerAuthError, normalize_registry_key, resolve_auth_for_registry};
    use std::fs;
    use std::sync::Mutex;

    static DOCKER_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn normalizes_registry_keys() {
        assert_eq!(normalize_registry_key("https://index.docker.io/v1/"), "registry-1.docker.io");
        assert_eq!(normalize_registry_key("registry-1.docker.io"), "registry-1.docker.io");
        assert_eq!(normalize_registry_key("ghcr.io"), "ghcr.io");
    }

    #[test]
    fn resolves_auth_from_docker_config() {
        let _guard = DOCKER_ENV_LOCK.lock().expect("lock env");
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("config.json");
        fs::write(
            &config_path,
            r#"{
  "auths": {
    "https://index.docker.io/v1/": {"auth": "dXNlcjpwYXNz"},
    "ghcr.io": {"username": "writer", "password": "secret"}
  }
}"#,
        )
        .expect("write config");

        unsafe { std::env::set_var("DOCKER_CONFIG", dir.path()); }
        let auth = resolve_auth_for_registry("registry-1.docker.io")
            .expect("auth resolves")
            .expect("auth present");
        assert_eq!(auth.username, "user");
        assert_eq!(auth.password, "pass");

        let gh = resolve_auth_for_registry("ghcr.io")
            .expect("auth resolves")
            .expect("auth present");
        assert_eq!(gh.username, "writer");
        assert_eq!(gh.password, "secret");

        unsafe { std::env::remove_var("DOCKER_CONFIG"); }
    }

    #[test]
    fn returns_none_when_config_missing() {
        let _guard = DOCKER_ENV_LOCK.lock().expect("lock env");
        unsafe { std::env::set_var("DOCKER_CONFIG", "/tmp/ferrocrate-missing-config"); }
        let auth = resolve_auth_for_registry("ghcr.io").expect("ok");
        assert!(auth.is_none());
        unsafe { std::env::remove_var("DOCKER_CONFIG"); }
    }

    #[test]
    fn errors_on_invalid_auth() {
        let _guard = DOCKER_ENV_LOCK.lock().expect("lock env");
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("config.json");
        fs::write(&config_path, r#"{"auths": {"ghcr.io": {"auth": "broken"}}}"#)
            .expect("write config");
        unsafe { std::env::set_var("DOCKER_CONFIG", dir.path()); }

        let err = resolve_auth_for_registry("ghcr.io").expect_err("should error");
        match err {
            DockerAuthError::InvalidAuth(registry) => assert_eq!(registry, "ghcr.io"),
            other => panic!("unexpected error: {other:?}"),
        }

        unsafe { std::env::remove_var("DOCKER_CONFIG"); }
    }
}
