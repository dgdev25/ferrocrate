use crate::fs_atomic::write_atomic;
use crate::registry::{parse_image_reference, RegistryAuth};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use thiserror::Error;
#[cfg(target_os = "linux")]
use tracing::warn;

// SEC-02: Scoped environment variable guard for safe test environment manipulation
#[allow(dead_code)]
struct ScopedEnvVar {
    key: String,
    _old_value: Option<String>,
}

#[allow(dead_code)]
impl ScopedEnvVar {
    fn set(key: &str, value: &str) -> Self {
        let old_value = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self {
            key: key.to_string(),
            _old_value: old_value,
        }
    }
}

impl Drop for ScopedEnvVar {
    fn drop(&mut self) {
        match &self._old_value {
            Some(old) => std::env::set_var(&self.key, old),
            None => std::env::remove_var(&self.key),
        }
    }
}

#[derive(Debug, Error)]
pub enum DockerAuthError {
    #[error("failed to read docker config: {0}")]
    Read(String),
    #[error("failed to parse docker config: {0}")]
    Parse(String),
    #[error("invalid auth entry for registry {0}")]
    InvalidAuth(String),
    #[error("credential helper error: {0}")]
    Helper(String),
    #[error("credential helper timed out after {0:?}")]
    Timeout(Duration),
}

#[derive(Debug, Deserialize)]
struct DockerConfig {
    auths: Option<HashMap<String, DockerAuthEntry>>,
    #[serde(rename = "credHelpers")]
    cred_helpers: Option<HashMap<String, String>>,
    #[serde(rename = "credsStore")]
    creds_store: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DockerAuthEntry {
    auth: Option<String>,
    username: Option<String>,
    password: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FerrocrateAuthFile {
    auths: HashMap<String, FerrocrateAuthEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FerrocrateAuthEntry {
    username: String,
    password: String,
}

#[derive(Debug, Deserialize)]
struct HelperResponse {
    #[serde(rename = "Username")]
    username: String,
    #[serde(rename = "Secret")]
    secret: String,
}

pub fn resolve_registry_auth(image: &str) -> Result<Option<RegistryAuth>, DockerAuthError> {
    let parsed = parse_image_reference(image)
        .map_err(|err| DockerAuthError::InvalidAuth(err.to_string()))?;
    resolve_auth_for_registry(&parsed.registry)
}

pub fn resolve_auth_for_registry(registry: &str) -> Result<Option<RegistryAuth>, DockerAuthError> {
    if let Some(auths) = load_ferrocrate_auths()? {
        let target = normalize_registry_key(registry);
        if let Some(entry) = auths.get(&target) {
            return Ok(Some(entry.clone()));
        }
    }

    let config_path = docker_config_path();
    let Some(config_path) = config_path else {
        return Ok(None);
    };

    if !config_path.exists() {
        return Ok(None);
    }

    let content = match fs::read_to_string(&config_path) {
        Ok(content) => content,
        // Docker config files can disappear between the existence check and
        // the read (for example during an atomic config rotation). Treat that
        // race like an absent config, while preserving all other I/O errors.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(DockerAuthError::Read(error.to_string())),
    };
    let config: DockerConfig =
        serde_json::from_str(&content).map_err(|err| DockerAuthError::Parse(err.to_string()))?;

    let target = normalize_registry_key(registry);
    if let Some(helper) = resolve_helper(&config, &target) {
        if let Ok(auth) = resolve_with_helper(&helper, &target) {
            return Ok(Some(auth));
        }
    }

    let auths = match config.auths {
        Some(auths) => auths,
        None => return Ok(None),
    };

    for (key, entry) in auths {
        if normalize_registry_key(&key) == target {
            return decode_auth_entry(&target, &entry).map(Some);
        }
    }

    Ok(None)
}

pub fn export_docker_auths() -> Result<HashMap<String, RegistryAuth>, DockerAuthError> {
    let config_path = docker_config_path();
    let Some(config_path) = config_path else {
        return Ok(HashMap::new());
    };
    if !config_path.exists() {
        return Ok(HashMap::new());
    }

    let content =
        fs::read_to_string(&config_path).map_err(|err| DockerAuthError::Read(err.to_string()))?;
    let config: DockerConfig =
        serde_json::from_str(&content).map_err(|err| DockerAuthError::Parse(err.to_string()))?;

    let mut out = HashMap::new();

    if let Some(helpers) = &config.cred_helpers {
        for (key, helper) in helpers {
            let target = normalize_registry_key(key);
            if let Ok(auth) = resolve_with_helper(helper, &target) {
                out.insert(target, auth);
            }
        }
    }

    if let Some(auths) = &config.auths {
        for (key, entry) in auths {
            let target = normalize_registry_key(key);
            if out.contains_key(&target) {
                continue;
            }
            if let Ok(auth) = decode_auth_entry(&target, entry) {
                out.insert(target, auth);
            }
        }
    }

    Ok(out)
}

pub fn write_ferrocrate_auth_file(
    path: &std::path::Path,
    auths: &HashMap<String, RegistryAuth>,
) -> Result<(), DockerAuthError> {
    let mut entries = HashMap::new();
    for (registry, auth) in auths {
        entries.insert(
            registry.to_string(),
            FerrocrateAuthEntry {
                username: auth.username.clone(),
                password: auth.password.clone(),
            },
        );
    }
    let file = FerrocrateAuthFile { auths: entries };
    let bytes =
        serde_json::to_vec_pretty(&file).map_err(|err| DockerAuthError::Parse(err.to_string()))?;
    write_atomic(path, &bytes).map_err(|err| DockerAuthError::Read(err.to_string()))?;

    // Set restrictive permissions (0o600) on auth file to prevent credential exposure
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|err| DockerAuthError::Read(format!("failed to set permissions: {err}")))?;
    }

    Ok(())
}

pub fn store_registry_auth(registry: &str, auth: &RegistryAuth) -> Result<(), DockerAuthError> {
    let path = ferrocrate_auth_path()
        .ok_or_else(|| DockerAuthError::Read("credential store path is unavailable".into()))?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| DockerAuthError::Read(error.to_string()))?;
    }
    let mut auths = load_ferrocrate_auths()?.unwrap_or_default();
    auths.insert(normalize_registry_key(registry), auth.clone());
    write_ferrocrate_auth_file(&path, &auths)
}

pub fn remove_registry_auth(registry: &str) -> Result<bool, DockerAuthError> {
    let path = ferrocrate_auth_path()
        .ok_or_else(|| DockerAuthError::Read("credential store path is unavailable".into()))?;
    let mut auths = load_ferrocrate_auths()?.unwrap_or_default();
    let removed = auths.remove(&normalize_registry_key(registry)).is_some();
    if removed {
        write_ferrocrate_auth_file(&path, &auths)?;
    }
    Ok(removed)
}

pub fn ferrocrate_auth_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("FERROCRATE_AUTH_FILE") {
        return Some(PathBuf::from(path));
    }
    let home = std::env::var("HOME").ok()?;
    Some(
        PathBuf::from(home)
            .join(".ferrocrate")
            .join("registry-auth.json"),
    )
}

fn decode_auth_entry(
    registry: &str,
    entry: &DockerAuthEntry,
) -> Result<RegistryAuth, DockerAuthError> {
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

fn resolve_helper(config: &DockerConfig, registry: &str) -> Option<String> {
    if let Some(helpers) = &config.cred_helpers {
        for (key, helper) in helpers {
            if normalize_registry_key(key) == registry {
                return Some(helper.clone());
            }
        }
    }
    config.creds_store.clone()
}

// SEC-05: Default timeout for credential helpers (10 seconds)
const HELPER_TIMEOUT: Duration = Duration::from_secs(10);

fn resolve_with_helper(helper: &str, registry: &str) -> Result<RegistryAuth, DockerAuthError> {
    let helper_bin = format!("docker-credential-{helper}");
    let helper_path = resolve_helper_path(&helper_bin).ok_or_else(|| {
        DockerAuthError::Helper(format!(
            "credential helper is unavailable or not trusted: {helper_bin}"
        ))
    })?;

    // SEC-05: Execute credential helper with timeout to prevent blocking indefinitely
    let output = execute_helper_with_timeout(&helper_path, registry)?;

    if !output.status.success() {
        let msg = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(DockerAuthError::Helper(msg));
    }

    let resp: HelperResponse = serde_json::from_slice(&output.stdout)
        .map_err(|err| DockerAuthError::Helper(err.to_string()))?;
    Ok(RegistryAuth {
        username: resp.username,
        password: resp.secret,
    })
}

fn resolve_helper_path(helper_bin: &str) -> Option<PathBuf> {
    if let Ok(config_dir) = std::env::var("DOCKER_CONFIG") {
        let candidate = PathBuf::from(config_dir).join("bin").join(helper_bin);
        if trusted_helper_path(&candidate) {
            return Some(candidate);
        }
    }
    #[cfg(target_os = "linux")]
    {
        crate::rootless::trusted_executable_path(helper_bin)
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Rootless helper discovery is Linux-specific. Windows/macOS builds
        // retain the explicit untrusted-helper failure until a native helper
        // policy is implemented.
        let _ = helper_bin;
        None
    }
}

fn trusted_helper_path(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let owner_ok = if nix::unistd::geteuid().is_root() {
            metadata.uid() == 0
        } else {
            metadata.uid() == nix::unistd::geteuid().as_raw()
        };
        owner_ok
            && metadata.permissions().mode() & 0o111 != 0
            && metadata.permissions().mode() & 0o022 == 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// SEC-05: Execute credential helper with timeout to prevent blocking indefinitely
fn execute_helper_with_timeout(
    helper_bin: &Path,
    registry: &str,
) -> Result<std::process::Output, DockerAuthError> {
    let mut child = Command::new(helper_bin)
        .arg("get")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| DockerAuthError::Helper(e.to_string()))?;

    // Write registry to stdin
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        stdin
            .write_all(registry.as_bytes())
            .map_err(|e| DockerAuthError::Helper(e.to_string()))?;
        stdin
            .write_all(b"\n")
            .map_err(|e| DockerAuthError::Helper(e.to_string()))?;
    }

    // Wait for completion with timeout
    let start = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|e| DockerAuthError::Helper(e.to_string()))?
        {
            // Process completed - collect output
            let mut stdout = child
                .stdout
                .take()
                .ok_or_else(|| DockerAuthError::Helper("failed to capture stdout".to_string()))?;
            let mut stderr = child
                .stderr
                .take()
                .ok_or_else(|| DockerAuthError::Helper("failed to capture stderr".to_string()))?;

            let mut stdout_buf = Vec::new();
            let mut stderr_buf = Vec::new();
            stdout
                .read_to_end(&mut stdout_buf)
                .map_err(|e| DockerAuthError::Helper(e.to_string()))?;
            stderr
                .read_to_end(&mut stderr_buf)
                .map_err(|e| DockerAuthError::Helper(e.to_string()))?;

            return Ok(std::process::Output {
                status,
                stdout: stdout_buf,
                stderr: stderr_buf,
            });
        }

        if start.elapsed() >= HELPER_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(DockerAuthError::Timeout(HELPER_TIMEOUT));
        }

        std::thread::sleep(Duration::from_millis(10));
    }
}

fn docker_config_path() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("DOCKER_CONFIG") {
        let path = PathBuf::from(dir).join("config.json");
        return Some(path);
    }

    let home = std::env::var("HOME").ok()?;
    Some(PathBuf::from(home).join(".docker").join("config.json"))
}

fn load_ferrocrate_auths() -> Result<Option<HashMap<String, RegistryAuth>>, DockerAuthError> {
    let Some(path) = ferrocrate_auth_path() else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }

    // Warn if auth file has overly permissive permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(metadata) = fs::metadata(&path) {
            let mode = metadata.permissions().mode();
            if mode & 0o077 != 0 {
                warn!(
                    path = %path.display(),
                    mode = format!("{:o}", mode & 0o777),
                    "auth file has overly permissive mode, run: chmod 600 {}",
                    path.display()
                );
            }
        }
    }

    let content = match fs::read_to_string(&path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(DockerAuthError::Read(error.to_string())),
    };
    let file: FerrocrateAuthFile =
        serde_json::from_str(&content).map_err(|err| DockerAuthError::Parse(err.to_string()))?;
    let mut out = HashMap::new();
    for (registry, entry) in file.auths {
        out.insert(
            normalize_registry_key(&registry),
            RegistryAuth {
                username: entry.username,
                password: entry.password,
            },
        );
    }
    Ok(Some(out))
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
    use super::{
        normalize_registry_key, remove_registry_auth, resolve_auth_for_registry,
        store_registry_auth, trusted_helper_path, DockerAuthError, ScopedEnvVar,
    };
    use crate::registry::RegistryAuth;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    static DOCKER_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn normalizes_registry_keys() {
        assert_eq!(
            normalize_registry_key("https://index.docker.io/v1/"),
            "registry-1.docker.io"
        );
        assert_eq!(
            normalize_registry_key("registry-1.docker.io"),
            "registry-1.docker.io"
        );
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

        let _config_guard =
            ScopedEnvVar::set("DOCKER_CONFIG", dir.path().to_str().expect("valid path"));
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
    }

    #[test]
    fn resolves_auth_for_custom_registry() {
        let _guard = DOCKER_ENV_LOCK.lock().expect("lock env");
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("config.json");
        fs::write(
            &config_path,
            r#"{
  "auths": {
    "registry.example.com": {"username": "alice", "password": "token123"}
  }
}"#,
        )
        .expect("write config");

        let _config_guard =
            ScopedEnvVar::set("DOCKER_CONFIG", dir.path().to_str().expect("valid path"));
        let auth = resolve_auth_for_registry("registry.example.com")
            .expect("auth resolves")
            .expect("auth present");
        assert_eq!(auth.username, "alice");
        assert_eq!(auth.password, "token123");
    }

    #[test]
    fn resolves_auth_from_helper() {
        let _guard = DOCKER_ENV_LOCK.lock().expect("lock env");
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("config.json");
        fs::write(
            &config_path,
            r#"{
  "credHelpers": {
    "ghcr.io": "test"
  }
}"#,
        )
        .expect("write config");

        let bin_dir = dir.path().join("bin");
        fs::create_dir_all(&bin_dir).expect("bin dir");
        let helper_path = bin_dir.join("docker-credential-test");
        fs::write(
            &helper_path,
            "#!/bin/sh\ncat >/dev/null\nprintf '{\"Username\":\"helper\",\"Secret\":\"token\"}'\n",
        )
        .expect("write helper");
        let mut perms = fs::metadata(&helper_path).expect("metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&helper_path, perms).expect("chmod");

        let old_path = std::env::var("PATH").unwrap_or_default();
        let new_path = format!("{}:{}", bin_dir.display(), old_path);

        // SEC-02: Use scoped environment guards for proper cleanup even on panic
        let _path_guard = ScopedEnvVar::set("PATH", &new_path);
        let _config_guard =
            ScopedEnvVar::set("DOCKER_CONFIG", dir.path().to_str().expect("valid path"));

        let auth = resolve_auth_for_registry("ghcr.io")
            .expect("auth resolves")
            .expect("auth present");
        assert_eq!(auth.username, "helper");
        assert_eq!(auth.password, "token");
    }

    #[test]
    fn rejects_group_writable_credential_helper() {
        let dir = tempfile::tempdir().expect("tempdir");
        let helper_path = dir.path().join("docker-credential-test");
        fs::write(&helper_path, "#!/bin/sh\n").expect("write helper");
        let mut perms = fs::metadata(&helper_path).expect("metadata").permissions();
        perms.set_mode(0o777);
        fs::set_permissions(&helper_path, perms).expect("chmod");
        assert!(!trusted_helper_path(&helper_path));
    }

    #[test]
    fn returns_none_when_config_missing() {
        let _guard = DOCKER_ENV_LOCK.lock().expect("lock env");
        let _config_guard = ScopedEnvVar::set("DOCKER_CONFIG", "/tmp/ferrocrate-missing-config");
        let auth = resolve_auth_for_registry("ghcr.io").expect("ok");
        assert!(auth.is_none());
    }

    #[test]
    fn errors_on_invalid_auth() {
        let _guard = DOCKER_ENV_LOCK.lock().expect("lock env");
        let dir = tempfile::tempdir().expect("tempdir");
        let config_path = dir.path().join("config.json");
        fs::write(
            &config_path,
            r#"{"auths": {"ghcr.io": {"auth": "broken"}}}"#,
        )
        .expect("write config");
        let _config_guard =
            ScopedEnvVar::set("DOCKER_CONFIG", dir.path().to_str().expect("valid path"));

        let err = resolve_auth_for_registry("ghcr.io").expect_err("should error");
        match err {
            DockerAuthError::InvalidAuth(registry) => assert_eq!(registry, "ghcr.io"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn login_and_logout_update_the_ferrocrate_credential_store() {
        let _guard = DOCKER_ENV_LOCK.lock().expect("lock env");
        let dir = tempfile::tempdir().expect("tempdir");
        let auth_path = dir.path().join("registry-auth.json");
        let _auth_guard = ScopedEnvVar::set(
            "FERROCRATE_AUTH_FILE",
            auth_path.to_str().expect("auth path"),
        );

        store_registry_auth(
            "https://index.docker.io/v1/",
            &RegistryAuth {
                username: "alice".to_string(),
                password: "secret".to_string(),
            },
        )
        .expect("store login");
        let stored = resolve_auth_for_registry("registry-1.docker.io")
            .expect("resolve")
            .expect("stored auth");
        assert_eq!(stored.username, "alice");
        assert_eq!(stored.password, "secret");

        assert!(remove_registry_auth("registry-1.docker.io").expect("remove login"));
        assert!(resolve_auth_for_registry("registry-1.docker.io")
            .expect("resolve after logout")
            .is_none());
        assert!(!remove_registry_auth("registry-1.docker.io").expect("idempotent logout"));
    }
}
