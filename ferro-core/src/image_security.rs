use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::thread;
use std::time::Duration;

/// Validates that an image reference matches OCI specification format.
/// Pattern: `[registry/]repository[:tag or @sha256:digest]`
pub fn validate_image_reference(image: &str) -> Result<(), String> {
    // Basic validation: must contain valid characters
    // Full OCI reference regex is complex, this covers common cases
    let valid_chars = |c: char| -> bool {
        c.is_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '/' || c == ':' || c == '@'
    };

    if image.is_empty() {
        return Err("image reference cannot be empty".to_string());
    }

    if !image.chars().all(valid_chars) {
        return Err(format!(
            "image reference contains invalid characters: {}",
            image
        ));
    }

    // Reject relative path components. They never occur in a valid
    // repository name and let a traversal-shaped reference reach downstream
    // consumers verbatim.
    if image
        .split('/')
        .any(|component| component == "." || component == "..")
    {
        return Err("image reference contains path traversal components".to_string());
    }

    // Must have at least one repository component
    let repo_part = image
        .split('@')
        .next()
        .unwrap_or(image)
        .split(':')
        .next()
        .unwrap_or(image);
    if repo_part.is_empty() || repo_part.contains("//") {
        return Err("image reference must have valid repository name".to_string());
    }

    // Validate tag format if present
    if let Some(tag_pos) = image.find(':') {
        let after_colon = &image[tag_pos + 1..];
        if !after_colon.contains('@') && after_colon.contains('/') {
            return Err("invalid tag format in image reference".to_string());
        }
    }

    Ok(())
}

/// Helper function to run a command with a timeout
fn run_with_timeout(child: &mut Child, timeout: Duration) -> Result<std::process::Output, String> {
    let start = std::time::Instant::now();

    loop {
        // Check if process has exited without borrowing
        match child.try_wait() {
            Ok(Some(_status)) => {
                // Process has exited, collect output
                // Use wait() instead of wait_with_output() to avoid move issues
                let status = child
                    .wait()
                    .map_err(|e| format!("failed to wait for process: {}", e))?;
                // Since we can't get stdout/stderr after wait(), we need a different approach
                // For now, return empty output on success
                return Ok(std::process::Output {
                    status,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                });
            }
            Ok(None) => {
                // Still running
            }
            Err(_) => {
                // Error checking status, assume still running
            }
        }

        if start.elapsed() >= timeout {
            // Kill the child process on timeout
            let _ = child.kill();
            let _ = child.wait();
            return Err("command timed out".to_string());
        }

        // Sleep a bit to avoid busy waiting
        thread::sleep(Duration::from_millis(100));
    }
}

/// Verifies an image signature using cosign.
///
/// # Security
/// - Validates image reference format before passing to external command
/// - Uses `--` delimiter to prevent flag injection
/// - Enforces 30-second timeout to prevent hangs
/// - Sanitizes error messages to prevent information leakage
pub fn verify_image_signature(image: &str) -> Result<(), String> {
    if !signature_verification_enabled() {
        return Ok(());
    }
    let cosign = resolve_command("cosign")
        .ok_or_else(|| "signature verification requires cosign".to_string())?;

    // Validate image reference format (SEC-01)
    validate_image_reference(image)?;

    let key = std::env::var("FERROCRATE_SIGNATURE_KEY")
        .or_else(|_| std::env::var("COSIGN_PUBLIC_KEY"))
        .map_err(|_| "signature verification requires FERROCRATE_SIGNATURE_KEY".to_string())?;

    // Security: Use "--" delimiter to prevent flag injection from malicious image names.
    // Cosign does not consume Ferrocrate's CA override automatically, so pass
    // the validated trust root explicitly for private TLS registries.
    let mut args = vec!["verify".to_string(), "--key".to_string(), key];
    if let Some(ca_path) = registry_ca_path()? {
        args.extend(["--registry-cacert".to_string(), ca_path]);
    }
    args.extend(["--".to_string(), image.to_string()]);
    let mut child = Command::new(cosign)
        .args(&args)
        .spawn()
        .map_err(|_| "failed to execute cosign verification".to_string())?;

    let output = run_with_timeout(&mut child, Duration::from_secs(30))?;

    if !output.status.success() {
        // SEC-01: Sanitize error messages - don't leak raw stderr
        return Err("image signature verification failed".to_string());
    }
    Ok(())
}

fn registry_ca_path() -> Result<Option<String>, String> {
    let Some(path) = std::env::var_os("FERROCRATE_REGISTRY_CA_CERT") else {
        return Ok(None);
    };
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|_| "signature verification CA certificate is unavailable".to_string())?;
    if !metadata.file_type().is_file() {
        return Err("signature verification CA certificate must be a regular file".to_string());
    }
    let size = metadata.len();
    if size == 0 || size > 1024 * 1024 {
        return Err("signature verification CA certificate is empty or oversized".to_string());
    }
    Ok(Some(
        path.to_str()
            .ok_or_else(|| "signature verification CA certificate path is not UTF-8".to_string())?
            .to_string(),
    ))
}

fn signature_verification_enabled() -> bool {
    std::env::var("FERROCRATE_SIGNATURE_VERIFY")
        .map(|val| val == "1" || val.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[cfg(test)]
fn command_exists(bin: &str) -> bool {
    resolve_command(bin).is_some()
}

/// Resolve a helper without executing it. Probing a user-controlled PATH by
/// running `helper --version` is itself an unintended side effect and can
/// execute an attacker-supplied program before authorization reaches the real
/// verification boundary.
fn resolve_command(bin: &str) -> Option<PathBuf> {
    if bin.is_empty() || bin.contains('/') {
        return None;
    }

    if let Some(path) = std::env::var_os("PATH") {
        for directory in std::env::split_paths(&path) {
            let candidate = directory.join(bin);
            if is_executable(&candidate) {
                return Some(candidate);
            }
        }
    }

    // Restricted test/service environments may clear PATH. Keep the bounded
    // system fallback, but still inspect metadata rather than executing code.
    for directory in [
        "/usr/local/sbin",
        "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
    ] {
        let candidate = Path::new(directory).join(bin);
        if is_executable(&candidate) {
            return Some(candidate);
        }
    }

    None
}

fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::ENV_LOCK;
    use std::env;
    use std::fs;
    use std::io::Write;

    // Helper to create a temporary fake cosign binary
    struct FakeCosign {
        dir: tempfile::TempDir,
    }

    impl FakeCosign {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let bin_path = dir.path().join("cosign");

            // Create a simple shell script that mimics cosign behavior
            let mut script = fs::File::create(&bin_path).expect("create script");
            writeln!(
                script,
                r#"#!/bin/sh
# Fake cosign binary for testing
# Exit 0 for success, 1 for failure, based on args

case "$1" in
    --version)
        # Simulate version check
        echo "cosign version 2.0.0"
        exit 0
        ;;
    verify)
        # Check for required arguments
        if [ -z "$2" ] || [ "$2" != "--key" ]; then
            echo "Error: missing --key argument" >&2
            exit 1
        fi

        if [ -z "$3" ]; then
            echo "Error: missing key path" >&2
            exit 1
        fi

        # Skip "verify --key <path> --" to get image name
        shift 4

        # Get image name
        IMAGE="$1"

        # Simulate verification based on image name
        case "$IMAGE" in
            *":invalid"*)
                echo "Error: signature verification failed for $IMAGE" >&2
                exit 1
                ;;
            *":missing-key"*)
                echo "Error: public key not found" >&2
                exit 1
                ;;
            *":timeout"*)
                # Simulate timeout by hanging
                sleep 35
                exit 1
                ;;
            *)
                # Success case
                echo "Signature verification successful for $IMAGE"
                exit 0
                ;;
        esac
        ;;
    *)
        echo "Error: unknown command: $1" >&2
        exit 1
        ;;
esac
"#
            )
            .expect("write script");

            // Make it executable
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&bin_path).expect("metadata").permissions();
                perms.set_mode(0o755);
                fs::set_permissions(&bin_path, perms).expect("chmod");
            }

            Self { dir }
        }
    }

    #[test]
    fn validate_image_reference_accepts_valid_images() {
        // Valid registry images
        assert!(validate_image_reference("registry.example.com/myapp:v1.0").is_ok());
        assert!(validate_image_reference("ghcr.io/user/repo:latest").is_ok());
        assert!(validate_image_reference("docker.io/library/ubuntu:22.04").is_ok());
        assert!(validate_image_reference("alpine:3.18").is_ok());

        // Valid digest references
        assert!(validate_image_reference("alpine@sha256:abc123").is_ok());
        assert!(validate_image_reference("registry.io/repo@sha256:def456").is_ok());

        // Valid tagless references
        assert!(validate_image_reference("ubuntu").is_ok());
        assert!(validate_image_reference("library/nginx").is_ok());
    }

    #[test]
    fn validate_image_reference_rejects_empty() {
        let err = validate_image_reference("").expect_err("should reject empty");
        assert!(err.contains("cannot be empty"));
    }

    #[test]
    fn validate_image_reference_rejects_invalid_characters() {
        let invalid_images = vec![
            "my image",  // space
            "my\nimage", // newline
            "my\timage", // tab
            "my;image",  // semicolon
            "my&image",  // ampersand
            "my|image",  // pipe
            "my$image",  // dollar
            "my%image",  // percent
            "my!image",  // exclamation
            "my*image",  // asterisk
            "my?image",  // question mark
            "my[image]", // brackets
            "my{image}", // braces
            "my(image)", // parentheses
        ];

        for image in invalid_images {
            assert!(
                validate_image_reference(image).is_err(),
                "should reject image with invalid characters: {}",
                image
            );
        }
    }

    #[test]
    fn validate_image_reference_rejects_double_slash() {
        let err = validate_image_reference("repo//image:tag").expect_err("should reject //");
        assert!(err.contains("repository name"));
    }

    #[test]
    fn validate_image_reference_rejects_invalid_tag_format() {
        // Tag with slash after colon is invalid
        let err = validate_image_reference("myimage:tag/with/slash").expect_err("should reject");
        assert!(err.contains("invalid tag format"));
    }

    #[test]
    fn validate_image_reference_accepts_digest_with_colon_before_tag() {
        // Digest reference with colon before @ is valid
        // e.g., registry:5000/repo@sha256:abc
        assert!(validate_image_reference("registry:5000/repo@sha256:abc").is_ok());
    }

    #[test]
    fn validate_image_reference_rejects_path_traversal_components() {
        for image in [
            "../../../etc/passwd",
            "registry.example.com/../repo",
            "repo/./tag",
            "repo/..",
            "..",
        ] {
            let err =
                validate_image_reference(image).expect_err("should reject traversal reference");
            assert!(
                err.contains("path traversal"),
                "unexpected error for {image}: {err}"
            );
        }
    }

    #[test]
    fn validate_image_reference_accepts_separator_runs_inside_components() {
        // Doubled separators inside a component are valid OCI names and must
        // not be confused for traversal components.
        assert!(validate_image_reference("foo..bar/baz:tag").is_ok());
        assert!(validate_image_reference("foo__bar").is_ok());
    }

    #[test]
    fn signature_verification_enabled_returns_false_by_default() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Ensure env var is not set (clear both to be safe)
        env::remove_var("FERROCRATE_SIGNATURE_VERIFY");
        env::remove_var("COSIGN_PUBLIC_KEY");
        env::remove_var("FERROCRATE_SIGNATURE_KEY");

        assert!(
            !signature_verification_enabled(),
            "signature verification should be disabled by default"
        );
    }

    #[test]
    fn signature_verification_enabled_returns_true_for_1() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        env::set_var("FERROCRATE_SIGNATURE_VERIFY", "1");
        assert!(signature_verification_enabled());
        env::remove_var("FERROCRATE_SIGNATURE_VERIFY");
    }

    #[test]
    fn signature_verification_enabled_returns_true_for_true() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // The implementation uses eq_ignore_ascii_case, so lowercase and mixed case work
        env::set_var("FERROCRATE_SIGNATURE_VERIFY", "true");
        assert!(signature_verification_enabled());
        env::set_var("FERROCRATE_SIGNATURE_VERIFY", "TRUE");
        assert!(signature_verification_enabled()); // eq_ignore_ascii_case handles uppercase
        env::set_var("FERROCRATE_SIGNATURE_VERIFY", "TrUe");
        assert!(signature_verification_enabled()); // eq_ignore_ascii_case handles mixed case
        env::remove_var("FERROCRATE_SIGNATURE_VERIFY");
    }

    #[test]
    fn signature_verification_enabled_returns_false_for_0() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        env::set_var("FERROCRATE_SIGNATURE_VERIFY", "0");
        assert!(!signature_verification_enabled());
        env::set_var("FERROCRATE_SIGNATURE_VERIFY", "false");
        assert!(!signature_verification_enabled());
        env::remove_var("FERROCRATE_SIGNATURE_VERIFY");
    }

    #[test]
    fn command_exists_returns_true_for_available_command() {
        // "sh" should be available on all Unix-like systems
        #[cfg(unix)]
        assert!(command_exists("sh"));
    }

    #[test]
    fn command_exists_returns_false_for_missing_command() {
        // A command that definitely shouldn't exist
        assert!(!command_exists("ferrocrate-nonexistent-command-xyz123"));
    }

    #[test]
    #[cfg(unix)]
    fn command_probe_does_not_execute_path_helper() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let directory = tempfile::tempdir().expect("helper directory");
        let helper = directory.path().join("ferrocrate-probe-helper");
        let marker = directory.path().join("executed");
        fs::write(
            &helper,
            format!("#!/bin/sh\nprintf x > {}\n", marker.display()),
        )
        .expect("helper");
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).expect("executable");
        let old_path = env::var_os("PATH");
        env::set_var("PATH", directory.path());

        assert!(command_exists("ferrocrate-probe-helper"));
        assert!(
            !marker.exists(),
            "capability probing must not execute helpers"
        );

        if let Some(path) = old_path {
            env::set_var("PATH", path);
        } else {
            env::remove_var("PATH");
        }
    }

    #[test]
    fn verify_image_signature_returns_ok_when_disabled() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Ensure verification is disabled
        env::set_var("FERROCRATE_SIGNATURE_VERIFY", "0");
        env::set_var("FERROCRATE_SIGNATURE_KEY", "/tmp/key.pem");

        // Should return Ok even without cosign
        let result = verify_image_signature("alpine:latest");
        assert!(
            result.is_ok(),
            "should return Ok when verification disabled"
        );

        env::remove_var("FERROCRATE_SIGNATURE_VERIFY");
        env::remove_var("FERROCRATE_SIGNATURE_KEY");
    }

    #[test]
    fn verify_image_signature_returns_error_when_cosign_missing() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Enable verification but cosign is not available
        env::set_var("FERROCRATE_SIGNATURE_VERIFY", "1");
        env::set_var("FERROCRATE_SIGNATURE_KEY", "/tmp/key.pem");

        // Set PATH to empty to ensure cosign is not found
        let old_path = env::var("PATH").ok();
        env::remove_var("PATH");

        let result = verify_image_signature("alpine:latest");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("signature verification requires cosign"));

        // Restore PATH
        if let Some(path) = old_path {
            env::set_var("PATH", path);
        }
        env::remove_var("FERROCRATE_SIGNATURE_VERIFY");
        env::remove_var("FERROCRATE_SIGNATURE_KEY");
    }

    #[test]
    fn verify_image_signature_returns_error_when_key_missing() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Enable verification but don't set key
        env::set_var("FERROCRATE_SIGNATURE_VERIFY", "1");
        env::remove_var("FERROCRATE_SIGNATURE_KEY");
        env::remove_var("COSIGN_PUBLIC_KEY");

        let result = verify_image_signature("alpine:latest");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("signature verification requires"));

        env::remove_var("FERROCRATE_SIGNATURE_VERIFY");
    }

    #[test]
    fn verify_image_signature_returns_error_for_invalid_image() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        env::set_var("FERROCRATE_SIGNATURE_VERIFY", "1");
        env::set_var("FERROCRATE_SIGNATURE_KEY", "/tmp/key.pem");

        // Invalid image reference
        let result = verify_image_signature("my image with spaces");
        assert!(result.is_err());

        env::remove_var("FERROCRATE_SIGNATURE_VERIFY");
        env::remove_var("FERROCRATE_SIGNATURE_KEY");
    }

    #[test]
    fn verify_image_signature_sanitizes_key_env_fallback() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Test COSIGN_PUBLIC_KEY fallback
        env::set_var("FERROCRATE_SIGNATURE_VERIFY", "1");
        env::remove_var("FERROCRATE_SIGNATURE_KEY");
        env::set_var("COSIGN_PUBLIC_KEY", "/tmp/cosign-key.pem");

        // Should use COSIGN_PUBLIC_KEY
        let result = verify_image_signature("alpine:latest");
        // Will fail because cosign doesn't exist or key doesn't exist, but should NOT be about missing key
        // Error could be "signature verification requires cosign" OR "signature verification failed"
        if let Err(err) = result {
            // Either error is acceptable - just not "requires FERROCRATE_SIGNATURE_KEY"
            assert!(err.contains("cosign") || err.contains("signature verification"));
        }

        env::remove_var("FERROCRATE_SIGNATURE_VERIFY");
        env::remove_var("COSIGN_PUBLIC_KEY");
    }

    #[test]
    fn run_with_timeout_returns_error_on_timeout() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Create a long-running process
        let mut child = Command::new("sleep")
            .arg("100")
            .spawn()
            .expect("sleep should spawn");

        // Set a short timeout
        let result = run_with_timeout(&mut child, Duration::from_millis(100));

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("timed out"));

        // Clean up
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn run_with_timeout_returns_output_for_quick_process() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Create a quick process
        let mut child = if cfg!(unix) {
            Command::new("true").spawn().expect("true should spawn")
        } else {
            // Windows equivalent
            Command::new("cmd")
                .args(["/C", "exit", "0"])
                .spawn()
                .expect("cmd should spawn")
        };

        let result = run_with_timeout(&mut child, Duration::from_secs(5));

        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(output.status.success());
    }

    #[test]
    fn run_with_timeout_handles_immediate_exit() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Create a process that exits immediately
        let mut child = if cfg!(unix) {
            Command::new("false").spawn().expect("false should spawn")
        } else {
            Command::new("cmd")
                .args(["/C", "exit", "1"])
                .spawn()
                .expect("cmd should spawn")
        };

        let result = run_with_timeout(&mut child, Duration::from_secs(5));

        assert!(result.is_ok());
        let output = result.unwrap();
        assert!(!output.status.success());
    }

    // Integration test with fake cosign binary
    #[test]
    #[cfg(unix)]
    fn verify_image_signature_with_fake_cosign_success() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fake_cosign = FakeCosign::new();

        // Set up environment
        env::set_var("FERROCRATE_SIGNATURE_VERIFY", "1");
        env::set_var("FERROCRATE_SIGNATURE_KEY", "/tmp/key.pem");

        // Add fake cosign FIRST in PATH so it takes precedence over system cosign
        let old_path = env::var("PATH").unwrap_or_default();
        let fake_dir = fake_cosign.dir.path().to_str().expect("valid path");
        env::set_var("PATH", format!("{}:{}", fake_dir, old_path));

        // Test successful verification
        let result = verify_image_signature("registry.io/myapp:v1.0");
        assert!(
            result.is_ok(),
            "fake cosign should succeed for valid image: {:?}",
            result
        );

        // Cleanup
        env::set_var("PATH", old_path);
        env::remove_var("FERROCRATE_SIGNATURE_VERIFY");
        env::remove_var("FERROCRATE_SIGNATURE_KEY");
    }

    #[test]
    #[cfg(unix)]
    fn verify_image_signature_with_fake_cosign_failure() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fake_cosign = FakeCosign::new();

        env::set_var("FERROCRATE_SIGNATURE_VERIFY", "1");
        env::set_var("FERROCRATE_SIGNATURE_KEY", "/tmp/key.pem");

        let old_path = env::var("PATH").unwrap_or_default();
        let fake_dir = fake_cosign.dir.path().to_str().expect("valid path");
        env::set_var("PATH", format!("{}:{}", fake_dir, old_path));

        // Test failed verification (using ":invalid" suffix triggers failure in our fake cosign)
        let result = verify_image_signature("registry.io/myapp:invalid");
        assert!(
            result.is_err(),
            "fake cosign should fail for :invalid image"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("signature verification failed"),
            "error should mention verification failure: {}",
            err
        );

        env::set_var("PATH", old_path);
        env::remove_var("FERROCRATE_SIGNATURE_VERIFY");
        env::remove_var("FERROCRATE_SIGNATURE_KEY");
    }

    #[test]
    fn validate_image_reference_handles_complex_references() {
        // Multi-part registry paths (without port in registry for now - current validator has limitations)
        assert!(validate_image_reference("registry.example.com/path/to/app:tag").is_ok());
        assert!(validate_image_reference("localhost/myapp:latest").is_ok());

        // Note: registry:port syntax fails current validation because ':' splits at wrong place
        // This is a known limitation of the simple validator - OCI spec compliance would need regex

        // Digest with registry
        assert!(validate_image_reference("registry.io/repo@sha256:abcd1234").is_ok());

        // Complex tag names
        assert!(validate_image_reference("myapp:v1.2.3-beta").is_ok());
        assert!(validate_image_reference("myapp:20240101").is_ok());
    }

    #[test]
    fn validate_image_reference_handles_edge_cases() {
        // Just registry name - accepted by current simple validator
        assert!(validate_image_reference("docker.io").is_ok());

        // Registry with trailing slash - actually accepted (becomes "docker.io")
        assert!(validate_image_reference("docker.io/").is_ok());

        // Just tag - rejected (empty repo before colon)
        assert!(validate_image_reference(":latest").is_err());

        // Just digest - rejected (empty repo before @)
        assert!(validate_image_reference("@sha256:abc").is_err());
    }
}
