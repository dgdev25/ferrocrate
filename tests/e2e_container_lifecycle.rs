//! E2E Tests for complete container lifecycle.
//!
//! Tests full workflows from pull to cleanup.

use std::process::Command;
use std::time::Duration;

/// Helper to run ferro-cli
fn ferro_cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
}

/// Check if test should run (requires rootless container support)
fn should_run() -> bool {
    std::env::var("FERROCRATE_RUNTIME_DIR").is_ok() || cfg!(target_os = "linux")
}

/// Helper to wait for container state
fn wait_for_container(container_id: &str, state: &str, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        let output = ferro_cli()
            .args(["ps", "--filter", &format!("id={}", container_id), "--format", "{{.Status}}"])
            .output()
            .ok();

        if let Some(output) = output {
            let status = String::from_utf8_lossy(&output.stdout);
            if status.to_lowercase().contains(state) {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "Requires container runtime"]
    fn pull_build_run_stop_remove_full_cycle() {
        if !should_run() {
            eprintln!("Skipping: container runtime not available");
            return;
        }

        // Create temp directory
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let runtime_dir = tempfile::tempdir().expect("runtime dir");

        // Step 1: Build from Dockerfile
        let dockerfile = r#"FROM alpine:3.19
RUN echo "Hello from FerroCrate" > /hello.txt
CMD ["cat", "/hello.txt"]
"#;
        std::fs::write(temp_dir.path().join("Dockerfile"), dockerfile).expect("write dockerfile");

        let build_output = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .current_dir(temp_dir.path())
            .args(["build", "--dockerfile", "Dockerfile", "--tag", "test/cycle:latest"])
            .output()
            .expect("build");

        assert!(build_output.status.success(), "Build should succeed: {}",
            String::from_utf8_lossy(&build_output.stderr));

        // Step 2: List images - should contain our image
        let images_output = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args(["images", "--format", "{{.Repository}}"])
            .output()
            .expect("images list");

        let images = String::from_utf8_lossy(&images_output.stdout);
        assert!(images.contains("test/cycle"), "Image should be listed");

        // Step 3: Run container
        let run_output = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args(["run", "--rm", "test/cycle:latest"])
            .output()
            .expect("run");

        let run_stdout = String::from_utf8_lossy(&run_output.stdout);
        assert!(run_stdout.contains("Hello from FerroCrate"), "Should see output");

        // Step 4: Verify cleanup (--rm should remove container)
        let ps_output = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args(["ps", "-a"])
            .output()
            .expect("ps");

        let containers = String::from_utf8_lossy(&ps_output.stdout);
        assert!(!containers.contains("test/cycle"), "Container should be removed");
    }

    #[test]
    #[ignore = "Requires container runtime"]
    fn container_restart_preserves_state() {
        if !should_run() {
            eprintln!("Skipping: container runtime not available");
            return;
        }

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let runtime_dir = tempfile::tempdir().expect("runtime dir");

        // Create container with persistent volume
        let run_output = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args([
                "run", "-d",
                "--name", "restart-test",
                "-v", &format!("{}:/data", temp_dir.path().display()),
                "alpine:3.19",
                "sh", "-c", "echo 'persistent' > /data/test.txt && sleep 60"
            ])
            .output()
            .expect("run");

        assert!(run_output.status.success(), "Container should start");

        // Wait for container to be running
        std::thread::sleep(Duration::from_secs(2));

        // Stop container
        let stop_output = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args(["stop", "restart-test"])
            .output()
            .expect("stop");

        assert!(stop_output.status.success(), "Container should stop");

        // Start container again
        let start_output = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args(["start", "restart-test"])
            .output()
            .expect("start");

        assert!(start_output.status.success(), "Container should restart");

        // Verify persistent data
        let exec_output = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args(["exec", "restart-test", "cat", "/data/test.txt"])
            .output()
            .expect("exec");

        let content = String::from_utf8_lossy(&exec_output.stdout);
        assert!(content.contains("persistent"), "Data should persist across restarts");

        // Cleanup
        let _ = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args(["rm", "-f", "restart-test"])
            .output();
    }

    #[test]
    #[ignore = "Requires container runtime"]
    fn container_commit_creates_new_image() {
        if !should_run() {
            eprintln!("Skipping: container runtime not available");
            return;
        }

        let runtime_dir = tempfile::tempdir().expect("runtime dir");

        // Run container and make changes
        let run_output = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args([
                "run", "-d",
                "--name", "commit-test",
                "alpine:3.19",
                "sh", "-c", "echo 'modified' > /modified.txt && sleep 60"
            ])
            .output()
            .expect("run");

        assert!(run_output.status.success(), "Container should start");
        std::thread::sleep(Duration::from_secs(2));

        // Commit to new image
        let commit_output = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args(["commit", "commit-test", "test/committed:v1"])
            .output()
            .expect("commit");

        assert!(commit_output.status.success(), "Commit should succeed");

        // Verify new image exists
        let images_output = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args(["images", "--format", "{{.Repository}}:{{.Tag}}"])
            .output()
            .expect("images");

        let images = String::from_utf8_lossy(&images_output.stdout);
        assert!(images.contains("test/committed:v1"), "Committed image should exist");

        // Cleanup
        let _ = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args(["rm", "-f", "commit-test"])
            .output();
        let _ = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args(["rmi", "test/committed:v1"])
            .output();
    }
}
