//! E2E Tests for complete container lifecycle.
//!
//! Tests full workflows from pull to cleanup.

use std::net::TcpListener;
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

fn reserve_dynamic_host_port() -> std::io::Result<(TcpListener, u16)> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    Ok((listener, port))
}

fn response_provenance_token() -> String {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("ferrocrate-ebpf-{}-{nonce}", std::process::id())
}

fn normalize_netfilter_snapshot(snapshot: &str) -> String {
    snapshot
        .lines()
        .map(|line| {
            let line = line.trim();
            let line = if line.starts_with('[') {
                line.split_once("] ").map(|(_, rest)| rest).unwrap_or(line)
            } else {
                line
            };
            let line = line.split(" # handle ").next().unwrap_or(line);
            let tokens = line.split_whitespace().collect::<Vec<_>>();
            let mut normalized = Vec::new();
            let mut index = 0;
            while index < tokens.len() {
                if tokens[index] == "counter"
                    && tokens.get(index + 1) == Some(&"packets")
                    && tokens.get(index + 3) == Some(&"bytes")
                {
                    normalized.push("counter");
                    index += 5;
                } else {
                    normalized.push(tokens[index]);
                    index += 1;
                }
            }
            normalized.join(" ")
        })
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Helper to wait for container state
#[allow(dead_code)]
fn wait_for_container(container_id: &str, state: &str, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < timeout {
        let output = ferro_cli()
            .args([
                "ps",
                "--filter",
                &format!("id={}", container_id),
                "--format",
                "{{.Status}}",
            ])
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

    fn netfilter_snapshot() -> (String, String) {
        let iptables = Command::new("iptables-save")
            .output()
            .expect("iptables-save must be present for the eBPF lane");
        assert!(iptables.status.success(), "iptables-save must succeed");
        let nftables = Command::new("nft")
            .args(["list", "ruleset"])
            .output()
            .expect("nft must be present for the eBPF lane");
        assert!(nftables.status.success(), "nft list ruleset must succeed");
        (
            normalize_netfilter_snapshot(&String::from_utf8_lossy(&iptables.stdout)),
            normalize_netfilter_snapshot(&String::from_utf8_lossy(&nftables.stdout)),
        )
    }

    #[test]
    fn network_backend_snapshot_normalization_keeps_all_rule_changes() {
        let before = "[1:2] -A POSTROUTING -j MASQUERADE\n-A OUTPUT -p tcp --dport 45001 -j DNAT\nfc_one # handle 7\n";
        let counters_only = "[9:8] -A POSTROUTING -j MASQUERADE\n-A OUTPUT -p tcp --dport 45001 -j DNAT\nfc_one # handle 99\n";
        let added = "[9:8] -A POSTROUTING -j MASQUERADE\n-A OUTPUT -p tcp --dport 45001 -j DNAT\nfc_one # handle 99\nfc_two\n";
        let deleted = "[9:8] -A POSTROUTING -j MASQUERADE\nfc_one # handle 99\n";
        assert_eq!(
            normalize_netfilter_snapshot(before),
            "-A POSTROUTING -j MASQUERADE\n-A OUTPUT -p tcp --dport 45001 -j DNAT\nfc_one"
        );
        assert_eq!(
            normalize_netfilter_snapshot(before),
            normalize_netfilter_snapshot(counters_only)
        );
        assert_ne!(
            normalize_netfilter_snapshot(before),
            normalize_netfilter_snapshot(added)
        );
        assert_ne!(
            normalize_netfilter_snapshot(before),
            normalize_netfilter_snapshot(deleted)
        );
    }

    #[test]
    fn network_backend_dynamic_port_and_provenance_are_nonempty() {
        let (_reservation, port) = reserve_dynamic_host_port().expect("dynamic host port");
        assert_ne!(port, 0);
        let token = response_provenance_token();
        assert!(token.starts_with("ferrocrate-ebpf-"));
        assert!(token.len() > "ferrocrate-ebpf-".len());
    }

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

        // The build fixture uses alpine as its base image. Pull it into the
        // same temporary image store first so the test exercises the complete
        // pull -> build -> run -> cleanup lifecycle rather than relying on a
        // developer's global image cache.
        let pull_output = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args(["pull", "alpine:3.19"])
            .output()
            .expect("pull base image");
        assert!(
            pull_output.status.success(),
            "Base image pull should succeed: {}",
            String::from_utf8_lossy(&pull_output.stderr)
        );

        // Step 1: Build from Dockerfile
        let dockerfile = r#"FROM alpine:3.19
RUN echo "Hello from FerroCrate" > /hello.txt
CMD ["cat", "/hello.txt"]
"#;
        std::fs::write(temp_dir.path().join("Dockerfile"), dockerfile).expect("write dockerfile");

        let build_output = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .current_dir(temp_dir.path())
            .args([
                "build",
                "--dockerfile",
                "Dockerfile",
                "--tag",
                "test/cycle:latest",
            ])
            .output()
            .expect("build");

        assert!(
            build_output.status.success(),
            "Build should succeed: {}",
            String::from_utf8_lossy(&build_output.stderr)
        );

        // Step 2: List images - should contain our image
        let images_output = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args(["images", "--format", "json"])
            .output()
            .expect("images list");

        let images = String::from_utf8_lossy(&images_output.stdout);
        assert!(images.contains("test/cycle"), "Image should be listed");

        // Step 3: Run container
        let run_output = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args([
                "run",
                "--rm",
                "--network-backend",
                "iptables",
                "test/cycle:latest",
            ])
            .output()
            .expect("run");

        let run_stdout = String::from_utf8_lossy(&run_output.stdout);
        assert!(
            run_output.status.success() && run_stdout.contains("run: container_id="),
            "Run should succeed; stdout={run_stdout}; stderr={}",
            String::from_utf8_lossy(&run_output.stderr)
        );

        // Step 4: Verify cleanup (--rm should remove container)
        let ps_output = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args(["ps", "-a"])
            .output()
            .expect("ps");

        let containers = String::from_utf8_lossy(&ps_output.stdout);
        assert!(
            !containers.contains("test/cycle"),
            "Container should be removed"
        );
    }

    #[test]
    #[ignore = "Requires container runtime"]
    fn container_start_preserves_bind_mount_across_cli_processes() {
        if !should_run() {
            eprintln!("Skipping: container runtime not available");
            return;
        }

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let runtime_dir = tempfile::tempdir().expect("runtime dir");

        // Create a long-lived container with a bind mount and exercise
        // ownership plus mount replay across separate CLI processes.
        let run_output = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args([
                "run",
                "--name",
                "restart-test",
                "--bind",
                &format!("{}:data", temp_dir.path().display()),
                "--network-backend",
                "iptables",
                "alpine:3.19",
                "sh",
                "-c",
                "echo 'persistent' > /data/test.txt && sleep 60",
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

        // Start the stopped container in a separate CLI process.
        let start_output = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args(["start", "restart-test"])
            .output()
            .expect("start");

        assert!(start_output.status.success(), "Container should restart");

        // Verify the restarted record is live and the persisted bind mount
        // still exposes the host-side data written by the workload.
        let inspection = std::fs::read_to_string(temp_dir.path().join("test.txt"))
            .expect("persisted bind mount file");
        assert!(
            inspection.contains("persistent"),
            "Persisted bind mount should retain workload data"
        );
        let inspect_output = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args(["inspect", "--format", "json", "restart-test"])
            .output()
            .expect("inspect");
        assert!(
            inspect_output.status.success(),
            "Container should be inspectable after restart"
        );
        let inspect_json = String::from_utf8_lossy(&inspect_output.stdout);
        assert!(
            inspect_json.contains(temp_dir.path().to_string_lossy().as_ref()),
            "inspect did not retain mounts: {inspect_json}"
        );

        // Cleanup
        let _ = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args(["rm", "restart-test"])
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
                "run",
                "--name",
                "commit-test",
                "alpine:3.19",
                "sh",
                "-c",
                "echo 'modified' > /modified.txt && sleep 60",
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
        assert!(
            images.contains("test/committed:v1"),
            "Committed image should exist"
        );

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

    #[test]
    #[ignore = "Requires root + container runtime + network + image (sudo -E cargo test --test e2e_container_lifecycle -- --ignored network_published_port_and_egress)"]
    fn network_published_port_and_egress() {
        if !should_run() {
            eprintln!("Skipping: container runtime not available");
            return;
        }

        let runtime_dir = tempfile::tempdir().expect("runtime dir");

        // Start nginx publishing host port 8080 -> container port 80 on bridge network.
        // This exercises the OUTPUT-chain DNAT rule inserted by ferro-net.
        let run_output = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args([
                "run",
                "--name",
                "ferro-e2e-web",
                "--network",
                "bridge",
                "--network-backend",
                "iptables",
                "--cap-add",
                "NET_BIND_SERVICE",
                "-p",
                "8080:80",
                "docker.io/library/nginx:alpine",
            ])
            .output()
            .expect("run nginx");

        assert!(
            run_output.status.success(),
            "nginx container should start: {}",
            String::from_utf8_lossy(&run_output.stderr)
        );

        // Give nginx a moment to bind.
        std::thread::sleep(Duration::from_secs(2));

        // --- Check 1: published port reachable from host (OUTPUT-chain DNAT) ---
        let start = std::time::Instant::now();
        let mut last_curl = None;
        while start.elapsed() < Duration::from_secs(12) {
            let curl_host = Command::new("curl")
                .args([
                    "--silent",
                    "--fail",
                    "--max-time",
                    "2",
                    "http://127.0.0.1:8080/",
                ])
                .output()
                .expect("curl must be present on host");
            if curl_host.status.success() {
                last_curl = Some(curl_host);
                break;
            }
            last_curl = Some(curl_host);
            std::thread::sleep(Duration::from_millis(400));
        }

        let curl_host = last_curl.expect("at least one curl attempt");
        assert!(
            curl_host.status.success(),
            "Published port 8080 must be reachable from localhost (DNAT check failed): {}",
            String::from_utf8_lossy(&curl_host.stderr)
        );

        // --- Check 2: container has outbound internet egress (MASQUERADE + ip_forward) ---
        let exec_output = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args([
                "exec",
                "ferro-e2e-web",
                "wget",
                "-q",
                "-O",
                "-",
                "--timeout=5",
                "http://1.1.1.1/",
            ])
            .output()
            .expect("exec wget");

        assert!(
            exec_output.status.success(),
            "Container must have outbound egress to 1.1.1.1 (MASQUERADE/ip_forward check failed): {}",
            String::from_utf8_lossy(&exec_output.stderr)
        );

        // Cleanup
        let _ = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args(["rm", "-f", "ferro-e2e-web"])
            .output();
    }

    #[test]
    #[ignore = "Requires root + eBPF prerequisites + reserved SNAT range + network + image (FERROCRATE_E2E_NETWORK_BACKEND=ebpf sudo -E cargo test --test e2e_container_lifecycle -- --ignored ebpf_network_published_port_egress_without_netfilter_changes)"]
    fn ebpf_network_published_port_egress_without_netfilter_changes() {
        if std::env::var("FERROCRATE_E2E_NETWORK_BACKEND").as_deref() != Ok("ebpf") {
            eprintln!("Skipping: FERROCRATE_E2E_NETWORK_BACKEND is not ebpf");
            return;
        }
        if !should_run() {
            eprintln!("Skipping: container runtime not available");
            return;
        }

        let runtime_dir = tempfile::tempdir().expect("runtime dir");
        let (port_reservation, host_port) =
            reserve_dynamic_host_port().expect("reserve unoccupied localhost port");
        let port_mapping = format!("{host_port}:80");
        let provenance = response_provenance_token();
        let nginx_command = format!(
            "printf '%s\\n' '{provenance}' > /usr/share/nginx/html/index.html; exec nginx -g 'daemon off;'"
        );
        let before = netfilter_snapshot();
        drop(port_reservation);
        let run_output = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args([
                "run".to_string(),
                "--name".to_string(),
                "ferro-e2e-ebpf-web".to_string(),
                "--network".to_string(),
                "bridge".to_string(),
                "--network-backend".to_string(),
                "ebpf".to_string(),
                "--cap-add".to_string(),
                "NET_BIND_SERVICE".to_string(),
                "-p".to_string(),
                port_mapping,
                "docker.io/library/nginx:alpine".to_string(),
                "sh".to_string(),
                "-c".to_string(),
                nginx_command,
            ])
            .output()
            .expect("run nginx with eBPF");
        assert!(
            run_output.status.success(),
            "eBPF nginx container should start: {}",
            String::from_utf8_lossy(&run_output.stderr)
        );

        std::thread::sleep(Duration::from_secs(2));
        let start = std::time::Instant::now();
        let mut last_curl = None;
        while start.elapsed() < Duration::from_secs(12) {
            let curl = Command::new("curl")
                .args(["--silent", "--fail", "--max-time", "2"])
                .arg(format!("http://127.0.0.1:{host_port}/"))
                .output()
                .expect("curl must be present on host");
            let success = curl.status.success();
            last_curl = Some(curl);
            if success {
                break;
            }
            std::thread::sleep(Duration::from_millis(400));
        }
        let curl = last_curl.expect("at least one curl attempt");
        assert!(
            curl.status.success(),
            "eBPF published TCP port must be reachable: {}",
            String::from_utf8_lossy(&curl.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&curl.stdout).trim(),
            provenance,
            "published-port response did not come from the test container"
        );

        let during = netfilter_snapshot();
        assert_eq!(
            before.0, during.0,
            "eBPF setup changed the iptables ruleset"
        );
        assert_eq!(
            before.1, during.1,
            "eBPF setup changed the nftables ruleset"
        );

        let egress = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args([
                "exec",
                "ferro-e2e-ebpf-web",
                "wget",
                "-q",
                "-O",
                "-",
                "--timeout=5",
                "http://1.1.1.1/",
            ])
            .output()
            .expect("exec wget");
        assert!(
            egress.status.success(),
            "eBPF container must have outbound traffic: {}",
            String::from_utf8_lossy(&egress.stderr)
        );

        let cleanup = ferro_cli()
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .args(["rm", "-f", "ferro-e2e-ebpf-web"])
            .output()
            .expect("remove eBPF test container");
        assert!(
            cleanup.status.success(),
            "eBPF container cleanup must succeed: {}",
            String::from_utf8_lossy(&cleanup.stderr)
        );
        let after = netfilter_snapshot();
        assert_eq!(
            before.0, after.0,
            "eBPF cleanup changed the iptables ruleset"
        );
        assert_eq!(
            before.1, after.1,
            "eBPF cleanup changed the nftables ruleset"
        );
    }
}
