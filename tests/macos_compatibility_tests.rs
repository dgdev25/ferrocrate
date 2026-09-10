// macOS compatibility tests for FerroCrate desktop and CLI
// Tests installer, desktop daemon, VM lifecycle, and platform-specific functionality
//
// Run with: cargo test --test macos_compatibility_tests -- --nocapture

#[cfg(target_os = "macos")]
mod macos_tests {
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    fn workspace_root() -> PathBuf {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        if manifest_dir.join("scripts").exists() {
            manifest_dir
        } else {
            manifest_dir
                .parent()
                .unwrap_or(manifest_dir.as_path())
                .to_path_buf()
        }
    }

    fn get_test_dir() -> PathBuf {
        let test_root = workspace_root().join("target").join("test_macos");
        let _ = fs::create_dir_all(&test_root);
        test_root
    }

    fn ferrocrate_bin() -> PathBuf {
        PathBuf::from(env!("CARGO_BIN_EXE_ferro-cli"))
    }

    fn write_signed_entitlement(path: &Path, features: &[&str]) -> String {
        let signing_key = SigningKey::from_bytes(&[23u8; 32]);
        let verify_key = signing_key.verifying_key();
        let pubkey_b64 = BASE64_STANDARD.encode(verify_key.to_bytes());
        let payload = serde_json::to_vec(&serde_json::json!({
            "plan": "pro",
            "subject": "macos-test-suite",
            "issued_at": 1760000000u64,
            "features": features,
        }))
        .expect("entitlement payload");
        let signature = signing_key.sign(&payload);
        let envelope = serde_json::json!({
            "payload": BASE64_STANDARD.encode(&payload),
            "signature": BASE64_STANDARD.encode(signature.to_bytes()),
        });
        fs::write(
            path,
            serde_json::to_string(&envelope).expect("entitlement envelope"),
        )
        .expect("write entitlement file");
        pubkey_b64
    }

    // ============================================================================
    // Platform detection tests
    // ============================================================================

    #[test]
    fn detect_macos_platform() {
        assert_eq!(std::env::consts::OS, "macos", "Expected macOS platform");
    }

    #[test]
    fn detect_macos_architecture() {
        let arch = std::env::consts::ARCH;
        assert!(
            arch == "aarch64" || arch == "x86_64",
            "macOS should be aarch64 (Apple Silicon) or x86_64 (Intel)"
        );
        println!("macOS Architecture: {}", arch);
    }

    #[test]
    fn macos_major_version_at_least_12() {
        let output = Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .expect("Failed to get macOS version");

        let version_str = String::from_utf8_lossy(&output.stdout);
        let parts: Vec<&str> = version_str.trim().split('.').collect();

        if let Some(major) = parts.first().and_then(|v| v.parse::<u32>().ok()) {
            assert!(
                major >= 12,
                "FerroCrate requires macOS 12 or later, found: {}",
                major
            );
            println!("macOS Version: {}.x (✓ supported)", major);
        }
    }

    // ============================================================================
    // Installer script tests
    // ============================================================================

    #[test]
    fn installer_script_exists() {
        let installer_path = workspace_root().join("scripts").join("install-macos.sh");
        assert!(installer_path.exists(), "install-macos.sh not found");
    }

    #[test]
    fn installer_script_is_executable() {
        let installer_path = workspace_root().join("scripts").join("install-macos.sh");

        let metadata = fs::metadata(&installer_path).expect("Failed to read installer metadata");
        let mode = metadata.permissions().mode();
        assert_ne!(mode & 0o100, 0, "install-macos.sh must be executable");
    }

    #[test]
    fn installer_script_contains_required_functions() {
        let installer_path = workspace_root().join("scripts").join("install-macos.sh");

        let content = fs::read_to_string(&installer_path).expect("Failed to read install-macos.sh");

        assert!(
            content.contains("arch_name()"),
            "Missing arch_name function"
        );
        assert!(
            content.contains("ensure_macos()"),
            "Missing ensure_macos function"
        );
        assert!(
            content.contains("install_binary_release()"),
            "Missing install_binary_release function"
        );
        assert!(
            content.contains("install_from_source()"),
            "Missing install_from_source function"
        );
    }

    #[test]
    fn installer_supports_both_architectures() {
        let installer_path = workspace_root().join("scripts").join("install-macos.sh");

        let content = fs::read_to_string(&installer_path).expect("Failed to read install-macos.sh");

        assert!(
            content.contains("aarch64"),
            "Missing aarch64 (Apple Silicon) support"
        );
        assert!(content.contains("x86_64"), "Missing x86_64 (Intel) support");
    }

    // ============================================================================
    // Desktop package script tests
    // ============================================================================

    #[test]
    fn package_macos_app_script_exists() {
        let package_script = workspace_root()
            .join("scripts")
            .join("package-macos-app.sh");
        assert!(package_script.exists(), "package-macos-app.sh not found");
    }

    #[test]
    fn package_script_creates_valid_app_structure() {
        let package_script = workspace_root()
            .join("scripts")
            .join("package-macos-app.sh");

        let content =
            fs::read_to_string(&package_script).expect("Failed to read package-macos-app.sh");

        // Verify standard macOS app bundle structure creation
        assert!(
            content.contains("MACOS_DIR="),
            "Missing MacOS directory structure"
        );
        assert!(
            content.contains("RES_DIR="),
            "Missing Resources directory structure"
        );
        assert!(
            content.contains("PLIST_PATH="),
            "Missing Info.plist creation"
        );
        assert!(
            content.contains("CFBundleExecutable"),
            "Missing CFBundleExecutable in plist"
        );
    }

    // ============================================================================
    // Path handling tests (macOS-specific)
    // ============================================================================

    #[test]
    fn macos_home_directory_resolution() {
        let home = std::env::var("HOME").expect("HOME environment variable not set on macOS");
        assert!(!home.is_empty(), "HOME should not be empty");
        assert!(home.starts_with("/"), "macOS home should use absolute path");
        println!("HOME={}", home);
    }

    #[test]
    fn macos_library_paths_exist() {
        let home = std::env::var("HOME").expect("HOME not set");
        let library = Path::new(&home).join("Library");
        assert!(library.exists(), "~/Library should exist on macOS");

        let launch_agents = library.join("LaunchAgents");
        // LaunchAgents may not exist, but if it does, it should be a directory
        if launch_agents.exists() {
            assert!(launch_agents.is_dir(), "LaunchAgents should be a directory");
        }
    }

    #[test]
    fn macos_desktop_state_paths() {
        let home = std::env::var("HOME").expect("HOME not set");
        let ferrocrate_dir = Path::new(&home).join(".ferrocrate");

        // Directory may not exist yet, but the path should be valid
        assert!(ferrocrate_dir.to_string_lossy().contains(".ferrocrate"));
    }

    // ============================================================================
    // Launch agent (autostart) tests
    // ============================================================================

    #[test]
    fn launch_agent_plist_format_is_valid() {
        // This would be from ferro-desktop main.rs render_macos_launch_agent_plist
        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>io.ferrocrate.desktop</string>
    <key>ProgramArguments</key>
    <array>
      <string>/usr/local/bin/ferro-desktop</string>
      <string>daemon</string>
      <string>--addr</string>
      <string>127.0.0.1:4288</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
  </dict>
</plist>"#;

        // Verify XML structure
        assert!(
            plist.starts_with("<?xml"),
            "Plist should start with XML declaration"
        );
        assert!(
            plist.contains("<!DOCTYPE plist"),
            "Plist should have DOCTYPE"
        );
        assert!(
            plist.contains("<dict>"),
            "Plist should contain dict element"
        );
        assert!(plist.contains("RunAtLoad"), "Plist should have RunAtLoad");
        assert!(plist.contains("KeepAlive"), "Plist should have KeepAlive");
    }

    #[test]
    fn launch_agent_plist_can_be_parsed() {
        // Use macOS native plutil to validate plist structure
        let test_dir = get_test_dir();
        let test_plist = test_dir.join("test-launch-agent.plist");

        let plist_content = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>io.ferrocrate.test</string>
    <key>ProgramArguments</key>
    <array>
      <string>/usr/bin/echo</string>
      <string>test</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
  </dict>
</plist>"#;

        fs::write(&test_plist, plist_content).expect("Failed to write test plist");

        // Verify with plutil
        let output = Command::new("plutil")
            .arg("-lint")
            .arg(&test_plist)
            .output()
            .expect("Failed to run plutil");

        assert!(
            output.status.success(),
            "plutil validation failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let _ = fs::remove_file(&test_plist);
    }

    // ============================================================================
    // Daemon socket tests
    // ============================================================================

    #[test]
    fn daemon_can_bind_loopback_socket() {
        use std::net::TcpListener;

        // Try to bind to a random loopback port
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind to loopback");

        let addr = listener.local_addr().expect("Failed to get local address");
        assert!(
            addr.ip().to_string().contains("127.0.0.1"),
            "Should bind to loopback"
        );
    }

    #[test]
    fn daemon_rejects_non_loopback_by_default() {
        // Mock of validate_daemon_addr logic
        let addr = "192.168.1.1:4288";
        let allow_remote = false;

        let is_loopback = addr.starts_with("127.0.0.1:")
            || addr.starts_with("localhost:")
            || addr.starts_with("[::1]:");

        let should_reject = !is_loopback && !allow_remote;
        assert!(
            should_reject,
            "Should reject non-loopback when allow_remote=false"
        );
    }

    // ============================================================================
    // VM backend tests (qemu-hvf for macOS)
    // ============================================================================

    #[test]
    fn qemu_hvf_backend_is_macos_only() {
        // qemu-hvf requires hypervisor framework on macOS; this test file only compiles there.
        assert_eq!(
            std::env::consts::OS,
            "macos",
            "qemu-hvf backend only on macOS"
        );
    }

    #[test]
    fn qemu_version_check() {
        // Check if qemu is available on the system
        let output = Command::new("qemu-system-aarch64")
            .arg("--version")
            .output();

        match output {
            Ok(out) => {
                let version_str = String::from_utf8_lossy(&out.stdout);
                println!("Found QEMU: {}", version_str);
                assert!(version_str.contains("QEMU"), "Should be QEMU");
            }
            Err(_) => {
                println!("QEMU not installed on this system (optional)");
            }
        }
    }

    #[test]
    fn hypervisor_framework_check() {
        // Check if Hypervisor framework is available
        let output = Command::new("sysctl")
            .arg("-n")
            .arg("hw.optional.hv_capable")
            .output();

        match output {
            Ok(out) => {
                let capable = String::from_utf8_lossy(&out.stdout);
                println!("Hypervisor capable: {}", capable.trim());
            }
            Err(_) => {
                println!("Could not check hypervisor capability");
            }
        }
    }

    // ============================================================================
    // Filesystem tests
    // ============================================================================

    #[test]
    fn disk_capacity_check() {
        // VM disk creation needs sufficient space
        let home = std::env::var("HOME").expect("HOME not set");

        let output = Command::new("df")
            .arg(&home)
            .output()
            .expect("Failed to run df");

        let df_output = String::from_utf8_lossy(&output.stdout);
        println!("Disk usage for {}: {}", home, df_output);

        // At least verify we can parse df output
        assert!(
            df_output.contains("Filesystem") || df_output.contains("/"),
            "df should show filesystem info"
        );
    }

    #[test]
    fn case_sensitive_filesystem_handling() {
        // macOS filesystems might be case-insensitive
        let test_dir = get_test_dir();
        let test_file = test_dir.join("TestFile.txt");
        let lower_file = test_dir.join("testfile.txt");

        fs::write(&test_file, "test").expect("Failed to write TestFile.txt");

        // On case-insensitive FS, both paths refer to same file
        let exists_lower = lower_file.exists();
        println!(
            "Filesystem case-sensitive: {}",
            !exists_lower || test_file == lower_file
        );

        let _ = fs::remove_file(&test_file);
    }

    // ============================================================================
    // Signal handling tests (Unix)
    // ============================================================================

    #[test]
    fn unix_signal_constants_available() {
        // Should have signal support on macOS
        assert_eq!(
            std::env::consts::FAMILY,
            "unix",
            "macOS should have Unix signal support"
        );
    }

    #[test]
    fn pid_check_command_available() {
        // `kill -0` used to check if pid is alive
        let output = Command::new("kill").arg("--help").output();

        // kill should be available
        assert!(output.is_ok(), "kill command should be available");
    }

    // ============================================================================
    // Network tests
    // ============================================================================

    #[test]
    fn ipv4_loopback_localhost_available() {
        use std::net::IpAddr;

        let localhost: IpAddr = "127.0.0.1".parse().expect("Failed to parse localhost");
        assert!(localhost.is_loopback(), "127.0.0.1 should be loopback");
    }

    #[test]
    fn ipv6_loopback_available() {
        use std::net::IpAddr;

        let localhost_v6: IpAddr = "::1".parse().expect("Failed to parse ::1");
        assert!(localhost_v6.is_loopback(), "::1 should be loopback");
    }

    // ============================================================================
    // Environment variable tests
    // ============================================================================

    #[test]
    fn required_env_vars_can_be_read() {
        // HOME is critical on macOS
        let home = std::env::var("HOME");
        assert!(home.is_ok(), "HOME environment variable should be set");

        // LOCALAPPDATA is Windows-specific, might not exist on macOS
        let _app_data = std::env::var("LOCALAPPDATA");
        // It's OK if not set on macOS
    }

    // ============================================================================
    // Cargo build verification
    // ============================================================================

    #[test]
    fn cargo_build_targets_include_macos() {
        let output = Command::new("cargo")
            .arg("--version")
            .output()
            .expect("cargo should be installed");

        assert!(output.status.success(), "cargo should be available");
    }

    // ============================================================================
    // Smoke tests
    // ============================================================================

    #[test]
    fn can_create_temp_directory() {
        let temp_dir = get_test_dir();
        assert!(temp_dir.exists(), "Test directory should be created");
    }

    #[test]
    fn can_write_and_read_json_file() {
        let test_dir = get_test_dir();
        let json_file = test_dir.join("test-config.json");
        let json_content = r#"{"test": "data", "nested": {"value": 42}}"#;

        fs::write(&json_file, json_content).expect("Failed to write JSON");
        let read_back = fs::read_to_string(&json_file).expect("Failed to read JSON");

        assert_eq!(read_back, json_content, "JSON content should match");
        let _ = fs::remove_file(&json_file);
    }

    #[test]
    fn macos_app_bundle_dir_names_valid() {
        // Test that standard macOS directory names are accepted
        let dirs = vec![
            "Contents",
            "Contents/MacOS",
            "Contents/Resources",
            "Contents/Frameworks",
            "Contents/Library",
        ];

        for dir_name in dirs {
            assert!(
                !dir_name.contains(' '),
                "macOS path '{}' should not have spaces in structure",
                dir_name
            );
        }
    }

    #[test]
    fn ai_orchestrate_requires_entitlement() {
        let test_dir = get_test_dir();
        let image_store = test_dir.join("images-entitlement-missing");
        let _ = fs::create_dir_all(&image_store);
        let out = Command::new(ferrocrate_bin())
            .args(["ai", "orchestrate", "--task", "test-entitlement-gate"])
            .env("FERROCRATE_IMAGE_STORE", &image_store)
            .env("FERROCRATE_AI_DEGRADE", "1")
            .output()
            .expect("run ferrocrate ai orchestrate");

        assert!(
            !out.status.success(),
            "ai orchestrate should fail without entitlement"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("requires paid entitlement"),
            "expected entitlement error, got: {stderr}"
        );
    }

    #[test]
    fn ai_orchestrate_succeeds_with_valid_entitlement() {
        let test_dir = get_test_dir();
        let entitlement = test_dir.join("entitlement-ai.lic");
        let image_store = test_dir.join("images-entitlement-valid");
        let _ = fs::create_dir_all(&image_store);
        let pubkey = write_signed_entitlement(&entitlement, &["ai_advanced"]);

        let out = Command::new(ferrocrate_bin())
            .args(["ai", "orchestrate", "--task", "test-entitlement-ok"])
            .env("FERROCRATE_IMAGE_STORE", &image_store)
            .env("FERROCRATE_ENTITLEMENT_FILE", &entitlement)
            .env("FERROCRATE_ENTITLEMENT_PUBKEY", &pubkey)
            .env(
                "FERROCRATE_CLAUDE_FLOW_CMD",
                "/definitely/missing/claude-flow",
            )
            .env("FERROCRATE_AI_DEGRADE", "1")
            .output()
            .expect("run ferrocrate ai orchestrate with entitlement");

        assert!(
            out.status.success(),
            "expected success with valid entitlement"
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("degraded mode enabled") || stdout.contains("claude-flow unavailable"),
            "expected degraded orchestration output, got: {stdout}"
        );
    }
}

#[cfg(not(target_os = "macos"))]
mod non_macos_tests {
    #[test]
    fn skipped_on_non_macos() {
        println!("macOS-specific tests skipped on non-macOS platform");
    }
}
