#![cfg(target_os = "linux")]

#[cfg(target_os = "linux")]
mod linux_tests {
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    fn write_signed_entitlement(path: &Path, features: &[&str]) -> String {
        let signing_key = SigningKey::from_bytes(&[31u8; 32]);
        let verify_key = signing_key.verifying_key();
        let pubkey_b64 = BASE64_STANDARD.encode(verify_key.to_bytes());

        let payload = serde_json::to_vec(&serde_json::json!({
            "plan": "pro",
            "subject": "linux-integration-tests",
            "issued_at": 1760000000u64,
            "features": features,
        }))
        .expect("entitlement payload");

        let signature = signing_key.sign(&payload);
        let envelope = serde_json::json!({
            "payload": BASE64_STANDARD.encode(&payload),
            "signature": BASE64_STANDARD.encode(signature.to_bytes()),
        });

        fs::write(path, serde_json::to_string(&envelope).expect("envelope"))
            .expect("write entitlement file");

        pubkey_b64
    }

    fn cmd_with_isolated_state() -> (Command, tempfile::TempDir, tempfile::TempDir) {
        let runtime_dir = tempfile::tempdir().expect("runtime tempdir");
        let image_store = tempfile::tempdir().expect("image store tempdir");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ferro-cli"));
        cmd.env("HOME", runtime_dir.path())
            .env_remove("FERROCRATE_ENTITLEMENT_FILE")
            .env_remove("FERROCRATE_ENTITLEMENT_PUBKEY")
            .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
            .env("FERROCRATE_IMAGE_STORE", image_store.path());
        (cmd, runtime_dir, image_store)
    }

    #[test]
    fn ai_orchestrate_requires_entitlement_on_linux() {
        let (mut cmd, runtime_dir, _image_store) = cmd_with_isolated_state();
        let output = cmd
            .args(["ai", "orchestrate", "--task", "linux-entitlement-gate"])
            .env(
                "FERROCRATE_ENTITLEMENT_FILE",
                runtime_dir.path().join("missing-entitlement.lic"),
            )
            .env_remove("FERROCRATE_ENTITLEMENT_PUBKEY")
            .env("FERROCRATE_AI_DEGRADE", "1")
            .output()
            .expect("run ferro-cli");

        assert!(
            !output.status.success(),
            "ai orchestrate should fail without entitlement"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("requires paid entitlement"),
            "expected entitlement error, got: {stderr}"
        );
    }

    #[test]
    fn free_cli_workflow_does_not_require_entitlement() {
        let (mut cmd, _runtime_dir, _image_store) = cmd_with_isolated_state();
        let output = cmd
            .env_remove("FERROCRATE_ENTITLEMENT_FILE")
            .env_remove("FERROCRATE_ENTITLEMENT_PUBKEY")
            .args(["images"])
            .output()
            .expect("run free CLI workflow");

        assert!(
            output.status.success(),
            "free workflow must remain available without entitlement, stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn ai_orchestrate_succeeds_with_valid_entitlement_on_linux() {
        let (mut cmd, _runtime_dir, _image_store) = cmd_with_isolated_state();
        let entitlement_dir = tempfile::tempdir().expect("entitlement tempdir");
        let entitlement_path = entitlement_dir.path().join("entitlement.lic");
        let pubkey = write_signed_entitlement(&entitlement_path, &["ai_advanced"]);

        let output = cmd
            .args(["ai", "orchestrate", "--task", "linux-entitlement-ok"])
            .env("FERROCRATE_ENTITLEMENT_FILE", &entitlement_path)
            .env("FERROCRATE_ENTITLEMENT_PUBKEY", &pubkey)
            .env(
                "FERROCRATE_CLAUDE_FLOW_CMD",
                "/definitely/missing/claude-flow",
            )
            .env("FERROCRATE_AI_DEGRADE", "1")
            .output()
            .expect("run ferro-cli with entitlement");

        assert!(
            output.status.success(),
            "expected success with valid entitlement, stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );

        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("degraded mode enabled") || stdout.contains("claude-flow unavailable"),
            "expected degraded output, got: {stdout}"
        );
    }
}

#[cfg(not(target_os = "linux"))]
mod non_linux_tests {
    #[test]
    fn skipped_on_non_linux() {
        println!("linux-only entitlement integration tests skipped");
    }
}
