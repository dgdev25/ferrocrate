#![cfg(target_os = "linux")]

#[test]
fn unsupported_login_lifetimes_fail_before_tls_or_connection_setup() {
    for seconds in ["0", "901", "3600", "-1"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_ferro-mgr"))
            .args(["fleet-ui", "--login-ttl-seconds", seconds])
            .output()
            .expect("run Fleet UI argument validation");
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("--login-ttl-seconds must be between 1 and 900"),
            "unsupported lifetime {seconds} reached later startup work: {stderr}"
        );
    }
}
