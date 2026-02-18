//! Security tests for FerroCrate
//!
//! Tests for seccomp, capabilities, and auth file security.

#![cfg(target_os = "linux")]

use ferro_core::seccomp::{apply_seccomp_profile, default_seccomp_profile, parse_seccomp_profile};

#[test]
fn parses_default_seccomp_profile() {
    let profile = default_seccomp_profile().expect("default profile should parse");
    assert_eq!(profile.default_action, "SCMP_ACT_ERRNO");
    assert!(!profile.architectures.is_empty());
    assert!(!profile.syscalls.is_empty());
}

#[test]
fn rejects_invalid_seccomp_json() {
    let err = parse_seccomp_profile("{not-valid-json").expect_err("should fail");
    assert!(err.to_string().contains("invalid seccomp profile JSON"));
}

#[test]
fn parses_valid_custom_profile() {
    let json = r#"{
        "defaultAction": "SCMP_ACT_ALLOW",
        "architectures": ["SCMP_ARCH_X86_64"],
        "syscalls": [
            {"names": ["reboot"], "action": "SCMP_ACT_KILL_PROCESS"}
        ]
    }"#;
    let profile = parse_seccomp_profile(json).expect("should parse");
    assert_eq!(profile.default_action, "SCMP_ACT_ALLOW");
    assert_eq!(profile.architectures, vec!["SCMP_ARCH_X86_64"]);
    assert_eq!(profile.syscalls.len(), 1);
}

#[test]
fn parses_syscall_rules_with_args() {
    let json = r#"{
        "defaultAction": "SCMP_ACT_ERRNO",
        "architectures": ["SCMP_ARCH_X86_64"],
        "syscalls": [
            {
                "names": ["write"],
                "action": "SCMP_ACT_ALLOW",
                "args": [
                    {"index": 0, "value": 1, "op": "SCMP_CMP_EQ"}
                ]
            }
        ]
    }"#;
    let profile = parse_seccomp_profile(json).expect("should parse");
    assert_eq!(profile.syscalls.len(), 1);
    let rule = &profile.syscalls[0];
    assert!(rule.args.is_some());
    let args = rule.args.as_ref().unwrap();
    assert_eq!(args.len(), 1);
    assert_eq!(args[0].index, 0);
    assert_eq!(args[0].value, 1);
}

// Note: apply_seccomp_profile tests require root and seccomp capabilities
// These are marked #[ignore] so they don't fail in regular test runs

#[test]
#[ignore = "requires root to apply seccomp filter"]
fn applies_seccomp_profile() {
    let profile = default_seccomp_profile().expect("profile should parse");
    // This would apply the filter to the current process
    // Only run this if you understand the implications
    let result = apply_seccomp_profile(&profile);
    assert!(result.is_ok(), "seccomp profile should apply successfully");
}
