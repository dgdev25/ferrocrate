//! Security tests for FerroCrate
//!
//! Tests for seccomp, capabilities, and auth file security.

#![cfg(target_os = "linux")]

use ferro_core::seccomp::{apply_seccomp_profile, default_seccomp_profile, parse_seccomp_profile};

#[test]
fn parses_default_seccomp_profile() {
    let profile = default_seccomp_profile().expect("default profile should parse");
    // The shipped default is a Docker-style denylist: ordinary container
    // syscalls remain allowed while explicitly dangerous syscalls are denied.
    assert_eq!(profile.default_action, "SCMP_ACT_ALLOW");
    assert!(!profile.architectures.is_empty());
    assert!(!profile.syscalls.is_empty());
    assert!(profile
        .syscalls
        .iter()
        .any(|rule| rule.action == "SCMP_ACT_ERRNO"));
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

#[test]
fn applies_and_enforces_seccomp_profile_in_isolated_child() {
    // Load the filter in a forked child so a denied syscall cannot poison the
    // test harness. libseccomp sets no_new_privs for an unprivileged caller.
    let mut pipe_fds = [0; 2];
    assert_eq!(unsafe { nix::libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
    let child = unsafe { nix::libc::fork() };
    assert!(child >= 0, "fork seccomp probe");
    if child == 0 {
        unsafe {
            nix::libc::close(pipe_fds[0]);
        }
        let profile = ferro_core::seccomp::SeccompProfile {
            default_action: "SCMP_ACT_ERRNO".to_string(),
            default_errno_ret: Some(1),
            architectures: vec![if cfg!(target_arch = "x86_64") {
                "SCMP_ARCH_X86_64"
            } else if cfg!(target_arch = "aarch64") {
                "SCMP_ARCH_AARCH64"
            } else {
                "SCMP_ARCH_X86"
            }
            .to_string()],
            syscalls: vec![
                ferro_core::seccomp::SyscallRule {
                    names: vec!["write".to_string()],
                    action: "SCMP_ACT_ALLOW".to_string(),
                    args: None,
                },
                ferro_core::seccomp::SyscallRule {
                    names: vec!["exit".to_string(), "exit_group".to_string()],
                    action: "SCMP_ACT_ALLOW".to_string(),
                    args: None,
                },
            ],
        };
        if apply_seccomp_profile(&profile).is_err() {
            let marker = [0xee_u8];
            unsafe {
                nix::libc::write(pipe_fds[1], marker.as_ptr().cast(), marker.len());
                nix::libc::_exit(2);
            }
        }
        let result = unsafe { nix::libc::syscall(nix::libc::SYS_getpid) };
        let marker = [if result == -1 { 1_u8 } else { 0_u8 }];
        unsafe {
            nix::libc::write(pipe_fds[1], marker.as_ptr().cast(), marker.len());
            nix::libc::_exit(0);
        }
    }
    unsafe {
        nix::libc::close(pipe_fds[1]);
    }
    let mut marker = [0_u8];
    assert_eq!(
        unsafe { nix::libc::read(pipe_fds[0], marker.as_mut_ptr().cast(), marker.len()) },
        1,
        "seccomp probe marker"
    );
    unsafe {
        nix::libc::close(pipe_fds[0]);
    }
    let mut status = 0;
    assert_eq!(unsafe { nix::libc::waitpid(child, &mut status, 0) }, child);
    assert_eq!(status, 0, "seccomp probe child exited unexpectedly");
    assert_eq!(marker[0], 1, "getpid should be denied by the loaded filter");
}
