#![cfg(target_os = "linux")]

//! Adversarial execution-surface tests (roadmap item 2).
//!
//! Covers symlink/path traversal in layer extraction, descriptor
//! substitution, namespace-identity teardown decisions, seccomp profile
//! parsing, and fail-closed authorization policy loading. Every test uses a
//! canary outside the sandbox to prove an escape attempt deletes nothing.

use std::fs;
use std::io::Cursor;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use ferro_core::rootfs::{construct_rootfs, RootfsError};
use ferro_core::seccomp::parse_seccomp_profile;
use tar::{Builder, Header};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn create_tar_with_files(path: &Path, entries: &[(&str, &[u8])]) {
    let file = fs::File::create(path).expect("create tar");
    let mut builder = Builder::new(file);
    for (entry_path, content) in entries {
        let mut header = Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        // Adversarial paths (absolute, `..`) are rejected by the builder's
        // own path validation, so write the raw header name field directly.
        let name = header.as_gnu_mut().expect("gnu header");
        for (slot, byte) in name.name.iter_mut().zip(entry_path.bytes()) {
            *slot = byte;
        }
        header.set_cksum();
        builder
            .append(&mut header, Cursor::new(content))
            .expect("append raw entry");
    }
    builder.finish().expect("finish tar");
}

fn append_symlink_entry(builder: &mut Builder<fs::File>, path: &str, target: &str) {
    let mut header = Header::new_gnu();
    header.set_size(0);
    header.set_mode(0o777);
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_cksum();
    builder
        .append_link(&mut header, PathBuf::from(path), target)
        .expect("append symlink");
}

fn append_hard_link_entry(builder: &mut Builder<fs::File>, path: &str, target: &str) {
    let mut header = Header::new_gnu();
    header.set_size(0);
    header.set_mode(0o644);
    header.set_entry_type(tar::EntryType::hard_link());
    header.set_cksum();
    builder
        .append_link(&mut header, PathBuf::from(path), target)
        .expect("append hard link");
}

/// Victim directory outside the rootfs with a canary file that must survive
/// every extraction attempt.
fn victim_dir(temp: &tempfile::TempDir) -> PathBuf {
    let victim = temp.path().join("victim");
    fs::create_dir_all(&victim).expect("victim dir");
    fs::write(victim.join("canary.txt"), b"must-survive").expect("victim canary");
    victim
}

fn canary_survives(victim: &Path) -> bool {
    fs::read(victim.join("canary.txt")).is_ok_and(|bytes| bytes == b"must-survive")
}


// ---------------------------------------------------------------------------
// symlink / path traversal in layer extraction
// ---------------------------------------------------------------------------

#[test]
fn rootfs_rejects_absolute_and_parent_traversal_entries() {
    let temp = tempfile::tempdir().expect("tempdir");
    let rootfs = temp.path().join("rootfs");
    for case in ["/etc/absolute-evil", "../../escape", "a/../../escape", "/../escape"] {
        let layer = temp.path().join("layer.tar");
        create_tar_with_files(&layer, &[(case, b"payload".as_slice())]);

        let error = construct_rootfs(&rootfs, &[layer])
            .expect_err("traversal entry must fail closed");
        assert!(
            matches!(error, RootfsError::UnsafePath(_)),
            "case {case:?} must be rejected as unsafe, got {error:?}"
        );
    }
}

#[test]
fn rootfs_rejects_files_written_through_symlinked_directory() {
    let temp = tempfile::tempdir().expect("tempdir");
    let victim = victim_dir(&temp);
    let rootfs = temp.path().join("rootfs");

    let layer = temp.path().join("layer.tar");
    {
        let file = fs::File::create(&layer).expect("create tar");
        let mut builder = Builder::new(file);
        append_symlink_entry(&mut builder, "esc", victim.to_str().expect("utf8 victim"));
        let mut header = Header::new_gnu();
        header.set_size(7);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, PathBuf::from("esc/pwned.txt"), Cursor::new(b"pwned!!"))
            .expect("append through symlink");
        builder.finish().expect("finish tar");
    }

    let error =
        construct_rootfs(&rootfs, &[layer]).expect_err("write through symlink must fail closed");
    assert!(matches!(error, RootfsError::UnsafePath(_)), "got {error:?}");
    assert!(canary_survives(&victim));
    assert!(!victim.join("pwned.txt").exists());
}

/// Regression: an opaque whiteout (`.wh..wh..opq`) placed under a directory
/// that a previous layer turned into a symlink must not follow the symlink
/// and must not clear files outside the rootfs.
#[test]
fn rootfs_opaque_whiteout_cannot_escape_through_symlinked_directory() {
    let temp = tempfile::tempdir().expect("tempdir");
    let victim = victim_dir(&temp);
    let rootfs = temp.path().join("rootfs");

    let layer1 = temp.path().join("layer1.tar");
    {
        let file = fs::File::create(&layer1).expect("create tar");
        let mut builder = Builder::new(file);
        append_symlink_entry(&mut builder, "etc/esc", victim.to_str().expect("utf8 victim"));
        builder.finish().expect("finish tar");
    }
    let layer2 = temp.path().join("layer2.tar");
    create_tar_with_files(&layer2, &[("etc/esc/.wh..wh..opq", b"".as_slice())]);

    let result = construct_rootfs(&rootfs, &[layer1.clone(), layer2]);
    assert!(
        canary_survives(&victim),
        "opaque whiteout escaped the rootfs and deleted the victim canary (result: {result:?})"
    );
    assert!(
        result.is_err(),
        "opaque whiteout through a symlinked directory must fail closed, got {result:?}"
    );
}

/// Regression: a regular whiteout (`.wh.<name>`) under a symlinked directory
/// must not delete the outside file the symlink points at.
#[test]
fn rootfs_regular_whiteout_cannot_delete_through_symlinked_directory() {
    let temp = tempfile::tempdir().expect("tempdir");
    let victim = victim_dir(&temp);
    let rootfs = temp.path().join("rootfs");

    let layer1 = temp.path().join("layer1.tar");
    {
        let file = fs::File::create(&layer1).expect("create tar");
        let mut builder = Builder::new(file);
        append_symlink_entry(&mut builder, "etc/esc", victim.to_str().expect("utf8 victim"));
        builder.finish().expect("finish tar");
    }
    let layer2 = temp.path().join("layer2.tar");
    create_tar_with_files(&layer2, &[("etc/esc/.wh.canary.txt", b"".as_slice())]);

    let result = construct_rootfs(&rootfs, &[layer1, layer2]);
    assert!(
        canary_survives(&victim),
        "regular whiteout escaped the rootfs and deleted the victim canary (result: {result:?})"
    );
    assert!(
        result.is_err(),
        "regular whiteout through a symlinked directory must fail closed, got {result:?}"
    );
}

#[test]
fn rootfs_hard_link_targets_cannot_escape_the_rootfs() {
    let temp = tempfile::tempdir().expect("tempdir");
    let victim = victim_dir(&temp);

    // Parent traversal in the link target.
    let rootfs = temp.path().join("rootfs-a");
    let layer = temp.path().join("layer-a.tar");
    {
        let file = fs::File::create(&layer).expect("create tar");
        let mut builder = Builder::new(file);
        append_hard_link_entry(&mut builder, "link", "../../victim/canary.txt");
        builder.finish().expect("finish tar");
    }
    let error =
        construct_rootfs(&rootfs, &[layer]).expect_err("traversal hard link must fail closed");
    assert!(matches!(error, RootfsError::UnsafePath(_)), "got {error:?}");
    assert!(canary_survives(&victim));

    // Link target whose parent path is a symlink out of the rootfs.
    let rootfs = temp.path().join("rootfs-b");
    let layer1 = temp.path().join("layer-b1.tar");
    {
        let file = fs::File::create(&layer1).expect("create tar");
        let mut builder = Builder::new(file);
        append_symlink_entry(&mut builder, "esc", victim.to_str().expect("utf8 victim"));
        builder.finish().expect("finish tar");
    }
    let layer2 = temp.path().join("layer-b2.tar");
    {
        let file = fs::File::create(&layer2).expect("create tar");
        let mut builder = Builder::new(file);
        append_hard_link_entry(&mut builder, "stolen", "esc/canary.txt");
        builder.finish().expect("finish tar");
    }
    let error = construct_rootfs(&rootfs, &[layer1, layer2])
        .expect_err("hard link through symlink must fail closed");
    assert!(matches!(error, RootfsError::UnsafePath(_)), "got {error:?}");
    assert!(canary_survives(&victim));
}

// ---------------------------------------------------------------------------
// namespace identity: fail-closed teardown decision
// ---------------------------------------------------------------------------

use ferro_core::container_store::KernelObjectIdentityRecord;
use ferro_core::runtime::{netns_deletion_decision, NetnsDeletionDecision};

fn identity_of(path: &Path) -> KernelObjectIdentityRecord {
    let metadata = fs::symlink_metadata(path).expect("identity metadata");
    KernelObjectIdentityRecord {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[test]
fn netns_deletion_allows_only_the_exact_recorded_namespace() {
    let temp = tempfile::tempdir().expect("tempdir");
    let netns_root = temp.path().join("netns");
    fs::create_dir_all(&netns_root).expect("netns root");
    let namespace = netns_root.join("ferrocrate-abc");
    fs::write(&namespace, b"").expect("namespace file");
    let expected = identity_of(&namespace);

    // Exact device+inode match is the only path that permits deletion.
    assert_eq!(
        netns_deletion_decision(&netns_root, "ferrocrate-abc", Some(expected)),
        NetnsDeletionDecision::Delete
    );

    // A recreated file at the same name is a different kernel object.
    fs::remove_file(&namespace).expect("remove namespace");
    fs::write(&namespace, b"").expect("recreate namespace");
    assert_eq!(
        netns_deletion_decision(&netns_root, "ferrocrate-abc", Some(expected)),
        NetnsDeletionDecision::RefuseIdentityMismatch
    );
    assert!(namespace.exists(), "refused decision must not delete");
}

#[test]
fn netns_deletion_fails_closed_on_missing_identity_and_symlinks() {
    let temp = tempfile::tempdir().expect("tempdir");
    let netns_root = temp.path().join("netns");
    fs::create_dir_all(&netns_root).expect("netns root");

    // Missing namespace file: nothing to delete, not a failure.
    assert_eq!(
        netns_deletion_decision(&netns_root, "absent", None),
        NetnsDeletionDecision::NothingToDelete
    );

    // Namespace present but identity record missing: refuse name-only deletion.
    let namespace = netns_root.join("ferrocrate-noid");
    fs::write(&namespace, b"").expect("namespace file");
    assert_eq!(
        netns_deletion_decision(&netns_root, "ferrocrate-noid", None),
        NetnsDeletionDecision::RefuseIdentityMismatch
    );
    assert!(namespace.exists(), "refused decision must not delete");

    // Symlink planted at the namespace path: never follow, always refuse.
    fs::remove_file(&namespace).expect("remove namespace");
    let decoy = temp.path().join("decoy");
    fs::write(&decoy, b"decoy").expect("decoy target");
    std::os::unix::fs::symlink(&decoy, &namespace).expect("planted symlink");
    assert_eq!(
        netns_deletion_decision(
            &netns_root,
            "ferrocrate-noid",
            Some(identity_of(&decoy))
        ),
        NetnsDeletionDecision::RefuseIdentityMismatch,
        "a symlink at the netns path must be refused even when its recorded identity matches the decoy"
    );
    assert!(decoy.exists(), "refused decision must not touch the decoy");
}

// ---------------------------------------------------------------------------
// seccomp profile parsing
// ---------------------------------------------------------------------------

#[test]
fn seccomp_profile_validation_rejects_adversarial_profiles() {
    let valid = r#"{
        "defaultAction": "SCMP_ACT_ALLOW",
        "architectures": ["SCMP_ARCH_X86_64"],
        "syscalls": [{"names": ["getpid"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1}]
    }"#;
    parse_seccomp_profile(valid).expect("baseline profile must parse");

    let cases: &[(&str, &str, &str)] = &[
        (
            "unknown default action",
            r#"{"defaultAction":"SCMP_ACT_OPEN","architectures":[],"syscalls":[]}"#,
            "unknown syscall action",
        ),
        (
            "unknown architecture",
            r#"{"defaultAction":"SCMP_ACT_ALLOW","architectures":["SCMP_ARCH_EVIL"],"syscalls":[]}"#,
            "unknown architecture",
        ),
        (
            "arg index out of range",
            r#"{"defaultAction":"SCMP_ACT_ALLOW","architectures":[],"syscalls":[{"names":["write"],"action":"SCMP_ACT_ERRNO","args":[{"index":9,"value":1,"op":"SCMP_CMP_EQ"}]}]}"#,
            "out of range 0..5",
        ),
        (
            "contradictory kill and allow",
            r#"{"defaultAction":"SCMP_ACT_ALLOW","architectures":[],"syscalls":[{"names":["sync"],"action":"SCMP_ACT_ALLOW"},{"names":["sync"],"action":"SCMP_ACT_KILL"}]}"#,
            "contradictory rules",
        ),
        (
            "errno out of range",
            r#"{"defaultAction":"SCMP_ACT_ALLOW","defaultErrnoRet":999999,"architectures":[],"syscalls":[]}"#,
            "between 0 and 4095",
        ),
    ];
    for (name, json, expected) in cases {
        let error =
            parse_seccomp_profile(json).expect_err("adversarial case must be rejected: {name}");
        assert!(
            error.to_string().contains(expected),
            "case {name:?}: expected {expected:?} in {error}"
        );
    }
}

// ---------------------------------------------------------------------------
// fail-closed authorization policy loading
// ---------------------------------------------------------------------------

use ferro_core::authorization::policy::{PolicyError, PolicyStore};

fn write_protected_policy(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write policy");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("protect policy");
}

#[test]
fn policy_loader_rejects_hardlinked_policy_sources() {
    let dir = tempfile::tempdir().expect("tempdir");
    let original = dir.path().join("policy.toml");
    let alias = dir.path().join("policy-alias.toml");
    write_protected_policy(&original, "schema_version = 1\ngeneration = 1\nmode = \"disabled\"\n");
    fs::hard_link(&original, &alias).expect("hard link policy");

    let error = PolicyStore::load(&alias).expect_err("hard-linked policy must fail closed");
    assert!(matches!(error, PolicyError::HardLinked), "got {error:?}");
}

#[test]
fn policy_loader_rejects_invalid_schema_and_zero_generation() {
    let dir = tempfile::tempdir().expect("tempdir");

    let future = dir.path().join("future.toml");
    write_protected_policy(
        &future,
        "schema_version = 2\ngeneration = 1\nmode = \"disabled\"\n",
    );
    let error = PolicyStore::load(&future).expect_err("unknown schema must fail closed");
    assert!(matches!(error, PolicyError::UnsupportedSchema(2)), "got {error:?}");

    let zero = dir.path().join("zero.toml");
    write_protected_policy(
        &zero,
        "schema_version = 1\ngeneration = 0\nmode = \"disabled\"\n",
    );
    let error = PolicyStore::load(&zero).expect_err("zero generation must fail closed");
    assert!(matches!(error, PolicyError::InvalidGeneration), "got {error:?}");
}

#[test]
fn policy_loader_rejects_invalid_mode_and_broken_documents() {
    let dir = tempfile::tempdir().expect("tempdir");

    let bad_mode = dir.path().join("bad-mode.toml");
    write_protected_policy(
        &bad_mode,
        "schema_version = 1\ngeneration = 1\nmode = \"permissive\"\n",
    );
    let error = PolicyStore::load(&bad_mode).expect_err("unknown mode must fail closed");
    assert!(
        matches!(error, PolicyError::Parse(_)),
        "unknown mode must be a parse failure, got {error:?}"
    );

    let truncated = dir.path().join("truncated.toml");
    write_protected_policy(&truncated, "schema_version = ");
    let error = PolicyStore::load(&truncated).expect_err("truncated policy must fail closed");
    assert!(matches!(error, PolicyError::Parse(_)), "got {error:?}");
}
