#![cfg(target_os = "linux")]

use std::io::Cursor;
use std::process::Command;

/// Read every stored layer blob, gunzip it, and return the tar mode of the
/// first entry whose path ends with `name`. Fails when no layer holds `name`.
fn layer_entry_mode(runtime_dir: &std::path::Path, name: &str) -> u32 {
    let blobs = std::fs::read_dir(runtime_dir.join("images").join("blobs"))
        .expect("blobs directory after build");
    for entry in blobs.flatten() {
        let bytes = std::fs::read(entry.path()).expect("read layer blob");
        let mut decompressed = Vec::new();
        let mut decoder = flate2::read::GzDecoder::new(bytes.as_slice());
        if std::io::Read::read_to_end(&mut decoder, &mut decompressed).is_err() {
            continue;
        }
        let mut archive = tar::Archive::new(decompressed.as_slice());
        let Ok(entries) = archive.entries() else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry
                .path()
                .expect("entry path")
                .to_string_lossy()
                .into_owned();
            if path.ends_with(name) {
                return entry.header().mode().expect("entry mode");
            }
        }
    }
    panic!("no built layer contains an entry named {name}");
}

fn run_build(
    runtime_dir: &std::path::Path,
    context_dir: &std::path::Path,
    dockerfile: &std::path::Path,
    tag: &str,
    extra_args: &[&str],
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
        .env("FERROCRATE_HOME", runtime_dir)
        .env("FERROCRATE_RUNTIME_DIR", runtime_dir)
        .current_dir(context_dir)
        .args(["build", "--dockerfile"])
        .arg(dockerfile)
        .args(["--tag", tag])
        .args(extra_args)
        .output()
        .expect("run build")
}

#[test]
fn dockerfile_build_from_scratch_is_listed_in_images() {
    let runtime_dir = tempfile::tempdir().expect("runtime dir");
    let context_dir = tempfile::tempdir().expect("context dir");
    let dockerfile_path = context_dir.path().join("Dockerfile");

    std::fs::write(
        &dockerfile_path,
        "FROM scratch\nLABEL org.ferrocrate.test=parity\nCOPY hello.txt /hello.txt\n",
    )
    .expect("write dockerfile");
    std::fs::write(context_dir.path().join("hello.txt"), "hello\n").expect("write context file");

    let tag = "local/parity:test";

    let build_output = Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
        .env("FERROCRATE_HOME", runtime_dir.path())
        .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
        .current_dir(context_dir.path())
        .args(["build", "--dockerfile"])
        .arg(&dockerfile_path)
        .args(["--tag", tag])
        .output()
        .expect("run build");
    assert!(
        build_output.status.success(),
        "build failed: stdout={} stderr={}",
        String::from_utf8_lossy(&build_output.stdout),
        String::from_utf8_lossy(&build_output.stderr)
    );

    let images_output = Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
        .env("FERROCRATE_HOME", runtime_dir.path())
        .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
        .args(["images", "--format", "json"])
        .output()
        .expect("run images");
    assert!(
        images_output.status.success(),
        "images failed: stdout={} stderr={}",
        String::from_utf8_lossy(&images_output.stdout),
        String::from_utf8_lossy(&images_output.stderr)
    );

    let images_text = String::from_utf8_lossy(&images_output.stdout);
    assert!(
        images_text.contains(tag),
        "built tag not found in images output: {images_text}"
    );
}

#[test]
fn dockerfile_build_defaults_to_local_dockerfile() {
    let runtime_dir = tempfile::tempdir().expect("runtime dir");
    let context_dir = tempfile::tempdir().expect("context dir");
    let dockerfile_path = context_dir.path().join("Dockerfile");

    std::fs::write(
        &dockerfile_path,
        "FROM scratch\nLABEL org.ferrocrate.test=default-dockerfile\nCOPY hello.txt /hello.txt\n",
    )
    .expect("write dockerfile");
    std::fs::write(context_dir.path().join("hello.txt"), "hello\n").expect("write context file");

    let tag = "local/parity:default-dockerfile";

    let build_output = Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
        .env("FERROCRATE_HOME", runtime_dir.path())
        .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
        .current_dir(context_dir.path())
        .args(["build", "--dockerfile", "Dockerfile", "--tag", tag])
        .output()
        .expect("run build");
    assert!(
        build_output.status.success(),
        "build failed: stdout={} stderr={}",
        String::from_utf8_lossy(&build_output.stdout),
        String::from_utf8_lossy(&build_output.stderr)
    );

    let images_output = Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
        .env("FERROCRATE_HOME", runtime_dir.path())
        .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
        .args(["images", "--format", "json"])
        .output()
        .expect("run images");
    assert!(
        images_output.status.success(),
        "images failed: stdout={} stderr={}",
        String::from_utf8_lossy(&images_output.stdout),
        String::from_utf8_lossy(&images_output.stderr)
    );

    let images_text = String::from_utf8_lossy(&images_output.stdout);
    assert!(
        images_text.contains(tag),
        "built tag not found in images output: {images_text}"
    );
}

#[test]
fn dockerfile_add_extracts_a_local_tar_archive() {
    let runtime_dir = tempfile::tempdir().expect("runtime dir");
    let context_dir = tempfile::tempdir().expect("context dir");
    let dockerfile_path = context_dir.path().join("Dockerfile");
    let archive_path = context_dir.path().join("payload.tar");
    let mut archive = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path("nested/payload.txt").expect("archive path");
    header.set_size(7);
    header.set_mode(0o644);
    header.set_cksum();
    archive
        .append(&header, Cursor::new(b"payload"))
        .expect("append archive payload");
    std::fs::write(archive_path, archive.into_inner().expect("finish archive"))
        .expect("write archive");
    std::fs::write(&dockerfile_path, "FROM scratch\nADD payload.tar /app\n")
        .expect("write dockerfile");

    let tag = "local/parity:add-archive";
    let build_output = Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
        .env("FERROCRATE_HOME", runtime_dir.path())
        .env("FERROCRATE_RUNTIME_DIR", runtime_dir.path())
        .current_dir(context_dir.path())
        .args(["build", "--dockerfile"])
        .arg(&dockerfile_path)
        .args(["--tag", tag])
        .output()
        .expect("run build");
    assert!(
        build_output.status.success(),
        "ADD archive build failed: stdout={} stderr={}",
        String::from_utf8_lossy(&build_output.stdout),
        String::from_utf8_lossy(&build_output.stderr)
    );
}

#[test]
fn dockerfile_copy_chmod_lands_in_the_built_rootfs_layer() {
    let runtime_dir = tempfile::tempdir().expect("runtime dir");
    let context_dir = tempfile::tempdir().expect("context dir");
    let dockerfile_path = context_dir.path().join("Dockerfile");
    std::fs::write(context_dir.path().join("secret.txt"), "secret\n").expect("write context file");
    std::fs::write(
        &dockerfile_path,
        "FROM scratch\nCOPY --chmod=640 secret.txt /etc/secret.txt\n",
    )
    .expect("write dockerfile");

    let output = run_build(
        runtime_dir.path(),
        context_dir.path(),
        &dockerfile_path,
        "local/parity:chmod",
        &[],
    );
    assert!(
        output.status.success(),
        "chmod build failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        layer_entry_mode(runtime_dir.path(), "secret.txt") & 0o777,
        0o640,
        "COPY --chmod must set the mode of the copied file in the layer"
    );
}

#[test]
fn dockerfile_build_joins_line_continuations() {
    let runtime_dir = tempfile::tempdir().expect("runtime dir");
    let context_dir = tempfile::tempdir().expect("context dir");
    let dockerfile_path = context_dir.path().join("Dockerfile");
    std::fs::write(context_dir.path().join("hello.txt"), "hello\n").expect("write context file");
    std::fs::write(
        &dockerfile_path,
        "FROM scratch\nLABEL a=b\nCOPY hello.txt \\\n    /hello.txt\n",
    )
    .expect("write dockerfile");

    let output = run_build(
        runtime_dir.path(),
        context_dir.path(),
        &dockerfile_path,
        "local/parity:continuation",
        &[],
    );
    assert!(
        output.status.success(),
        "continuation build failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        layer_entry_mode(runtime_dir.path(), "hello.txt") > 0,
        "joined COPY must place the context file in the built layer"
    );
}

#[test]
fn dockerfile_escape_directive_builds_with_backtick_continuation() {
    let runtime_dir = tempfile::tempdir().expect("runtime dir");
    let context_dir = tempfile::tempdir().expect("context dir");
    let dockerfile_path = context_dir.path().join("Dockerfile");
    std::fs::write(context_dir.path().join("hello.txt"), "hello\n").expect("write context file");
    std::fs::write(
        &dockerfile_path,
        "# escape=`\nFROM scratch\nCOPY hello.txt `\n    /hello.txt\n",
    )
    .expect("write dockerfile");

    let output = run_build(
        runtime_dir.path(),
        context_dir.path(),
        &dockerfile_path,
        "local/parity:escape",
        &[],
    );
    assert!(
        output.status.success(),
        "escape directive build failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn dockerfile_syntax_directive_is_consumed_before_building() {
    let runtime_dir = tempfile::tempdir().expect("runtime dir");
    let context_dir = tempfile::tempdir().expect("context dir");
    let dockerfile_path = context_dir.path().join("Dockerfile");
    std::fs::write(
        &dockerfile_path,
        "# syntax=docker/dockerfile:1\nFROM scratch\nLABEL a=b\n",
    )
    .expect("write dockerfile");

    let output = run_build(
        runtime_dir.path(),
        context_dir.path(),
        &dockerfile_path,
        "local/parity:syntax",
        &[],
    );
    assert!(
        output.status.success(),
        "syntax directive build failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn dockerfile_build_platform_is_host_bound() {
    let host_arch = match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };
    let runtime_dir = tempfile::tempdir().expect("runtime dir");
    let context_dir = tempfile::tempdir().expect("context dir");
    let dockerfile_path = context_dir.path().join("Dockerfile");
    std::fs::write(context_dir.path().join("hello.txt"), "hello\n").expect("write context file");
    std::fs::write(&dockerfile_path, "FROM scratch\nLABEL a=b\n").expect("write dockerfile");

    let host_output = run_build(
        runtime_dir.path(),
        context_dir.path(),
        &dockerfile_path,
        "local/parity:platform-host",
        &[&format!("--platform=linux/{host_arch}")],
    );
    assert!(
        host_output.status.success(),
        "host platform build failed: stdout={} stderr={}",
        String::from_utf8_lossy(&host_output.stdout),
        String::from_utf8_lossy(&host_output.stderr)
    );

    let foreign_arch = if host_arch == "amd64" {
        "arm64"
    } else {
        "amd64"
    };
    let foreign_output = run_build(
        runtime_dir.path(),
        context_dir.path(),
        &dockerfile_path,
        "local/parity:platform-foreign",
        &[&format!("--platform=linux/{foreign_arch}")],
    );
    assert!(
        !foreign_output.status.success(),
        "foreign platform must fail closed"
    );
    let stderr = String::from_utf8_lossy(&foreign_output.stderr);
    assert!(
        stderr.contains("cross-platform") || stderr.contains("unsupported"),
        "foreign platform error must be explicit, got: {stderr}"
    );
}
