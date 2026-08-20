#![cfg(target_os = "linux")]

use std::io::Cursor;
use std::process::Command;

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
