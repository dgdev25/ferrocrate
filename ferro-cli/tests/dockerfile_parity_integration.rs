#![cfg(target_os = "linux")]

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
        .args(["build", "--tag", tag])
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
