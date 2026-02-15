use std::process::Command;

fn bin() -> (Command, tempfile::TempDir) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ferro-cli"));
    let temp = tempfile::tempdir().expect("tempdir");
    cmd.env("FERROCRATE_RUNTIME_DIR", temp.path());
    (cmd, temp)
}

#[test]
fn images_command_succeeds() {
    let (mut cmd, _temp) = bin();
    let status = cmd.arg("images").status().expect("run ferro-cli");
    assert!(status.success());
}

#[test]
fn containers_command_succeeds() {
    let (mut cmd, _temp) = bin();
    let status = cmd.arg("containers").status().expect("run ferro-cli");
    assert!(status.success());
}

#[test]
fn logs_requires_container() {
    let (mut cmd, _temp) = bin();
    let output = cmd.arg("logs").output().expect("run ferro-cli");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("required arguments were not provided"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn pull_rejects_invalid_image() {
    let (mut cmd, _temp) = bin();
    let output = cmd.args(["pull", ""]).output().expect("run ferro-cli");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid image reference"),
        "unexpected stderr: {stderr}"
    );
}
