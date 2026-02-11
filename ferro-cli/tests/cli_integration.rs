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
    let status = cmd.arg("logs").status().expect("run ferro-cli");
    assert!(!status.success());
}

#[test]
fn pull_rejects_invalid_image() {
    let (mut cmd, _temp) = bin();
    let status = cmd.args(["pull", ""]).status().expect("run ferro-cli");
    assert!(!status.success());
}
