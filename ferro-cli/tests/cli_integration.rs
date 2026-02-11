use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ferro-cli"))
}

#[test]
fn images_command_succeeds() {
    let status = bin().arg("images").status().expect("run ferro-cli");
    assert!(status.success());
}

#[test]
fn containers_command_succeeds() {
    let status = bin().arg("containers").status().expect("run ferro-cli");
    assert!(status.success());
}

#[test]
fn logs_requires_container() {
    let status = bin().arg("logs").status().expect("run ferro-cli");
    assert!(!status.success());
}

#[test]
fn pull_rejects_invalid_image() {
    let status = bin().args(["pull", ""]).status().expect("run ferro-cli");
    assert!(!status.success());
}
