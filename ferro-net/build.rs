use std::{env, ffi::OsString, fs, path::PathBuf, process::Command};

use aya_build::{build_ebpf, Package, Toolchain};

const BPF_TOOLCHAIN: &str = "nightly-2026-02-11";
const BPF_LINKER_VERSION: &str = "0.10.4";
const BPF_PACKAGE: &str = "ferro-net-ebpf";
const BPF_INPUTS: &[&str] = &[
    "../ferro-net-ebpf/Cargo.toml",
    "../ferro-net-ebpf/src",
    "../ferro-net-ebpf/src/main.rs",
    "../ferro-net-ebpf/src/abi.rs",
];
const BPF_ENVIRONMENT: &[&str] = &[
    "AYA_BUILD_SKIP",
    "AYA_BPF_TARGET_ARCH",
    "BPF_LINKER",
    "CARGO_CFG_TARGET_ARCH",
    "CARGO_CFG_TARGET_ENDIAN",
    "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_HOME",
    "CARGO_TARGET_BPFEL_UNKNOWN_NONE_LINKER",
    "HOST",
    "PATH",
    "RUSTC",
    "RUSTC_BOOTSTRAP",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTFLAGS",
    "RUSTUP_HOME",
    "RUSTUP_TOOLCHAIN",
];

fn main() {
    emit_rebuild_contract();
    reject_skipped_build();
    require_bpf_toolchain();
    require_bpf_linker();

    build_ebpf(
        [Package {
            name: BPF_PACKAGE,
            root_dir: "../ferro-net-ebpf",
            features: &["bpf"],
            ..Package::default()
        }],
        Toolchain::Custom(BPF_TOOLCHAIN),
    )
    .unwrap_or_else(|error| {
        panic!(
            "failed to build {BPF_PACKAGE} for bpfel-unknown-none with {BPF_TOOLCHAIN}: \
             {error:#}. Repair the deterministic BPF toolchain with: \
             rustup toolchain install {BPF_TOOLCHAIN} --component rust-src"
        )
    });

    let object = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set by Cargo"))
        .join(BPF_PACKAGE);
    let metadata = fs::metadata(&object).unwrap_or_else(|error| {
        panic!(
            "aya-build did not produce the expected eBPF object {}: {error}",
            object.display()
        )
    });
    assert!(
        metadata.is_file() && metadata.len() > 0,
        "aya-build produced an invalid eBPF object at {}",
        object.display()
    );

    println!("cargo:rustc-env=FERRO_NET_EBPF_OBJECT={}", object.display());
}

fn emit_rebuild_contract() {
    for input in BPF_INPUTS {
        println!("cargo:rerun-if-changed={input}");
    }
    for variable in BPF_ENVIRONMENT {
        println!("cargo:rerun-if-env-changed={variable}");
    }
}

fn require_bpf_linker() {
    let output = Command::new("bpf-linker").arg("--version").output();
    let expected = format!("bpf-linker {BPF_LINKER_VERSION}");
    assert!(
        output.is_ok_and(|output| {
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == expected
        }),
        "bpf-linker {BPF_LINKER_VERSION} is required. Install the pinned linker with: \
         rustup run {BPF_TOOLCHAIN} cargo install bpf-linker \
         --version {BPF_LINKER_VERSION} --locked"
    );
}

fn reject_skipped_build() {
    let skip = env::var("AYA_BUILD_SKIP").unwrap_or_default();
    assert!(
        skip != "1" && !skip.eq_ignore_ascii_case("true"),
        "AYA_BUILD_SKIP cannot be used for ferro-net; a real eBPF object is required"
    );
}

fn require_bpf_toolchain() {
    let rustup = rustup_command();
    let rustup_version = Command::new(&rustup).arg("--version").output();
    assert!(
        rustup_version.is_ok_and(|output| output.status.success()),
        "rustup is required to build ferro-net's eBPF object. Install rustup, then run: \
         rustup toolchain install {BPF_TOOLCHAIN} --component rust-src"
    );

    if let Some(bin_dir) = rustup.parent().filter(|path| !path.as_os_str().is_empty()) {
        let mut paths = vec![bin_dir.to_path_buf()];
        paths.extend(env::split_paths(&env::var_os("PATH").unwrap_or_default()));
        let path = env::join_paths(paths).expect("rustup path must be valid");
        env::set_var("PATH", path);
    }

    let output = Command::new(&rustup)
        .args([
            "component",
            "list",
            "--toolchain",
            BPF_TOOLCHAIN,
            "--installed",
        ])
        .output()
        .unwrap_or_else(|error| panic!("failed to inspect {BPF_TOOLCHAIN}: {error}"));
    let components = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && components.lines().any(|line| line.starts_with("rust-src")),
        "the deterministic BPF toolchain is missing. Install it with: \
         rustup toolchain install {BPF_TOOLCHAIN} --component rust-src"
    );
}

fn rustup_command() -> PathBuf {
    if Command::new("rustup")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
    {
        return PathBuf::from("rustup");
    }

    let cargo_home = env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")));
    cargo_home
        .map(|home| home.join("bin").join("rustup"))
        .filter(|candidate| candidate.is_file())
        .unwrap_or_else(|| PathBuf::from(OsString::from("rustup")))
}
