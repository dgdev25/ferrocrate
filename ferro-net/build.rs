#[cfg(target_os = "linux")]
use std::{env, ffi::OsString, fs, path::PathBuf, process::Command};

#[cfg(target_os = "linux")]
use aya_build::{build_ebpf, Package, Toolchain};

#[cfg(target_os = "linux")]
const BPF_TOOLCHAIN: &str = "nightly-2026-02-11";
#[cfg(target_os = "linux")]
const BPF_LINKER_VERSION: &str = "0.10.4";
#[cfg(target_os = "linux")]
const BPF_PACKAGE: &str = "ferro-net-ebpf";
#[cfg(target_os = "linux")]
const SECURITY_BPF_PACKAGE: &str = "ferro-security-ebpf";
#[cfg(target_os = "linux")]
const BPF_INPUTS: &[&str] = &[
    "../ferro-net-ebpf/Cargo.toml",
    "../ferro-net-ebpf/src",
    "../ferro-net-ebpf/src/main.rs",
    "../ferro-net-ebpf/src/abi.rs",
];
#[cfg(target_os = "linux")]
const SECURITY_BPF_INPUTS: &[&str] = &[
    "../ferro-security-ebpf/Cargo.toml",
    "../ferro-security-ebpf/src",
    "../ferro-security-ebpf/src/main.rs",
];
#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn main() {
    // `build.rs` itself runs for the host, so a host-side cfg(target_os) is
    // not the package target. Avoid compiling the Linux eBPF payload when the
    // crate is being cross-checked for Windows or macOS.
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    emit_rebuild_contract();
    reject_skipped_build();
    require_bpf_toolchain();
    require_bpf_linker();

    // aya-build forwards nested Cargo stderr as cargo warnings, so silence progress output only.
    env::set_var("CARGO_TERM_QUIET", "true");

    build_ebpf(
        [
            Package {
                name: BPF_PACKAGE,
                root_dir: "../ferro-net-ebpf",
                features: &["bpf"],
                ..Package::default()
            },
            Package {
                name: SECURITY_BPF_PACKAGE,
                root_dir: "../ferro-security-ebpf",
                features: &["bpf"],
                ..Package::default()
            },
        ],
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

    let security_object = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR must be set"))
        .join(SECURITY_BPF_PACKAGE);
    let security_metadata = fs::metadata(&security_object).unwrap_or_else(|error| {
        panic!(
            "aya-build did not produce the expected security eBPF object {}: {error}",
            security_object.display()
        )
    });
    assert!(
        security_metadata.is_file() && security_metadata.len() > 0,
        "aya-build produced an invalid security eBPF object at {}",
        security_object.display()
    );
    println!(
        "cargo:rustc-env=FERRO_SECURITY_EBPF_OBJECT={}",
        security_object.display()
    );
}

#[cfg(not(target_os = "linux"))]
fn main() {
    // The eBPF object is a Linux-only implementation detail. Non-Linux builds
    // use the explicit unsupported backend in ebpf_non_linux.rs and must not
    // require a Linux BPF toolchain or attempt to run a build script for it.
}

#[cfg(target_os = "linux")]
fn emit_rebuild_contract() {
    for input in BPF_INPUTS {
        println!("cargo:rerun-if-changed={input}");
    }
    for input in SECURITY_BPF_INPUTS {
        println!("cargo:rerun-if-changed={input}");
    }
    for variable in BPF_ENVIRONMENT {
        println!("cargo:rerun-if-env-changed={variable}");
    }
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn reject_skipped_build() {
    let skip = env::var("AYA_BUILD_SKIP").unwrap_or_default();
    assert!(
        skip != "1" && !skip.eq_ignore_ascii_case("true"),
        "AYA_BUILD_SKIP cannot be used for ferro-net; a real eBPF object is required"
    );
}

#[cfg(target_os = "linux")]
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

    // FU-001: `rustup component list` takes the rustup lock, so every build of
    // this crate blocked (and sometimes failed) while another cargo or rustup
    // process held it. Rustup records installed components in a plain text file
    // inside the toolchain, one name per line — the same list the command
    // prints. Read that first; only shell out when the file cannot be read, so
    // an unusual rustup layout still works.
    if !bpf_toolchain_has_rust_src_on_disk() {
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
}

/// Read the toolchain's own component list from disk. Returns false when the
/// file is absent or unreadable, which sends the caller to the rustup command.
#[cfg(target_os = "linux")]
fn bpf_toolchain_has_rust_src_on_disk() -> bool {
    let rustup_home = env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|home| PathBuf::from(home).join(".rustup")));
    let Some(rustup_home) = rustup_home else {
        return false;
    };
    // The toolchain directory carries the host triple; the build script is given
    // it as HOST. Fall back to a prefix match when HOST is not set.
    let toolchains = rustup_home.join("toolchains");
    let candidate = match env::var("HOST") {
        Ok(host) => toolchains.join(format!("{BPF_TOOLCHAIN}-{host}")),
        Err(_) => match fs::read_dir(&toolchains) {
            Ok(entries) => {
                let prefix = format!("{BPF_TOOLCHAIN}-");
                match entries
                    .filter_map(Result::ok)
                    .find(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
                {
                    Some(entry) => entry.path(),
                    None => return false,
                }
            }
            Err(_) => return false,
        },
    };
    match fs::read_to_string(candidate.join("lib/rustlib/components")) {
        Ok(components) => components.lines().any(|line| line.trim() == "rust-src"),
        Err(_) => false,
    }
}

#[cfg(target_os = "linux")]
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
