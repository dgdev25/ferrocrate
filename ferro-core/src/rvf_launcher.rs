//! RVF image launcher: native vs QEMU selection and bounded QEMU execution.
//!
//! The native launcher is the normal container path: `ferro run image.rvf`
//! validates the image, imports it into the local OCI store, and executes it
//! through the rootless runtime. The QEMU launcher covers foreign-architecture
//! RVF images (for example an `aarch64` image on an `x86_64` host) by booting
//! the embedded `SEG_KERNEL` under emulation.
//!
//! Security properties:
//!
//! - Images are fully validated (`read_rvf_image`: manifest, layer size,
//!   layer digest) before any launch decision or boot.
//! - The QEMU invocation is a fixed argv vector. Every element is passed to
//!   `Command::arg` separately; no shell is involved, so kernel paths with
//!   commas, spaces, or quotes cannot inject QEMU options.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::rvf_image::{FerroImageManifest, RvfImage, SEG_KERNEL};

/// Minimum guest memory accepted for a QEMU launch, in MiB.
pub const QEMU_MEMORY_MIN_MIB: u32 = 16;
/// Maximum guest memory accepted for a QEMU launch, in MiB.
pub const QEMU_MEMORY_MAX_MIB: u32 = 2048;
/// Default guest memory for a QEMU launch, in MiB.
pub const QEMU_MEMORY_DEFAULT_MIB: u32 = 256;
/// Maximum wall-clock time `run_qemu_bounded` will keep a VM alive.
pub const QEMU_TIMEOUT_MAX_SECS: u64 = 300;
/// Guest architectures the QEMU launcher knows how to boot.
pub const QEMU_SUPPORTED_ARCHES: [&str; 2] = ["x86_64", "aarch64"];

/// Poll interval used by the bounded QEMU supervisor loop.
const QEMU_POLL_INTERVAL: Duration = Duration::from_millis(50);

// ── Launcher selection ────────────────────────────────────────────────────────

/// Execution backend for an RVF image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LauncherKind {
    /// Rootless native container execution (`ferro run image.rvf`).
    Native,
    /// QEMU VM boot of the embedded `SEG_KERNEL`.
    Qemu,
}

/// Caller preference for the launcher, applied after image validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LauncherPreference {
    /// Native when the image matches the host, QEMU otherwise.
    Auto,
    /// Force native execution; fails closed on architecture mismatch.
    Native,
    /// Force QEMU execution, even on a matching host.
    Qemu,
}

/// Errors produced by launcher selection, planning, and execution.
#[derive(Debug, Error)]
pub enum RvfLaunchError {
    #[error("unsupported guest os: {0} (only linux images can launch)")]
    UnsupportedGuestOs(String),
    #[error("unsupported guest arch: {0} (supported: x86_64/amd64, aarch64/arm64)")]
    UnsupportedGuestArch(String),
    #[error(
        "native launch requires arch {image_arch}, host is {host_arch}; use the qemu launcher"
    )]
    NativeArchMismatch {
        image_arch: String,
        host_arch: String,
    },
    #[error("native launch requires a linux host, host is {0}")]
    NativeHostUnsupported(String),
    #[error("qemu launch requires a non-empty kernel segment (type 0x0e)")]
    KernelSegmentMissing,
    #[error(
        "memory {0} MiB outside allowed range {QEMU_MEMORY_MIN_MIB}-{QEMU_MEMORY_MAX_MIB} MiB"
    )]
    MemoryOutOfRange(u32),
    #[error("timeout {0}s outside allowed range 1-{QEMU_TIMEOUT_MAX_SECS}s")]
    TimeoutOutOfRange(u64),
    #[error("qemu binary not found in PATH: {0}")]
    QemuBinaryNotFound(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Canonical guest architecture, accepting both Rust triple names
/// (`x86_64`, `aarch64`) and OCI/Go names (`amd64`, `arm64`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestArch {
    X86_64,
    Aarch64,
}

impl GuestArch {
    /// Normalise an architecture string from an RVF manifest or host probe.
    pub fn parse(arch: &str) -> Option<GuestArch> {
        match arch {
            "x86_64" | "amd64" => Some(GuestArch::X86_64),
            "aarch64" | "arm64" => Some(GuestArch::Aarch64),
            _ => None,
        }
    }

    /// Return the QEMU system binary for this architecture.
    pub fn qemu_binary(self) -> &'static str {
        match self {
            GuestArch::X86_64 => "qemu-system-x86_64",
            GuestArch::Aarch64 => "qemu-system-aarch64",
        }
    }
}

/// Return the QEMU system binary for a guest architecture, if known.
pub fn qemu_binary_for_arch(arch: &str) -> Option<&'static str> {
    GuestArch::parse(arch).map(GuestArch::qemu_binary)
}

/// Validate the guest platform fields of a manifest.
///
/// Fails closed on any os other than `linux` and any arch outside
/// [`QEMU_SUPPORTED_ARCHES`]; the native runtime and both QEMU machine types
/// only cover these platforms today.
fn validate_guest_platform(manifest: &FerroImageManifest) -> Result<GuestArch, RvfLaunchError> {
    if manifest.os != "linux" {
        return Err(RvfLaunchError::UnsupportedGuestOs(manifest.os.clone()));
    }
    GuestArch::parse(&manifest.arch)
        .ok_or_else(|| RvfLaunchError::UnsupportedGuestArch(manifest.arch.clone()))
}

/// Choose the launcher for a validated manifest.
///
/// `Auto` picks native when the image architecture matches the host and the
/// host runs Linux; otherwise QEMU. Explicit preferences that cannot be
/// satisfied fail closed instead of falling back.
pub fn select_launcher(
    manifest: &FerroImageManifest,
    host_arch: &str,
    host_os: &str,
    preference: LauncherPreference,
) -> Result<LauncherKind, RvfLaunchError> {
    let guest_arch = validate_guest_platform(manifest)?;
    let host_guest_arch = GuestArch::parse(host_arch)
        .ok_or_else(|| RvfLaunchError::UnsupportedGuestArch(host_arch.to_string()))?;
    let native_possible = host_os == "linux" && guest_arch == host_guest_arch;
    match preference {
        LauncherPreference::Auto => {
            if native_possible {
                Ok(LauncherKind::Native)
            } else {
                Ok(LauncherKind::Qemu)
            }
        }
        LauncherPreference::Native => {
            if host_os != "linux" {
                return Err(RvfLaunchError::NativeHostUnsupported(host_os.to_string()));
            }
            if !native_possible {
                return Err(RvfLaunchError::NativeArchMismatch {
                    image_arch: manifest.arch.clone(),
                    host_arch: host_arch.to_string(),
                });
            }
            Ok(LauncherKind::Native)
        }
        LauncherPreference::Qemu => Ok(LauncherKind::Qemu),
    }
}

// ── Kernel extraction ─────────────────────────────────────────────────────────

/// Extract the `SEG_KERNEL` payload of a validated RVF image atomically.
///
/// The destination is written to a temporary sibling, synced, then renamed.
pub fn extract_kernel(image: &RvfImage, output_path: &Path) -> Result<u64, RvfLaunchError> {
    let kernel = image
        .segments
        .iter()
        .find(|segment| segment.seg_type == SEG_KERNEL)
        .ok_or(RvfLaunchError::KernelSegmentMissing)?;
    if kernel.payload.is_empty() {
        return Err(RvfLaunchError::KernelSegmentMissing);
    }

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = output_path.with_extension("rvf-kernel.tmp");
    {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(&kernel.payload)?;
        file.sync_all()?;
    }
    std::fs::rename(&temporary, output_path)?;
    Ok(kernel.payload.len() as u64)
}

// ── QEMU planning ─────────────────────────────────────────────────────────────

/// Where QEMU serial output is directed.
#[derive(Debug, Clone)]
pub enum SerialOutput {
    /// Inherit the caller's stdio (`-serial stdio`).
    Stdio,
    /// Write serial output to a file (`-serial file:<path>`).
    File(PathBuf),
}

impl SerialOutput {
    fn qemu_arg(&self) -> String {
        match self {
            SerialOutput::Stdio => "stdio".to_string(),
            SerialOutput::File(path) => format!("file:{}", path.display()),
        }
    }
}

/// Kernel command line per architecture: serial console plus `panic=-1` so a
/// panicking guest exits immediately instead of hanging.
fn kernel_append_for_arch(arch: GuestArch) -> &'static str {
    match arch {
        GuestArch::Aarch64 => "console=ttyAMA0 panic=-1",
        GuestArch::X86_64 => "console=ttyS0 panic=-1",
    }
}

fn qemu_machine_for_arch(arch: GuestArch) -> &'static str {
    match arch {
        GuestArch::Aarch64 => "virt",
        GuestArch::X86_64 => "q35",
    }
}

/// A ready-to-execute QEMU launch plan for a validated RVF image.
#[derive(Debug, Clone)]
pub struct QemuLaunchPlan {
    /// QEMU binary name (resolved through `PATH` at execution time).
    pub binary: String,
    /// Full argv including the binary as element zero.
    pub argv: Vec<String>,
    /// Guest memory in MiB.
    pub memory_mib: u32,
    /// Timeout the caller should pass to `run_qemu_bounded`.
    pub timeout: Duration,
}

/// Build the QEMU launch plan for a validated image.
///
/// `kernel_path` must already hold the extracted `SEG_KERNEL` payload (see
/// [`extract_kernel`]); the path is embedded as a single argv element, so its
/// contents can never be parsed as extra QEMU options.
///
/// `memory_mib` fails closed outside
/// [`QEMU_MEMORY_MIN_MIB`]..[`QEMU_MEMORY_MAX_MIB`]; `timeout_secs` fails
/// closed outside `1..=QEMU_TIMEOUT_MAX_SECS`.
#[allow(clippy::result_large_err)]
pub fn plan_qemu_launch(
    image: &RvfImage,
    kernel_path: &Path,
    memory_mib: u32,
    timeout_secs: u64,
    serial: &SerialOutput,
) -> Result<QemuLaunchPlan, RvfLaunchError> {
    validate_guest_platform(&image.manifest)?;
    let guest_arch =
        GuestArch::parse(&image.manifest.arch).expect("validated arch always maps to a GuestArch");
    let binary = guest_arch.qemu_binary();
    if !(QEMU_MEMORY_MIN_MIB..=QEMU_MEMORY_MAX_MIB).contains(&memory_mib) {
        return Err(RvfLaunchError::MemoryOutOfRange(memory_mib));
    }
    if timeout_secs == 0 || timeout_secs > QEMU_TIMEOUT_MAX_SECS {
        return Err(RvfLaunchError::TimeoutOutOfRange(timeout_secs));
    }
    let kernel_segment = image
        .segments
        .iter()
        .find(|segment| segment.seg_type == SEG_KERNEL);
    match kernel_segment {
        Some(segment) if !segment.payload.is_empty() => {}
        _ => return Err(RvfLaunchError::KernelSegmentMissing),
    }

    let argv = vec![
        binary.to_string(),
        "-machine".to_string(),
        qemu_machine_for_arch(guest_arch).to_string(),
        "-accel".to_string(),
        "tcg".to_string(),
        "-m".to_string(),
        format!("{memory_mib}M"),
        "-kernel".to_string(),
        kernel_path.display().to_string(),
        "-append".to_string(),
        kernel_append_for_arch(guest_arch).to_string(),
        "-display".to_string(),
        "none".to_string(),
        "-no-reboot".to_string(),
        "-monitor".to_string(),
        "none".to_string(),
        "-serial".to_string(),
        serial.qemu_arg(),
    ];

    Ok(QemuLaunchPlan {
        binary: binary.to_string(),
        argv,
        memory_mib,
        timeout: Duration::from_secs(timeout_secs),
    })
}

// ── Bounded execution ─────────────────────────────────────────────────────────

/// Result of a bounded QEMU run.
#[derive(Debug)]
pub struct QemuRunOutcome {
    /// Exit status of the child, when it exited on its own or after kill.
    pub status: std::process::ExitStatus,
    /// `true` when the supervisor killed the VM at the deadline.
    pub timed_out: bool,
}

/// Locate `binary` in `PATH`.
fn find_in_path(binary: &str) -> Option<PathBuf> {
    if binary.contains('/') {
        return Some(PathBuf::from(binary));
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(binary))
        .find(|candidate| candidate.is_file())
}

/// Run a QEMU launch plan under a hard wall-clock deadline.
///
/// The child is spawned with each argv element passed separately (no shell).
/// If it has not exited by `plan.timeout`, it is killed and reaped. The
/// function always returns within `timeout + a small grace period`.
pub fn run_qemu_bounded(
    plan: &QemuLaunchPlan,
    stdin_null: bool,
) -> Result<QemuRunOutcome, RvfLaunchError> {
    if find_in_path(&plan.binary).is_none() {
        return Err(RvfLaunchError::QemuBinaryNotFound(plan.binary.clone()));
    }

    let mut command = Command::new(&plan.binary);
    command
        .args(&plan.argv[1..])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if stdin_null {
        command.stdin(Stdio::null());
    } else {
        command.stdin(Stdio::inherit());
    }

    let deadline = Instant::now() + plan.timeout;
    let mut child = command.spawn()?;
    loop {
        match child.try_wait()? {
            Some(status) => {
                return Ok(QemuRunOutcome {
                    status,
                    timed_out: false,
                })
            }
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let status = child.wait()?;
                    return Ok(QemuRunOutcome {
                        status,
                        timed_out: true,
                    });
                }
                std::thread::sleep(QEMU_POLL_INTERVAL);
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rvf_image::{FerroImageManifest, RvfSegment, SEG_KERNEL, SEG_LAYER, SEG_MANIFEST};
    use sha2::Digest;

    fn manifest(arch: &str, os: &str) -> FerroImageManifest {
        FerroImageManifest {
            name: "boot".into(),
            tag: "latest".into(),
            entrypoint: vec![],
            cmd: vec![],
            env: vec![],
            arch: arch.into(),
            os: os.into(),
            created_at: "0".into(),
            format_version: 1,
            layer_digest: "sha256:00".into(),
            layer_size: 0,
            overlay_model_type: None,
        }
    }

    fn image_with_kernel(arch: &str, os: &str) -> RvfImage {
        RvfImage {
            manifest: manifest(arch, os),
            segments: vec![
                RvfSegment {
                    seg_type: SEG_KERNEL,
                    payload: b"ELF-kernel-bytes".to_vec(),
                },
                RvfSegment {
                    seg_type: SEG_LAYER,
                    payload: vec![],
                },
            ],
        }
    }

    #[test]
    fn auto_selects_native_on_matching_linux_host() {
        let kind = select_launcher(
            &manifest("x86_64", "linux"),
            "x86_64",
            "linux",
            LauncherPreference::Auto,
        )
        .unwrap();
        assert_eq!(kind, LauncherKind::Native);
    }

    /// RVF manifests carry OCI arch names (amd64/arm64) while host probes may
    /// use Rust triples (x86_64/aarch64); both must interoperate.
    #[test]
    fn oci_and_rust_arch_names_interoperate() {
        for (image_arch, host_arch) in [("amd64", "x86_64"), ("x86_64", "amd64")] {
            let kind = select_launcher(
                &manifest(image_arch, "linux"),
                host_arch,
                "linux",
                LauncherPreference::Auto,
            )
            .unwrap();
            assert_eq!(kind, LauncherKind::Native, "{image_arch} vs {host_arch}");
        }
        for (image_arch, host_arch) in [("arm64", "x86_64"), ("aarch64", "amd64")] {
            let kind = select_launcher(
                &manifest(image_arch, "linux"),
                host_arch,
                "linux",
                LauncherPreference::Auto,
            )
            .unwrap();
            assert_eq!(kind, LauncherKind::Qemu, "{image_arch} vs {host_arch}");
        }
        // amd64 image plans the x86_64 QEMU binary.
        let image = image_with_kernel("amd64", "linux");
        let plan =
            plan_qemu_launch(&image, Path::new("/tmp/k"), 64, 5, &SerialOutput::Stdio).unwrap();
        assert_eq!(plan.binary, "qemu-system-x86_64");
        assert!(plan.argv.contains(&"console=ttyS0 panic=-1".to_string()));
    }

    #[test]
    fn auto_selects_qemu_on_architecture_mismatch() {
        let kind = select_launcher(
            &manifest("aarch64", "linux"),
            "x86_64",
            "linux",
            LauncherPreference::Auto,
        )
        .unwrap();
        assert_eq!(kind, LauncherKind::Qemu);
    }

    #[test]
    fn auto_selects_qemu_on_non_linux_host() {
        let kind = select_launcher(
            &manifest("x86_64", "linux"),
            "x86_64",
            "darwin",
            LauncherPreference::Auto,
        )
        .unwrap();
        assert_eq!(kind, LauncherKind::Qemu);
    }

    #[test]
    fn forced_native_on_mismatch_fails_closed() {
        let error = select_launcher(
            &manifest("aarch64", "linux"),
            "x86_64",
            "linux",
            LauncherPreference::Native,
        )
        .unwrap_err();
        assert!(matches!(error, RvfLaunchError::NativeArchMismatch { .. }));
    }

    #[test]
    fn forced_native_on_non_linux_host_fails_closed() {
        let error = select_launcher(
            &manifest("x86_64", "linux"),
            "x86_64",
            "darwin",
            LauncherPreference::Native,
        )
        .unwrap_err();
        assert!(matches!(error, RvfLaunchError::NativeHostUnsupported(_)));
    }

    #[test]
    fn forced_qemu_is_always_allowed() {
        let kind = select_launcher(
            &manifest("x86_64", "linux"),
            "x86_64",
            "linux",
            LauncherPreference::Qemu,
        )
        .unwrap();
        assert_eq!(kind, LauncherKind::Qemu);
    }

    #[test]
    fn non_linux_guest_os_fails_closed() {
        let error = select_launcher(
            &manifest("x86_64", "windows"),
            "x86_64",
            "linux",
            LauncherPreference::Auto,
        )
        .unwrap_err();
        assert!(matches!(error, RvfLaunchError::UnsupportedGuestOs(_)));
    }

    #[test]
    fn unknown_guest_arch_fails_closed() {
        let error = select_launcher(
            &manifest("riscv64", "linux"),
            "x86_64",
            "linux",
            LauncherPreference::Auto,
        )
        .unwrap_err();
        assert!(matches!(error, RvfLaunchError::UnsupportedGuestArch(_)));
    }

    #[test]
    fn plan_builds_fixed_argv_for_x86_64() {
        let image = image_with_kernel("x86_64", "linux");
        let kernel = Path::new("/tmp/kernel.img");
        let plan = plan_qemu_launch(&image, kernel, 256, 30, &SerialOutput::Stdio).unwrap();
        assert_eq!(plan.binary, "qemu-system-x86_64");
        assert_eq!(plan.argv[0], "qemu-system-x86_64");
        assert_eq!(plan.argv[1], "-machine");
        assert_eq!(plan.argv[2], "q35");
        // Kernel path must be a single argv element.
        let kernel_index = plan
            .argv
            .iter()
            .position(|element| element == "-kernel")
            .unwrap();
        assert_eq!(plan.argv[kernel_index + 1], "/tmp/kernel.img");
        let append_index = plan
            .argv
            .iter()
            .position(|element| element == "-append")
            .unwrap();
        assert_eq!(plan.argv[append_index + 1], "console=ttyS0 panic=-1");
        assert_eq!(plan.timeout, Duration::from_secs(30));
    }

    #[test]
    fn plan_uses_virt_machine_and_ttyama0_for_aarch64() {
        let image = image_with_kernel("aarch64", "linux");
        let plan =
            plan_qemu_launch(&image, Path::new("/tmp/k"), 128, 10, &SerialOutput::Stdio).unwrap();
        assert_eq!(plan.binary, "qemu-system-aarch64");
        assert!(plan.argv.contains(&"virt".to_string()));
        assert!(plan.argv.contains(&"console=ttyAMA0 panic=-1".to_string()));
    }

    #[test]
    fn plan_keeps_hostile_kernel_path_as_single_argv_element() {
        let image = image_with_kernel("x86_64", "linux");
        // A path that would break option parsing if interpolated into an
        // option string: commas, spaces, and an embedded -drive option.
        let hostile = Path::new("/tmp/evil, name -drive file=/etc/shadow");
        let plan = plan_qemu_launch(&image, hostile, 256, 30, &SerialOutput::Stdio).unwrap();
        let kernel_index = plan
            .argv
            .iter()
            .position(|element| element == "-kernel")
            .unwrap();
        assert_eq!(plan.argv[kernel_index + 1], hostile.display().to_string());
        // The path must not be split across multiple argv elements.
        assert_eq!(plan.argv[kernel_index + 1].matches(',').count(), 1);
    }

    #[test]
    fn plan_requires_kernel_segment() {
        let mut image = image_with_kernel("x86_64", "linux");
        image
            .segments
            .retain(|segment| segment.seg_type != SEG_KERNEL);
        let error = plan_qemu_launch(&image, Path::new("/tmp/k"), 256, 30, &SerialOutput::Stdio)
            .unwrap_err();
        assert!(matches!(error, RvfLaunchError::KernelSegmentMissing));

        let mut empty = image_with_kernel("x86_64", "linux");
        empty.segments[0].payload.clear();
        let error = plan_qemu_launch(&empty, Path::new("/tmp/k"), 256, 30, &SerialOutput::Stdio)
            .unwrap_err();
        assert!(matches!(error, RvfLaunchError::KernelSegmentMissing));
    }

    #[test]
    fn plan_rejects_out_of_range_memory_and_timeout() {
        let image = image_with_kernel("x86_64", "linux");
        for bad_memory in [0, QEMU_MEMORY_MIN_MIB - 1, QEMU_MEMORY_MAX_MIB + 1] {
            let error = plan_qemu_launch(
                &image,
                Path::new("/tmp/k"),
                bad_memory,
                30,
                &SerialOutput::Stdio,
            )
            .unwrap_err();
            assert!(matches!(error, RvfLaunchError::MemoryOutOfRange(_)));
        }
        for bad_timeout in [0, QEMU_TIMEOUT_MAX_SECS + 1] {
            let error = plan_qemu_launch(
                &image,
                Path::new("/tmp/k"),
                256,
                bad_timeout,
                &SerialOutput::Stdio,
            )
            .unwrap_err();
            assert!(matches!(error, RvfLaunchError::TimeoutOutOfRange(_)));
        }
    }

    #[test]
    fn serial_file_argument_is_a_single_element() {
        let image = image_with_kernel("x86_64", "linux");
        let serial = SerialOutput::File(PathBuf::from("/tmp/serial, out.log"));
        let plan = plan_qemu_launch(&image, Path::new("/tmp/k"), 256, 30, &serial).unwrap();
        let serial_index = plan
            .argv
            .iter()
            .position(|element| element == "-serial")
            .unwrap();
        assert_eq!(plan.argv[serial_index + 1], "file:/tmp/serial, out.log");
    }

    #[test]
    fn extract_kernel_writes_payload_atomically() {
        let temp = tempfile::tempdir().unwrap();
        let image = image_with_kernel("x86_64", "linux");
        let output = temp.path().join("boot/vmlinuz");
        let size = extract_kernel(&image, &output).unwrap();
        assert_eq!(size, b"ELF-kernel-bytes".len() as u64);
        assert_eq!(std::fs::read(&output).unwrap(), b"ELF-kernel-bytes");
        assert!(!temp.path().join("boot/vmlinuz.rvf-kernel.tmp").exists());
    }

    #[test]
    fn extract_kernel_without_segment_fails() {
        let temp = tempfile::tempdir().unwrap();
        let mut image = image_with_kernel("x86_64", "linux");
        image
            .segments
            .retain(|segment| segment.seg_type != SEG_KERNEL);
        let error = extract_kernel(&image, &temp.path().join("k")).unwrap_err();
        assert!(matches!(error, RvfLaunchError::KernelSegmentMissing));
    }

    /// The bounded supervisor kills a process that outlives the deadline.
    /// Uses a fabricated `sleep` plan so the test needs no QEMU install.
    #[test]
    fn bounded_run_kills_at_deadline() {
        let plan = QemuLaunchPlan {
            binary: "sleep".to_string(),
            argv: vec!["sleep".to_string(), "30".to_string()],
            memory_mib: QEMU_MEMORY_DEFAULT_MIB,
            timeout: Duration::from_millis(300),
        };
        let started = Instant::now();
        let outcome = run_qemu_bounded(&plan, true).unwrap();
        assert!(outcome.timed_out);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// The bounded supervisor returns promptly when the child exits first.
    #[test]
    fn bounded_run_returns_child_exit() {
        let plan = QemuLaunchPlan {
            binary: "true".to_string(),
            argv: vec!["true".to_string()],
            memory_mib: QEMU_MEMORY_DEFAULT_MIB,
            timeout: Duration::from_secs(5),
        };
        let outcome = run_qemu_bounded(&plan, true).unwrap();
        assert!(!outcome.timed_out);
        assert!(outcome.status.success());
    }

    #[test]
    fn bounded_run_fails_closed_on_missing_binary() {
        let plan = QemuLaunchPlan {
            binary: "qemu-system-definitely-not-installed-xyz".to_string(),
            argv: vec!["qemu-system-definitely-not-installed-xyz".to_string()],
            memory_mib: QEMU_MEMORY_DEFAULT_MIB,
            timeout: Duration::from_secs(1),
        };
        let error = run_qemu_bounded(&plan, true).unwrap_err();
        assert!(matches!(error, RvfLaunchError::QemuBinaryNotFound(_)));
    }

    /// End-to-end fixture: validate a full RVF file with kernel, then plan.
    #[test]
    fn validated_file_plans_end_to_end() {
        let temp = tempfile::tempdir().unwrap();
        let kernel_bytes = b"fake-kernel-elf".to_vec();
        let layer = b"layer-tar".to_vec();
        let digest = format!("sha256:{:x}", sha2::Sha256::digest(&layer));
        let mut manifest = manifest("x86_64", "linux");
        manifest.layer_digest = digest;
        manifest.layer_size = layer.len() as u64;

        let image_path = temp.path().join("boot.rvf");
        let mut bytes = Vec::new();
        crate::rvf_image::write_rvf(
            &mut bytes,
            &[
                RvfSegment {
                    seg_type: SEG_MANIFEST,
                    payload: serde_json::to_vec(&manifest).unwrap(),
                },
                RvfSegment {
                    seg_type: SEG_LAYER,
                    payload: layer,
                },
                RvfSegment {
                    seg_type: SEG_KERNEL,
                    payload: kernel_bytes.clone(),
                },
            ],
        )
        .unwrap();
        std::fs::write(&image_path, bytes).unwrap();

        // Full validation including layer digest must pass first.
        let image = crate::rvf_image::read_rvf_image(&image_path).unwrap();
        let kernel_path = temp.path().join("kernel");
        extract_kernel(&image, &kernel_path).unwrap();
        let plan = plan_qemu_launch(&image, &kernel_path, 64, 5, &SerialOutput::Stdio).unwrap();
        assert_eq!(plan.argv[0], "qemu-system-x86_64");
    }
}
