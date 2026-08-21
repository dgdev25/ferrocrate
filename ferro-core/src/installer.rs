//! Rootless installer and upgrade flows.
//!
//! Every flow in this module is split into a pure decision/generation step
//! (`plan_*` / `generate_*`) and an execution step that only touches
//! caller-supplied paths. The module never writes `/etc/subuid`, `/etc/subgid`,
//! or the systemd hierarchy itself: subordinate-ID remediation is emitted as
//! exact `usermod` commands for the operator, and user services are generated
//! as unit text plus `systemctl --user` commands.

use crate::rootless::{first_subid_range_in, IdRange, RootlessError};
use ferro_net::rootless::RootlessNetConfig;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Default subordinate range start used by the remediation commands, matching
/// the messages emitted by `crate::rootless::subid_prerequisite_message`.
pub const DEFAULT_SUBID_START: u32 = 100_000;
/// Default subordinate range size (65536 IDs: 100000-165535).
pub const DEFAULT_SUBID_COUNT: u32 = 65_536;

/// Suffix for the deterministic binary backup written by [`execute_upgrade`].
pub const BACKUP_SUFFIX: &str = ".ferrocrate.previous";
/// Where [`execute_rollback`] parks a binary it replaces.
const FAILED_UPGRADE_SUFFIX: &str = ".failed-upgrade";

/// State entries FerroCrate owns inside its state directory. Uninstall only
/// removes a state directory whose every entry appears here.
pub const OWNED_STATE_ENTRIES: &[&str] = &[
    "containers",
    "images",
    "volumes",
    "community",
    "desktop-vm.json",
];

/// Host helper binaries the rootless flows depend on.
pub const ROOTLESS_HELPERS: &[&str] = &["newuidmap", "newgidmap", "slirp4netns", "bwrap"];

#[derive(Debug, Error)]
pub enum InstallerError {
    #[error("installer decisions require an absolute path; got {0}")]
    RelativePath(PathBuf),
    #[error("invalid user service unit name: {0}")]
    InvalidUnitName(String),
    #[error("generated-file field {field:?} must not contain newlines")]
    FieldNewline { field: &'static str },
    #[error("ExecStart must be an absolute path: {0}")]
    ExecStartNotAbsolute(PathBuf),
    #[error("upgrade refused: {0}")]
    UpgradeRefused(String),
    #[error("rollback refused: {0}")]
    RollbackRefused(String),
    #[error("refusing to remove state directory {dir}: it contains foreign entries {entries:?}")]
    ForeignStateData { dir: PathBuf, entries: Vec<PathBuf> },
    #[error("invalid subordinate id file: {0}")]
    SubId(#[from] RootlessError),
    #[error("invalid slirp configuration: {0}")]
    SlirpConfig(String),
    #[error("io error on {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

fn io_error(path: PathBuf) -> impl FnOnce(std::io::Error) -> InstallerError {
    move |source| InstallerError::Io { path, source }
}

fn require_absolute(path: &Path) -> Result<(), InstallerError> {
    if path.is_absolute() {
        Ok(())
    } else {
        Err(InstallerError::RelativePath(path.to_path_buf()))
    }
}

/// Reject newline injection into generated config and unit text.
fn reject_newlines(value: &str, field: &'static str) -> Result<(), InstallerError> {
    if value.contains('\n') || value.contains('\r') {
        Err(InstallerError::FieldNewline { field })
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// (a) Subordinate-ID / mapping helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubidReport {
    pub username: String,
    pub subuid: Option<IdRange>,
    pub subgid: Option<IdRange>,
}

impl SubidReport {
    pub fn complete(&self) -> bool {
        self.subuid.is_some() && self.subgid.is_some()
    }
}

/// Inspect subordinate-ID file contents for one user. `numeric_id` accepts the
/// UID or GID for `/etc/subuid`-style files keyed by numeric owner.
pub fn inspect_subid_contents(
    username: &str,
    numeric_id: u32,
    subuid: &str,
    subgid: &str,
) -> Result<SubidReport, InstallerError> {
    Ok(SubidReport {
        username: username.to_string(),
        subuid: first_subid_range_in(subuid, username, numeric_id)?,
        subgid: first_subid_range_in(subgid, username, numeric_id)?,
    })
}

/// Exact remediation commands for the missing subordinate ranges. Empty when
/// both ranges exist. The module never applies these itself.
pub fn subid_remediation_commands(report: &SubidReport) -> Vec<String> {
    let mut commands = Vec::new();
    let end = DEFAULT_SUBID_START + DEFAULT_SUBID_COUNT - 1;
    if report.subuid.is_none() {
        commands.push(format!(
            "sudo usermod --add-subuids {DEFAULT_SUBID_START}-{end} {}",
            report.username
        ));
    }
    if report.subgid.is_none() {
        commands.push(format!(
            "sudo usermod --add-subgids {DEFAULT_SUBID_START}-{end} {}",
            report.username
        ));
    }
    commands
}

/// Operator-facing instructions for the missing subordinate ranges, naming the
/// files to update and the consequence of skipping the fix.
pub fn subid_fix_instructions(report: &SubidReport) -> String {
    if report.complete() {
        return format!(
            "subordinate ID ranges for {} are present in /etc/subuid and /etc/subgid",
            report.username
        );
    }
    let mut lines = vec![format!(
        "FerroCrate will not edit /etc/subuid or /etc/subgid. Run these commands as root:"
    )];
    lines.extend(subid_remediation_commands(report));
    lines.push(
        "without subordinate ranges rootless containers fall back to a single-ID mapping, \
         which cannot chown files or run multi-user workloads"
            .to_string(),
    );
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// (b) Cgroup delegation
// ---------------------------------------------------------------------------

/// Exact remediation commands for undelegated cgroup v2 controllers.
pub fn cgroup_delegation_commands() -> Vec<String> {
    vec![
        "sudo loginctl enable-linger $USER".to_string(),
        "sudo systemctl set-property user-$(id -u).slice Delegate=yes".to_string(),
    ]
}

/// Probe one cgroup subtree root (or the process's own when `None` delegates
/// to `crate::rootless::cgroup_delegation_diagnostic`).
pub fn cgroup_delegation_check(root: Option<&Path>) -> Result<(), String> {
    match root {
        Some(path) => crate::rootless::cgroup_delegation_probe(path),
        None => crate::rootless::cgroup_delegation_diagnostic(),
    }
}

// ---------------------------------------------------------------------------
// (c) User-level systemd service units
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserServiceSpec {
    /// Unit name without the `.service` suffix, e.g. `ferrocrate-agent`.
    pub unit_name: String,
    pub description: String,
    /// Absolute path of the binary the service runs.
    pub exec_start: PathBuf,
    /// Optional absolute `EnvironmentFile=` target.
    pub environment_file: Option<PathBuf>,
}

fn validate_user_service_spec(spec: &UserServiceSpec) -> Result<(), InstallerError> {
    if spec.unit_name.is_empty()
        || !spec
            .unit_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '_' | '.' | '-'))
        || spec.unit_name.starts_with('.')
    {
        return Err(InstallerError::InvalidUnitName(spec.unit_name.clone()));
    }
    reject_newlines(&spec.description, "Description")?;
    if !spec.exec_start.is_absolute() {
        return Err(InstallerError::ExecStartNotAbsolute(
            spec.exec_start.clone(),
        ));
    }
    if let Some(file) = &spec.environment_file {
        require_absolute(file)?;
    }
    Ok(())
}

/// Generate a user-level systemd unit. The unit targets `systemctl --user`
/// semantics: no `User=` directive, `WantedBy=default.target`.
pub fn generate_user_service_unit(spec: &UserServiceSpec) -> Result<String, InstallerError> {
    validate_user_service_spec(spec)?;
    let mut unit = String::new();
    unit.push_str("[Unit]\n");
    unit.push_str(&format!("Description={}\n", spec.description));
    unit.push('\n');
    unit.push_str("[Service]\n");
    unit.push_str("Type=simple\n");
    if let Some(file) = &spec.environment_file {
        unit.push_str(&format!("EnvironmentFile={}\n", file.display()));
    }
    unit.push_str(&format!("ExecStart={}\n", spec.exec_start.display()));
    unit.push_str("Restart=on-failure\n");
    unit.push_str("RestartSec=2\n");
    unit.push('\n');
    unit.push_str("[Install]\n");
    unit.push_str("WantedBy=default.target\n");
    Ok(unit)
}

/// Install path of the unit under the user systemd directory.
pub fn user_unit_install_path(config_home: &Path, spec: &UserServiceSpec) -> PathBuf {
    config_home
        .join("systemd")
        .join("user")
        .join(format!("{}.service", spec.unit_name))
}

/// Commands that install and start the unit without root.
pub fn user_service_enable_commands(spec: &UserServiceSpec) -> Result<Vec<String>, InstallerError> {
    validate_user_service_spec(spec)?;
    Ok(vec![
        "systemctl --user daemon-reload".to_string(),
        format!("systemctl --user enable --now {}.service", spec.unit_name),
    ])
}

/// Commands that stop and disable the unit without root.
pub fn user_service_disable_commands(
    spec: &UserServiceSpec,
) -> Result<Vec<String>, InstallerError> {
    validate_user_service_spec(spec)?;
    Ok(vec![
        format!("systemctl --user disable --now {}.service", spec.unit_name),
        "systemctl --user daemon-reload".to_string(),
    ])
}

// ---------------------------------------------------------------------------
// (d) slirp4netns configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlirpSetup {
    pub tap_name: String,
    pub cidr: String,
    pub enable_ipv6: bool,
    pub outbound_addr6: Option<String>,
    /// Absolute path of the slirp4netns API socket.
    pub api_socket: PathBuf,
}

/// Generate the environment file content that captures the slirp4netns
/// settings for a rootless installation. Validation reuses the runtime's
/// `RootlessNetConfig` checks so installer and runtime cannot drift.
pub fn generate_slirp_environment(setup: &SlirpSetup) -> Result<String, InstallerError> {
    let config = RootlessNetConfig {
        tap_name: setup.tap_name.clone(),
        cidr: setup.cidr.clone(),
        enable_ipv6: setup.enable_ipv6,
        outbound_addr6: setup.outbound_addr6.clone(),
        api_socket: Some(setup.api_socket.display().to_string()),
    };
    config.validate().map_err(InstallerError::SlirpConfig)?;
    require_absolute(&setup.api_socket)?;
    reject_newlines(&setup.api_socket.display().to_string(), "api socket")?;
    Ok(format!(
        "FERROCRATE_SLIRP_TAP={}\n\
         FERROCRATE_SLIRP_CIDR={}\n\
         FERROCRATE_SLIRP_MTU=65520\n\
         FERROCRATE_SLIRP_IPV6={}\n\
         FERROCRATE_SLIRP_API_SOCKET={}\n",
        setup.tap_name,
        setup.cidr,
        if setup.enable_ipv6 { "true" } else { "false" },
        setup.api_socket.display()
    ))
}

// ---------------------------------------------------------------------------
// (e) Upgrade
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradePlan {
    pub install_dir: PathBuf,
    pub binary_path: PathBuf,
    pub backup_path: PathBuf,
    pub security_object_path: PathBuf,
    pub security_backup_path: PathBuf,
    /// State directories the upgrade must not touch.
    pub preserved_state_dirs: Vec<PathBuf>,
}

/// Decide the upgrade layout. The plan preserves every state directory: only
/// the binary and the optional eBPF security object are replaced.
pub fn plan_upgrade(
    install_dir: &Path,
    state_dirs: &[PathBuf],
) -> Result<UpgradePlan, InstallerError> {
    require_absolute(install_dir)?;
    for dir in state_dirs {
        require_absolute(dir)?;
        if dir == install_dir {
            return Err(InstallerError::UpgradeRefused(format!(
                "state directory {} must stay separate from the install directory {}",
                dir.display(),
                install_dir.display()
            )));
        }
        if dir.starts_with(install_dir) {
            return Err(InstallerError::UpgradeRefused(format!(
                "state directory {} lives inside the install directory {}",
                dir.display(),
                install_dir.display()
            )));
        }
    }
    let binary_path = install_dir.join("ferrocrate");
    Ok(UpgradePlan {
        install_dir: install_dir.to_path_buf(),
        backup_path: install_dir.join(format!("ferrocrate{BACKUP_SUFFIX}")),
        binary_path,
        security_object_path: install_dir.join("ferro-security.o"),
        security_backup_path: install_dir.join(format!("ferro-security.o{BACKUP_SUFFIX}")),
        preserved_state_dirs: state_dirs.to_vec(),
    })
}

/// Execute the upgrade: back up the current binary, move the staged one into
/// place, and restore the backups when any later step fails. The upgrade is
/// all-or-nothing: either both artifacts move, or neither does.
pub fn execute_upgrade(
    plan: &UpgradePlan,
    staged_binary: &Path,
    staged_security_object: Option<&Path>,
) -> Result<(), InstallerError> {
    require_absolute(staged_binary)?;
    if !staged_binary.is_file() {
        return Err(InstallerError::UpgradeRefused(format!(
            "staged binary {} does not exist",
            staged_binary.display()
        )));
    }
    if let Some(staged_object) = staged_security_object {
        require_absolute(staged_object)?;
    }
    fs::create_dir_all(&plan.install_dir).map_err(io_error(plan.install_dir.clone()))?;

    // Phase 1: back up the current binary. Nothing changed on failure.
    let had_binary = plan.binary_path.exists();
    if had_binary {
        fs::rename(&plan.binary_path, &plan.backup_path).map_err(|_| {
            InstallerError::UpgradeRefused(format!(
                "could not back up {} to {}",
                plan.binary_path.display(),
                plan.backup_path.display()
            ))
        })?;
    }

    // Phase 2: install the staged binary, restoring the backup on failure.
    if let Err(source) = fs::rename(staged_binary, &plan.binary_path) {
        if had_binary {
            let _ = fs::rename(&plan.backup_path, &plan.binary_path);
        }
        return Err(InstallerError::Io {
            path: plan.binary_path.clone(),
            source,
        });
    }

    // Phase 3 (optional): back up the security object, restoring the binary
    // upgrade when the backup cannot be written.
    if let Some(staged_object) = staged_security_object {
        let had_object = plan.security_object_path.exists();
        if had_object {
            if let Err(source) = fs::rename(&plan.security_object_path, &plan.security_backup_path)
            {
                restore_binary(plan, staged_binary, had_binary);
                return Err(InstallerError::Io {
                    path: plan.security_backup_path.clone(),
                    source,
                });
            }
        }
        // Phase 4: install the staged object, restoring everything on failure.
        if let Err(source) = fs::rename(staged_object, &plan.security_object_path) {
            if had_object {
                let _ = fs::rename(&plan.security_backup_path, &plan.security_object_path);
            }
            restore_binary(plan, staged_binary, had_binary);
            return Err(InstallerError::Io {
                path: plan.security_object_path.clone(),
                source,
            });
        }
    }
    Ok(())
}

/// Undo phases 1-2: hand the staged binary back and restore the old one.
fn restore_binary(plan: &UpgradePlan, staged_binary: &Path, had_binary: bool) {
    let _ = fs::rename(&plan.binary_path, staged_binary);
    if had_binary {
        let _ = fs::rename(&plan.backup_path, &plan.binary_path);
    }
}

// ---------------------------------------------------------------------------
// (f) Rollback
// ---------------------------------------------------------------------------

/// Roll back to the binary saved by [`execute_upgrade`]. The rejected binary
/// is parked next to it with a `.failed-upgrade` suffix instead of deleted.
pub fn execute_rollback(plan: &UpgradePlan) -> Result<(), InstallerError> {
    if !plan.backup_path.is_file() {
        return Err(InstallerError::RollbackRefused(format!(
            "no previous binary at {}; nothing to roll back to",
            plan.backup_path.display()
        )));
    }
    if plan.binary_path.exists() {
        let rejected = plan
            .binary_path
            .with_file_name(format!("ferrocrate{FAILED_UPGRADE_SUFFIX}"));
        fs::rename(&plan.binary_path, &rejected).map_err(io_error(plan.binary_path.clone()))?;
    }
    fs::rename(&plan.backup_path, &plan.binary_path).map_err(io_error(plan.backup_path.clone()))?;
    if plan.security_backup_path.is_file() {
        if plan.security_object_path.exists() {
            let _ = fs::remove_file(&plan.security_object_path);
        }
        fs::rename(&plan.security_backup_path, &plan.security_object_path)
            .map_err(io_error(plan.security_backup_path.clone()))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// (g) Uninstall
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UninstallPlan {
    /// FerroCrate-owned files to remove (binary, security object, unit).
    pub remove_files: Vec<PathBuf>,
    /// The state directory, removed only when every entry is FerroCrate-owned.
    pub remove_state_dir: Option<PathBuf>,
}

/// List entries in `state_dir` that FerroCrate does not own.
fn foreign_state_entries(state_dir: &Path) -> Result<Vec<PathBuf>, InstallerError> {
    let mut foreign = Vec::new();
    for entry in fs::read_dir(state_dir).map_err(io_error(state_dir.to_path_buf()))? {
        let entry = entry.map_err(io_error(state_dir.to_path_buf()))?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !OWNED_STATE_ENTRIES.contains(&name.as_str()) {
            foreign.push(entry.path());
        }
    }
    Ok(foreign)
}

/// Decide what uninstall may remove. Refuses with [`InstallerError::ForeignStateData`]
/// when the state directory holds foreign entries: user data is preserved even
/// if that blocks a clean uninstall.
pub fn plan_uninstall(
    install_dir: &Path,
    state_dir: &Path,
    unit_path: Option<&Path>,
) -> Result<UninstallPlan, InstallerError> {
    require_absolute(install_dir)?;
    require_absolute(state_dir)?;
    let mut remove_files = vec![install_dir.join("ferrocrate")];
    let security_object = install_dir.join("ferro-security.o");
    if security_object.exists() {
        remove_files.push(security_object);
    }
    if let Some(unit) = unit_path {
        require_absolute(unit)?;
        remove_files.push(unit.to_path_buf());
    }
    let remove_state_dir = if state_dir.is_dir() {
        let foreign = foreign_state_entries(state_dir)?;
        if foreign.is_empty() {
            Some(state_dir.to_path_buf())
        } else {
            return Err(InstallerError::ForeignStateData {
                dir: state_dir.to_path_buf(),
                entries: foreign,
            });
        }
    } else {
        None
    };
    Ok(UninstallPlan {
        remove_files,
        remove_state_dir,
    })
}

/// Execute the uninstall plan. Re-verifies the state directory at execution
/// time so a file created between planning and execution cannot be deleted.
pub fn execute_uninstall(plan: &UninstallPlan) -> Result<(), InstallerError> {
    for file in &plan.remove_files {
        require_absolute(file)?;
        match fs::remove_file(file) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(InstallerError::Io {
                    path: file.clone(),
                    source,
                })
            }
        }
    }
    if let Some(state_dir) = &plan.remove_state_dir {
        let foreign = foreign_state_entries(state_dir)?;
        if !foreign.is_empty() {
            return Err(InstallerError::ForeignStateData {
                dir: state_dir.clone(),
                entries: foreign,
            });
        }
        fs::remove_dir_all(state_dir).map_err(io_error(state_dir.clone()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    // (a) subordinate IDs ---------------------------------------------------

    #[test]
    fn subid_report_detects_complete_ranges() {
        let report = inspect_subid_contents(
            "tester",
            1000,
            "tester:100000:65536\n",
            "tester:100000:65536\n",
        )
        .expect("inspect");
        assert!(report.complete());
        assert_eq!(
            report.subuid,
            Some(IdRange {
                start: 100_000,
                count: 65_536
            })
        );
        assert!(subid_remediation_commands(&report).is_empty());
    }

    #[test]
    fn subid_remediation_covers_only_missing_side() {
        let report =
            inspect_subid_contents("tester", 1000, "", "tester:100000:65536\n").expect("inspect");
        assert!(!report.complete());
        let commands = subid_remediation_commands(&report);
        assert_eq!(
            commands,
            vec!["sudo usermod --add-subuids 100000-165535 tester".to_string()]
        );
        let instructions = subid_fix_instructions(&report);
        assert!(instructions.contains("will not edit /etc/subuid"));
        assert!(instructions.contains("--add-subuids 100000-165535 tester"));
        assert!(!instructions.contains("--add-subgids"));
    }

    #[test]
    fn subid_remediation_names_both_files_when_both_missing() {
        let report = inspect_subid_contents("tester", 1000, "", "").expect("inspect");
        let instructions = subid_fix_instructions(&report);
        assert!(instructions.contains("--add-subuids 100000-165535 tester"));
        assert!(instructions.contains("--add-subgids 100000-165535 tester"));
        assert!(instructions.contains("single-ID mapping"));
    }

    #[test]
    fn subid_inspect_rejects_invalid_line() {
        let error =
            inspect_subid_contents("tester", 1000, "tester:x:1\n", "").expect_err("invalid line");
        assert!(error.to_string().contains("subordinate id line"));
    }

    #[test]
    fn subid_inspect_matches_numeric_owner() {
        let report =
            inspect_subid_contents("tester", 4242, "4242:200000:65536\n", "").expect("inspect");
        assert_eq!(
            report.subuid,
            Some(IdRange {
                start: 200_000,
                count: 65_536
            })
        );
    }

    // (b) cgroup delegation -------------------------------------------------

    #[test]
    fn cgroup_delegation_commands_are_exact() {
        assert_eq!(
            cgroup_delegation_commands(),
            vec![
                "sudo loginctl enable-linger $USER".to_string(),
                "sudo systemctl set-property user-$(id -u).slice Delegate=yes".to_string(),
            ]
        );
    }

    #[test]
    fn cgroup_check_reports_missing_v2_hierarchy() {
        let temp = tempdir();
        let error = cgroup_delegation_check(Some(temp.path())).expect_err("no cgroup v2 hierarchy");
        assert!(error.contains("cgroup v2 hierarchy is unavailable"));
    }

    #[test]
    fn cgroup_check_accepts_delegated_fixture() {
        let temp = tempdir();
        fs::write(temp.path().join("cgroup.controllers"), "cpu memory pids").expect("controllers");
        fs::write(temp.path().join("cgroup.subtree_control"), "").expect("subtree control");
        cgroup_delegation_check(Some(temp.path())).expect("delegated fixture passes");
    }

    // (c) user service units ------------------------------------------------

    fn spec() -> UserServiceSpec {
        UserServiceSpec {
            unit_name: "ferrocrate-agent".to_string(),
            description: "FerroCrate rootless agent".to_string(),
            exec_start: PathBuf::from("/home/tester/.local/bin/ferrocrate"),
            environment_file: Some(PathBuf::from("/home/tester/.config/ferrocrate/agent.env")),
        }
    }

    #[test]
    fn user_service_unit_uses_user_semantics() {
        let unit = generate_user_service_unit(&spec()).expect("unit");
        assert!(unit.contains("Description=FerroCrate rootless agent"));
        assert!(unit.contains("EnvironmentFile=/home/tester/.config/ferrocrate/agent.env"));
        assert!(unit.contains("ExecStart=/home/tester/.local/bin/ferrocrate"));
        assert!(unit.contains("WantedBy=default.target"));
        // A user unit must not pin User=; it runs as the user themselves.
        assert!(!unit.contains("User="));
        // Every line is a unit directive: no newline injection is possible.
        assert!(unit.lines().all(|line| !line.starts_with(' ')));
    }

    #[test]
    fn user_service_unit_omits_environment_file_when_absent() {
        let mut spec = spec();
        spec.environment_file = None;
        let unit = generate_user_service_unit(&spec).expect("unit");
        assert!(!unit.contains("EnvironmentFile="));
    }

    #[test]
    fn user_service_rejects_path_like_unit_name() {
        let mut spec = spec();
        spec.unit_name = "../../etc/passwd".to_string();
        let error = generate_user_service_unit(&spec).expect_err("path-like name");
        assert!(matches!(error, InstallerError::InvalidUnitName(_)));
    }

    #[test]
    fn user_service_rejects_leading_dot_unit_name() {
        let mut spec = spec();
        spec.unit_name = ".hidden".to_string();
        assert!(matches!(
            generate_user_service_unit(&spec),
            Err(InstallerError::InvalidUnitName(_))
        ));
    }

    #[test]
    fn user_service_rejects_newline_in_description() {
        let mut spec = spec();
        spec.description = "safe\nExecStart=/bin/sh".to_string();
        let error = generate_user_service_unit(&spec).expect_err("newline description");
        assert!(matches!(
            error,
            InstallerError::FieldNewline {
                field: "Description"
            }
        ));
    }

    #[test]
    fn user_service_rejects_relative_exec_start() {
        let mut spec = spec();
        spec.exec_start = PathBuf::from("ferrocrate");
        let error = generate_user_service_unit(&spec).expect_err("relative exec start");
        assert!(matches!(error, InstallerError::ExecStartNotAbsolute(_)));
    }

    #[test]
    fn user_unit_install_path_lands_in_user_systemd_dir() {
        let path = user_unit_install_path(Path::new("/home/tester/.config"), &spec());
        assert_eq!(
            path,
            PathBuf::from("/home/tester/.config/systemd/user/ferrocrate-agent.service")
        );
    }

    #[test]
    fn user_service_enable_and_disable_use_systemctl_user() {
        let enable = user_service_enable_commands(&spec()).expect("enable");
        assert_eq!(
            enable,
            vec![
                "systemctl --user daemon-reload".to_string(),
                "systemctl --user enable --now ferrocrate-agent.service".to_string(),
            ]
        );
        let disable = user_service_disable_commands(&spec()).expect("disable");
        assert_eq!(
            disable,
            vec![
                "systemctl --user disable --now ferrocrate-agent.service".to_string(),
                "systemctl --user daemon-reload".to_string(),
            ]
        );
    }

    // (d) slirp configuration ----------------------------------------------

    fn slirp_setup(api_socket: &Path) -> SlirpSetup {
        SlirpSetup {
            tap_name: "tap0".to_string(),
            cidr: "10.0.2.0/24".to_string(),
            enable_ipv6: false,
            outbound_addr6: None,
            api_socket: api_socket.to_path_buf(),
        }
    }

    #[test]
    fn slirp_environment_captures_validated_settings() {
        let socket = tempdir();
        let env = generate_slirp_environment(&slirp_setup(&socket.path().join("slirp.sock")))
            .expect("env");
        assert!(env.contains("FERROCRATE_SLIRP_TAP=tap0"));
        assert!(env.contains("FERROCRATE_SLIRP_CIDR=10.0.2.0/24"));
        assert!(env.contains("FERROCRATE_SLIRP_MTU=65520"));
        assert!(env.contains("FERROCRATE_SLIRP_IPV6=false"));
        assert!(env.contains(&format!(
            "FERROCRATE_SLIRP_API_SOCKET={}",
            socket.path().join("slirp.sock").display()
        )));
    }

    #[test]
    fn slirp_environment_reflects_ipv6() {
        let socket = tempdir();
        let mut setup = slirp_setup(&socket.path().join("slirp.sock"));
        setup.enable_ipv6 = true;
        setup.outbound_addr6 = Some("2001:db8::1".to_string());
        let env = generate_slirp_environment(&setup).expect("env");
        assert!(env.contains("FERROCRATE_SLIRP_IPV6=true"));
    }

    #[test]
    fn slirp_environment_rejects_invalid_cidr() {
        let socket = tempdir();
        let mut setup = slirp_setup(&socket.path().join("slirp.sock"));
        setup.cidr = "not-a-cidr".to_string();
        let error = generate_slirp_environment(&setup).expect_err("invalid cidr");
        assert!(matches!(error, InstallerError::SlirpConfig(_)));
    }

    #[test]
    fn slirp_environment_rejects_relative_api_socket() {
        let error = generate_slirp_environment(&slirp_setup(&PathBuf::from("slirp.sock")))
            .expect_err("relative socket");
        assert!(matches!(error, InstallerError::RelativePath(_)));
    }

    #[test]
    fn slirp_environment_rejects_newline_in_socket_path() {
        let error = generate_slirp_environment(&slirp_setup(&PathBuf::from("/tmp/slirp\nEVIL=1")))
            .expect_err("newline socket");
        assert!(matches!(
            error,
            InstallerError::FieldNewline {
                field: "api socket"
            }
        ));
    }

    // (e) upgrade -----------------------------------------------------------

    #[test]
    fn upgrade_plan_refuses_relative_paths() {
        let error = plan_upgrade(Path::new("bin"), &[]).expect_err("relative install dir");
        assert!(matches!(error, InstallerError::RelativePath(_)));
        let error = plan_upgrade(
            Path::new("/home/tester/.local/bin"),
            &[PathBuf::from("state")],
        )
        .expect_err("relative state dir");
        assert!(matches!(error, InstallerError::RelativePath(_)));
    }

    #[test]
    fn upgrade_plan_refuses_state_inside_install_dir() {
        let install = Path::new("/home/tester/.local/bin");
        let error = plan_upgrade(install, &[install.join("state")]).expect_err("nested state");
        assert!(matches!(error, InstallerError::UpgradeRefused(_)));
        let error = plan_upgrade(install, &[install.to_path_buf()]).expect_err("equal state");
        assert!(matches!(error, InstallerError::UpgradeRefused(_)));
    }

    #[test]
    fn upgrade_execution_backs_up_and_installs() {
        let install = tempdir();
        let staged = tempdir();
        let state = tempdir();
        fs::write(install.path().join("ferrocrate"), b"old").expect("old binary");
        fs::write(staged.path().join("ferrocrate"), b"new").expect("staged binary");
        fs::write(state.path().join("containers"), b"state marker").expect("state");

        let plan = plan_upgrade(install.path(), &[state.path().to_path_buf()]).expect("plan");
        execute_upgrade(&plan, &staged.path().join("ferrocrate"), None).expect("upgrade");

        assert_eq!(
            fs::read(install.path().join("ferrocrate")).expect("new binary"),
            b"new"
        );
        assert_eq!(fs::read(plan.backup_path).expect("backup"), b"old");
        // State is preserved untouched.
        assert_eq!(
            fs::read(state.path().join("containers")).expect("state"),
            b"state marker"
        );
    }

    #[test]
    fn upgrade_refuses_when_backup_cannot_be_written() {
        let install = tempdir();
        let staged = tempdir();
        fs::write(install.path().join("ferrocrate"), b"old").expect("old binary");
        fs::write(staged.path().join("ferrocrate"), b"new").expect("staged binary");
        // A directory blocking the backup rename target.
        fs::create_dir(install.path().join(format!("ferrocrate{BACKUP_SUFFIX}")))
            .expect("blocked backup");

        let plan = plan_upgrade(install.path(), &[]).expect("plan");
        let error = execute_upgrade(&plan, &staged.path().join("ferrocrate"), None)
            .expect_err("backup blocked");

        assert!(matches!(error, InstallerError::UpgradeRefused(_)));
        // Nothing changed: the old binary is untouched and the staged binary
        // was never consumed.
        assert_eq!(
            fs::read(install.path().join("ferrocrate")).expect("untouched"),
            b"old"
        );
        assert_eq!(
            fs::read(staged.path().join("ferrocrate")).expect("staged intact"),
            b"new"
        );
    }

    #[test]
    fn upgrade_restores_binary_when_security_backup_fails() {
        let install = tempdir();
        let staged = tempdir();
        fs::write(install.path().join("ferrocrate"), b"old").expect("old binary");
        fs::write(install.path().join("ferro-security.o"), b"old-o").expect("old object");
        fs::write(staged.path().join("ferrocrate"), b"new").expect("staged binary");
        fs::write(staged.path().join("ferro-security.o"), b"new-o").expect("staged object");
        // A directory blocking the security-object backup rename target.
        fs::create_dir(
            install
                .path()
                .join(format!("ferro-security.o{BACKUP_SUFFIX}")),
        )
        .expect("blocked object backup");

        let plan = plan_upgrade(install.path(), &[]).expect("plan");
        let error = execute_upgrade(
            &plan,
            &staged.path().join("ferrocrate"),
            Some(&staged.path().join("ferro-security.o")),
        )
        .expect_err("object backup blocked");

        assert!(matches!(error, InstallerError::Io { .. }));
        // All-or-nothing: the old binary is back and the staged binary was
        // returned to its staging path.
        assert_eq!(
            fs::read(install.path().join("ferrocrate")).expect("restored"),
            b"old"
        );
        assert_eq!(
            fs::read(staged.path().join("ferrocrate")).expect("staged returned"),
            b"new"
        );
        assert_eq!(
            fs::read(install.path().join("ferro-security.o")).expect("object intact"),
            b"old-o"
        );
    }

    #[test]
    fn upgrade_execution_refuses_missing_staged_binary() {
        let install = tempdir();
        fs::write(install.path().join("ferrocrate"), b"old").expect("old binary");
        let plan = plan_upgrade(install.path(), &[]).expect("plan");
        let error = execute_upgrade(&plan, &install.path().join("missing"), None)
            .expect_err("missing staged");
        assert!(matches!(error, InstallerError::UpgradeRefused(_)));
        assert_eq!(
            fs::read(install.path().join("ferrocrate")).expect("untouched"),
            b"old"
        );
    }

    #[test]
    fn upgrade_execution_swaps_security_object() {
        let install = tempdir();
        let staged = tempdir();
        fs::write(install.path().join("ferrocrate"), b"old").expect("old binary");
        fs::write(install.path().join("ferro-security.o"), b"old-o").expect("old object");
        fs::write(staged.path().join("ferrocrate"), b"new").expect("staged binary");
        fs::write(staged.path().join("ferro-security.o"), b"new-o").expect("staged object");

        let plan = plan_upgrade(install.path(), &[]).expect("plan");
        execute_upgrade(
            &plan,
            &staged.path().join("ferrocrate"),
            Some(&staged.path().join("ferro-security.o")),
        )
        .expect("upgrade");

        assert_eq!(
            fs::read(install.path().join("ferro-security.o")).expect("new object"),
            b"new-o"
        );
        assert_eq!(
            fs::read(plan.security_backup_path).expect("object backup"),
            b"old-o"
        );
    }

    // (f) rollback ----------------------------------------------------------

    #[test]
    fn rollback_restores_previous_binary_and_parks_rejected_one() {
        let install = tempdir();
        let plan = plan_upgrade(install.path(), &[]).expect("plan");
        fs::write(&plan.binary_path, b"new-broken").expect("new binary");
        fs::write(&plan.backup_path, b"old-good").expect("backup");

        execute_rollback(&plan).expect("rollback");
        assert_eq!(fs::read(&plan.binary_path).expect("restored"), b"old-good");
        assert_eq!(
            fs::read(install.path().join("ferrocrate.failed-upgrade")).expect("parked"),
            b"new-broken"
        );
        assert!(!plan.backup_path.exists());
    }

    #[test]
    fn rollback_restores_security_object_backup() {
        let install = tempdir();
        let plan = plan_upgrade(install.path(), &[]).expect("plan");
        fs::write(&plan.backup_path, b"old").expect("binary backup");
        fs::write(&plan.security_backup_path, b"old-o").expect("object backup");
        fs::write(&plan.security_object_path, b"new-o").expect("new object");

        execute_rollback(&plan).expect("rollback");
        assert_eq!(
            fs::read(&plan.security_object_path).expect("restored object"),
            b"old-o"
        );
    }

    #[test]
    fn rollback_refuses_without_backup() {
        let install = tempdir();
        let plan = plan_upgrade(install.path(), &[]).expect("plan");
        let error = execute_rollback(&plan).expect_err("no backup");
        assert!(matches!(error, InstallerError::RollbackRefused(_)));
        assert!(error.to_string().contains("nothing to roll back to"));
    }

    // (g) uninstall ---------------------------------------------------------

    #[test]
    fn uninstall_plan_removes_only_owned_files() {
        let install = tempdir();
        fs::write(install.path().join("ferrocrate"), b"bin").expect("binary");
        fs::write(install.path().join("ferro-security.o"), b"obj").expect("object");
        let unit = install.path().join("unit/ferrocrate-agent.service");

        let plan = plan_uninstall(install.path(), &install.path().join("state"), Some(&unit))
            .expect("plan");
        assert_eq!(
            plan.remove_files,
            vec![
                install.path().join("ferrocrate"),
                install.path().join("ferro-security.o"),
                unit,
            ]
        );
    }

    #[test]
    fn uninstall_refuses_foreign_state_data() {
        let root = tempdir();
        let state = root.path().join("state");
        fs::create_dir_all(state.join("containers")).expect("containers");
        fs::write(state.join("secret-notes.txt"), b"user data").expect("foreign file");

        let error =
            plan_uninstall(&root.path().join("bin"), &state, None).expect_err("foreign data");
        match error {
            InstallerError::ForeignStateData { dir, entries } => {
                assert_eq!(dir, state);
                assert_eq!(entries, vec![state.join("secret-notes.txt")]);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        // Nothing was removed by planning.
        assert!(state.join("secret-notes.txt").exists());
        assert!(state.join("containers").exists());
    }

    #[test]
    fn uninstall_removes_fully_owned_state_dir() {
        let root = tempdir();
        let install = root.path().join("bin");
        let state = root.path().join("state");
        fs::create_dir_all(&install).expect("install dir");
        fs::create_dir_all(state.join("containers")).expect("containers");
        fs::create_dir_all(state.join("images")).expect("images");
        fs::write(state.join("desktop-vm.json"), b"{}").expect("owned file");
        fs::write(install.join("ferrocrate"), b"bin").expect("binary");

        let plan = plan_uninstall(&install, &state, None).expect("plan");
        execute_uninstall(&plan).expect("uninstall");
        assert!(!install.join("ferrocrate").exists());
        assert!(!state.exists());
    }

    #[test]
    fn uninstall_tolerates_already_removed_files() {
        let root = tempdir();
        let plan = plan_uninstall(&root.path().join("bin"), &root.path().join("state"), None)
            .expect("plan");
        execute_uninstall(&plan).expect("no-op uninstall");
    }

    #[test]
    fn uninstall_rechecks_state_dir_at_execution_time() {
        let root = tempdir();
        let install = root.path().join("bin");
        let state = root.path().join("state");
        fs::create_dir_all(&install).expect("install dir");
        fs::create_dir_all(state.join("containers")).expect("containers");
        fs::write(install.join("ferrocrate"), b"bin").expect("binary");

        let plan = plan_uninstall(&install, &state, None).expect("plan");
        // A foreign file appears after planning.
        fs::write(state.join("user-data.txt"), b"user data").expect("late foreign file");

        let error = execute_uninstall(&plan).expect_err("foreign file appeared");
        assert!(matches!(error, InstallerError::ForeignStateData { .. }));
        // The foreign file and the state tree survived; the binary was
        // already removed because files are handled before the state dir.
        assert!(state.join("user-data.txt").exists());
        assert!(!install.join("ferrocrate").exists());
    }

    #[test]
    fn uninstall_does_not_follow_symlinks_inside_the_state_dir() {
        // A symlink with an owned name appears inside the state dir after
        // planning. `remove_dir_all` must unlink the symlink itself and never
        // delete through it, so the victim directory survives.
        let root = tempdir();
        let install = root.path().join("bin");
        let state = root.path().join("state");
        let victim = root.path().join("victim");
        fs::create_dir_all(&install).expect("install dir");
        fs::create_dir_all(state.join("containers")).expect("containers");
        fs::create_dir_all(&victim).expect("victim dir");
        fs::write(victim.join("data"), b"precious").expect("victim data");
        fs::write(install.join("ferrocrate"), b"bin").expect("binary");

        let plan = plan_uninstall(&install, &state, None).expect("plan");
        // Owned-named entry swapped for a symlink between plan and execute.
        std::os::unix::fs::symlink(&victim, state.join("containers/symlinked"))
            .expect("plant symlink");

        execute_uninstall(&plan).expect("uninstall");
        assert!(!state.exists(), "state dir removed");
        assert!(victim.join("data").exists(), "victim must survive");
    }

    #[test]
    fn uninstall_refuses_symlinked_state_dir_without_deleting_the_target() {
        // The state dir path itself is replaced by a symlink. Removal must
        // fail or remove only the link; the target must survive either way.
        let root = tempdir();
        let install = root.path().join("bin");
        let real_state = root.path().join("real-state");
        let link = root.path().join("state-link");
        fs::create_dir_all(&install).expect("install dir");
        fs::create_dir_all(real_state.join("containers")).expect("containers");
        fs::write(real_state.join("desktop-vm.json"), b"{}").expect("owned file");
        fs::write(install.join("ferrocrate"), b"bin").expect("binary");
        std::os::unix::fs::symlink(&real_state, &link).expect("state symlink");

        let plan = plan_uninstall(&install, &link, None).expect("plan");
        let _ = execute_uninstall(&plan);
        // Whether removal refused the symlink or unlinked only the link, the
        // real state tree and its owned entries must still exist.
        assert!(
            real_state.join("containers").exists(),
            "symlinked state-dir target must never be deleted"
        );
    }

    #[test]
    fn uninstall_refuses_relative_paths() {
        let error = plan_uninstall(Path::new("bin"), Path::new("/state"), None)
            .expect_err("relative install");
        assert!(matches!(error, InstallerError::RelativePath(_)));
        let error = plan_uninstall(Path::new("/bin"), Path::new("state"), None)
            .expect_err("relative state");
        assert!(matches!(error, InstallerError::RelativePath(_)));
    }

    #[test]
    fn rootless_helper_list_names_the_mapping_and_network_tools() {
        assert_eq!(
            ROOTLESS_HELPERS,
            &["newuidmap", "newgidmap", "slirp4netns", "bwrap"]
        );
    }
}
