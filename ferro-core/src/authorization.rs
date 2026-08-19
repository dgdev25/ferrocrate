//! Typed authorization requests and native policy decisions.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod admission;
#[cfg(target_os = "linux")]
pub mod cri_delegation;
pub mod emergency;
pub mod gate;
pub mod helper_grant;
mod helper_grant_delegation;
mod helper_grant_encoding;
mod helper_grant_error;
pub mod inventory;
pub mod policy;
#[cfg(target_os = "linux")]
pub mod principal;
pub(crate) mod runtime;
pub mod surface;

/// Query the Linux immutable-file append-only bit on an already opened file.
/// The path must be validated by the caller before this descriptor is passed.
#[cfg(target_os = "linux")]
pub fn file_is_kernel_append_only(file: &std::fs::File) -> std::io::Result<bool> {
    use std::os::fd::AsRawFd;
    const FS_APPEND_FL: nix::libc::c_long = 0x0000_0020;
    const FS_IOC_GETFLAGS: nix::libc::c_ulong = 0x8008_6601;
    let mut flags: nix::libc::c_long = 0;
    // SAFETY: the ioctl only writes one machine word to the valid pointer and
    // operates on the caller's held regular-file descriptor.
    let result = unsafe { nix::libc::ioctl(file.as_raw_fd(), FS_IOC_GETFLAGS, &mut flags) };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(flags & FS_APPEND_FL != 0)
}

/// Open a path by walking from the process root without permitting symlink or
/// magic-link traversal in any component.
#[cfg(target_os = "linux")]
pub fn open_path_no_symlinks(
    path: &std::path::Path,
    flags: i32,
    mode: u32,
) -> std::io::Result<std::fs::File> {
    use std::{ffi::CString, os::fd::FromRawFd, os::unix::ffi::OsStrExt};
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let relative = absolute.strip_prefix("/").map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path is not beneath root")
    })?;
    let name = CString::new(relative.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let root = std::fs::File::open("/")?;
    use std::os::fd::AsRawFd;
    let how = OpenHow {
        flags: (flags | nix::libc::O_CLOEXEC) as u64,
        mode: mode as u64,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: all pointers reference initialized values for the duration of
    // the openat2 syscall; a successful return transfers ownership of a new fd.
    let fd = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_openat2,
            root.as_raw_fd(),
            name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        ) as i32
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` is a newly owned descriptor returned by openat2.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
pub struct SecureDirectory {
    directory: std::fs::File,
}

#[cfg(target_os = "linux")]
impl SecureDirectory {
    pub fn open(path: &std::path::Path) -> std::io::Result<Self> {
        let directory =
            open_path_no_symlinks(path, nix::libc::O_RDONLY | nix::libc::O_DIRECTORY, 0)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = directory.metadata()?;
            if !metadata.is_dir()
                || metadata.uid() != nix::unistd::geteuid().as_raw()
                || metadata.mode() & 0o022 != 0
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "secure directory owner or mode is unsafe",
                ));
            }
        }
        Ok(Self { directory })
    }

    fn name(name: &str) -> std::io::Result<std::ffi::CString> {
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid relative name",
            ));
        }
        std::ffi::CString::new(name)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "name contains NUL"))
    }

    pub fn open_file(&self, name: &str, flags: i32, mode: u32) -> std::io::Result<std::fs::File> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let name = Self::name(name)?;
        // SAFETY: name and dirfd remain valid; success returns a newly owned fd.
        let fd = unsafe {
            nix::libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                flags | nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW,
                mode,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }

    pub fn read_bounded(&self, name: &str, maximum: u64) -> std::io::Result<Vec<u8>> {
        use std::io::Read;
        let mut file = self.open_file(name, nix::libc::O_RDONLY, 0)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > maximum {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "insecure or oversized file",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.nlink() != 1
                || metadata.uid() != nix::unistd::geteuid().as_raw()
                || metadata.mode() & 0o077 != 0
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "secure file owner or mode is unsafe",
                ));
            }
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    pub fn exists(&self, name: &str) -> std::io::Result<bool> {
        match self.open_file(name, nix::libc::O_RDONLY, 0) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub fn write_atomic(&self, name: &str, bytes: &[u8], mode: u32) -> std::io::Result<()> {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let target = Self::name(name)?;
        let temporary_name = format!(
            ".secure-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let temporary = Self::name(&temporary_name)?;
        let mut file = self.open_file(
            &temporary_name,
            nix::libc::O_WRONLY | nix::libc::O_CREAT | nix::libc::O_EXCL,
            mode,
        )?;
        if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
            let _ = self.unlink(&temporary_name);
            return Err(error);
        }
        // SAFETY: both names are valid and resolved relative to the retained dirfd.
        let result = unsafe {
            nix::libc::renameat(
                self.directory.as_raw_fd(),
                temporary.as_ptr(),
                self.directory.as_raw_fd(),
                target.as_ptr(),
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            let _ = self.unlink(&temporary_name);
            return Err(error);
        }
        self.directory.sync_all()
    }

    pub fn create_exclusive(&self, name: &str, bytes: &[u8], mode: u32) -> std::io::Result<()> {
        use std::io::Write;
        let mut file = self.open_file(
            name,
            nix::libc::O_WRONLY | nix::libc::O_CREAT | nix::libc::O_EXCL,
            mode,
        )?;
        file.write_all(bytes)?;
        file.sync_all()?;
        self.directory.sync_all()
    }

    pub fn unlink(&self, name: &str) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        let name = Self::name(name)?;
        let result = unsafe { nix::libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
        self.directory.sync_all()
    }
}
#[cfg(feature = "test-support")]
pub use runtime::test_support;

#[cfg(target_os = "linux")]
pub use principal::{
    DelegatedPrincipal, DelegationPolicy, EffectivePrincipal, IdMapEntry, InvocationChannel,
    LinuxProcessIdentity, PrincipalResolutionError, PrincipalResolver, SupplementaryGroupPolicy,
    TransportPrincipal,
};

/// Authenticated caller information propagated from an entry point into the
/// runtime gate. Callers cannot supply a principal string or role.
#[derive(Clone, Debug)]
pub struct RequestOrigin {
    principal: ResolvedPrincipal,
    invocation: crate::witness::Invocation,
    request_id: Option<[u8; 16]>,
    parent_request_id: Option<[u8; 16]>,
    attempt: u32,
    fanout: Option<FanoutContext>,
    #[cfg(target_os = "linux")]
    transport: Option<TransportPrincipal>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FanoutContext {
    parent_request_id: [u8; 16],
    child_id: [u8; 16],
    idempotency_key: [u8; 32],
    expected_action: Action,
    expected_resource: String,
    request_digest: [u8; 32],
    deadline_unix_ms: u64,
    policy_generation: u64,
    policy_digest: [u8; 32],
    attempt: u32,
    ordinal: u32,
    plan_digest: [u8; 32],
}

impl FanoutContext {
    pub fn parent_request_id(&self) -> &[u8; 16] {
        &self.parent_request_id
    }
    pub fn child_id(&self) -> &[u8; 16] {
        &self.child_id
    }
    pub fn idempotency_key(&self) -> &[u8; 32] {
        &self.idempotency_key
    }
    pub fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }
    pub fn deadline_unix_ms(&self) -> u64 {
        self.deadline_unix_ms
    }
    pub fn policy_generation(&self) -> u64 {
        self.policy_generation
    }
    pub fn policy_digest(&self) -> &[u8; 32] {
        &self.policy_digest
    }
    pub fn attempt(&self) -> u32 {
        self.attempt
    }
    pub fn ordinal(&self) -> u32 {
        self.ordinal
    }
    pub fn plan_digest(&self) -> &[u8; 32] {
        &self.plan_digest
    }
    fn integrity_valid(&self) -> bool {
        let mut idem = Sha256::new();
        idem.update(b"ferrocrate/compose-idempotency/v1");
        idem.update(self.parent_request_id);
        idem.update(self.plan_digest);
        idem.update(self.ordinal.to_be_bytes());
        idem.update([fanout_action_code(self.expected_action)]);
        idem.update((self.expected_resource.len() as u64).to_be_bytes());
        idem.update(self.expected_resource.as_bytes());
        idem.update(self.request_digest);
        let expected: [u8; 32] = idem.finalize().into();
        let mut child = Sha256::new();
        child.update(b"ferrocrate/compose-child/v1");
        child.update(expected);
        child.update(self.attempt.to_be_bytes());
        let hash: [u8; 32] = child.finalize().into();
        expected == self.idempotency_key && hash[..16] == self.child_id
    }
}

fn fanout_action_code(action: Action) -> u8 {
    match action {
        Action::ContainerRun => 1,
        Action::ContainerStop => 2,
        Action::ContainerDelete => 3,
        Action::ImagePull => 4,
        Action::VolumeCreate => 5,
        Action::ImageBuild => 6,
        Action::ImageTag => 7,
        Action::ImageReferenceWrite => 8,
        _ => 0,
    }
}

#[cfg(target_os = "linux")]
impl RequestOrigin {
    pub fn cli_current() -> std::io::Result<Self> {
        Self::cli_current_with_request_id(None)
    }

    pub fn cli_current_for_operation(request_id: [u8; 16]) -> std::io::Result<Self> {
        Self::cli_current_with_request_id(Some(request_id))
    }

    fn cli_current_with_request_id(request_id: Option<[u8; 16]>) -> std::io::Result<Self> {
        use std::os::unix::fs::MetadataExt;
        let status = std::fs::read_to_string("/proc/self/status")?;
        let uid = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .and_then(|value| value.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "missing effective uid")
            })?;
        let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .to_owned();
        let userns = std::fs::metadata("/proc/self/ns/user")?.ino();
        let trusted = std::fs::metadata("/proc/1/ns/user")
            .map(|meta| meta.ino() == userns)
            .unwrap_or(false);
        let role = if uid == 0 && trusted {
            Role::Administrator
        } else {
            Role::Developer
        };
        Ok(Self {
            principal: ResolvedPrincipal::new(
                format!("linux:{boot_id}:uid:{uid}:userns:{userns}"),
                role,
            ),
            invocation: crate::witness::Invocation::Cli,
            request_id,
            parent_request_id: None,
            attempt: 0,
            fanout: None,
            transport: None,
        })
    }
    pub fn docker(transport: &TransportPrincipal) -> Self {
        Self {
            principal: transport.principal().clone(),
            invocation: crate::witness::Invocation::DockerUnix,
            request_id: None,
            parent_request_id: None,
            attempt: 0,
            fanout: None,
            transport: Some(transport.clone()),
        }
    }
    pub fn proxy(effective: &EffectivePrincipal) -> Self {
        Self {
            principal: effective.principal().clone(),
            invocation: crate::witness::Invocation::Cri,
            request_id: None,
            parent_request_id: None,
            attempt: 0,
            fanout: None,
            transport: Some(effective.transport().clone()),
        }
    }
    pub fn cri_transport(transport: &TransportPrincipal) -> Self {
        Self {
            principal: transport.principal().clone(),
            invocation: crate::witness::Invocation::Cri,
            request_id: None,
            parent_request_id: None,
            attempt: 0,
            fanout: None,
            transport: Some(transport.clone()),
        }
    }
    pub fn verified_cri_delegation(
        transport: &TransportPrincipal,
        verified: cri_delegation::VerifiedCriDelegation,
    ) -> Self {
        Self {
            principal: verified.into_principal(),
            invocation: crate::witness::Invocation::Cri,
            request_id: None,
            parent_request_id: None,
            attempt: 0,
            fanout: None,
            transport: Some(transport.clone()),
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub fn compose_child(
        parent: &Self,
        child_id: [u8; 16],
        parent_id: [u8; 16],
        idempotency_key: [u8; 32],
        expected_action: Action,
        expected_resource: impl Into<String>,
        request_digest: [u8; 32],
        deadline_unix_ms: u64,
        policy_generation: u64,
        policy_digest: [u8; 32],
        attempt: u32,
        ordinal: u32,
        plan_digest: [u8; 32],
    ) -> Self {
        let fanout = FanoutContext {
            parent_request_id: parent_id,
            child_id,
            idempotency_key,
            expected_action,
            expected_resource: expected_resource.into(),
            request_digest,
            deadline_unix_ms,
            policy_generation,
            policy_digest,
            attempt,
            ordinal,
            plan_digest,
        };
        Self {
            principal: parent.principal.clone(),
            invocation: crate::witness::Invocation::Compose,
            request_id: Some(child_id),
            parent_request_id: Some(parent_id),
            attempt,
            fanout: Some(fanout),
            transport: parent.transport.clone(),
        }
    }
    pub fn revalidate_transport(&self) -> Result<(), PrincipalResolutionError> {
        self.transport
            .as_ref()
            .map_or(Ok(()), TransportPrincipal::revalidate_for_execution)
    }
    pub(crate) fn fanout_integrity_valid(&self) -> bool {
        self.fanout.as_ref().is_none_or(|fanout| {
            fanout.integrity_valid()
                && self.request_id == Some(fanout.child_id)
                && self.parent_request_id == Some(fanout.parent_request_id)
                && self.attempt == fanout.attempt
        })
    }
    pub(crate) fn fanout_request_digest_matches(&self, actual: &[u8; 32]) -> bool {
        self.fanout
            .as_ref()
            .is_none_or(|fanout| &fanout.request_digest == actual)
    }
    pub fn principal(&self) -> &ResolvedPrincipal {
        &self.principal
    }
    pub fn invocation(&self) -> crate::witness::Invocation {
        self.invocation
    }
    pub fn request_id(&self) -> Option<[u8; 16]> {
        self.request_id
    }
    pub fn parent_request_id(&self) -> Option<[u8; 16]> {
        self.parent_request_id
    }
    pub fn attempt(&self) -> u32 {
        self.attempt
    }
    pub fn fanout(&self) -> Option<&FanoutContext> {
        self.fanout.as_ref()
    }
}

/// Canonical digest of the exact container snapshot consumed by a Compose
/// stop/delete executor. Both the fan-out planner and runtime use this helper,
/// preventing caller-chosen serialization from becoming an authority binding.
pub fn compose_down_executor_digest(
    record: &crate::container_store::ContainerRecord,
    action: Action,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"ferrocrate/compose-down-executor/v1");
    digest.update([match action {
        Action::ContainerStop => 1,
        Action::ContainerDelete => 2,
        _ => 0,
    }]);
    for value in [record.id.as_str(), record.status.as_str()] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    digest.update(record.mutation_generation.max(1).to_be_bytes());
    digest.finalize().into()
}

#[cfg(test)]
mod tests;

/// A stable, closed vocabulary for runtime mutations.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Action {
    #[serde(rename = "container.create")]
    ContainerCreate,
    #[serde(rename = "container.run")]
    ContainerRun,
    #[serde(rename = "container.exec")]
    ContainerExec,
    #[serde(rename = "container.pause")]
    ContainerPause,
    #[serde(rename = "container.resume")]
    ContainerResume,
    #[serde(rename = "container.stop")]
    ContainerStop,
    #[serde(rename = "container.kill")]
    ContainerKill,
    #[serde(rename = "container.restart")]
    ContainerRestart,
    #[serde(rename = "container.start")]
    ContainerStart,
    #[serde(rename = "container.delete")]
    ContainerDelete,
    #[serde(rename = "container.rename")]
    ContainerRename,
    #[serde(rename = "container.update")]
    ContainerUpdate,
    #[serde(rename = "container.archive-write")]
    ContainerArchiveWrite,
    #[serde(rename = "image.pull")]
    ImagePull,
    #[serde(rename = "image.delete")]
    ImageDelete,
    #[serde(rename = "image.build")]
    ImageBuild,
    #[serde(rename = "image.tag")]
    ImageTag,
    #[serde(rename = "image.reference-write")]
    ImageReferenceWrite,
    #[serde(rename = "volume.create")]
    VolumeCreate,
    #[serde(rename = "volume.delete")]
    VolumeDelete,
    #[serde(rename = "volume.mount")]
    VolumeMount,
    #[serde(rename = "volume.unmount")]
    VolumeUnmount,
    #[serde(rename = "network.create")]
    NetworkCreate,
    #[serde(rename = "network.delete")]
    NetworkDelete,
    #[serde(rename = "network.attach")]
    NetworkAttach,
    #[serde(rename = "network.detach")]
    NetworkDetach,
    #[serde(rename = "device.use")]
    DeviceUse,
    #[serde(rename = "policy.reload")]
    PolicyReload,
    #[serde(rename = "policy.rollback")]
    PolicyRollback,
    #[serde(rename = "witness.checkpoint-publish")]
    CheckpointPublish,
    #[serde(rename = "witness.checkpoint-recover")]
    CheckpointRecover,
    #[serde(rename = "witness.key-rotate")]
    KeyRotate,
    #[serde(rename = "rootless.mapping")]
    RootlessMapping,
}

/// The five roles supported by the native policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum Role {
    #[serde(rename = "administrator")]
    Administrator,
    #[serde(rename = "operator")]
    Operator,
    #[serde(rename = "developer")]
    Developer,
    #[serde(rename = "auditor")]
    Auditor,
    #[serde(rename = "runtime-cleanup")]
    RuntimeCleanup,
}

/// The canonical kind of a protected resource.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceKind {
    Container,
    Image,
    Volume,
    Network,
    Device,
    Policy,
    Administrative,
    RootlessMapping,
}

/// An authenticated principal identifier minted by the resolver boundary.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct PrincipalId(String);

impl PrincipalId {
    #[allow(dead_code)] // Used by the trusted resolver submodule added in Task 2.
    fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A resolver-produced principal with a trusted native role.
///
/// External callers cannot mint one:
///
/// ```compile_fail
/// use ferro_core::authorization::{ResolvedPrincipal, Role};
/// let _ = ResolvedPrincipal::new("caller-supplied", Role::Administrator);
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedPrincipal {
    id: PrincipalId,
    role: Role,
}

impl ResolvedPrincipal {
    #[allow(dead_code)] // Used by the trusted resolver submodule added in Task 2.
    fn new(id: impl Into<String>, role: Role) -> Self {
        Self {
            id: PrincipalId::new(id),
            role,
        }
    }

    pub fn id(&self) -> &PrincipalId {
        &self.id
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn is_host_administrator(&self) -> bool {
        self.role == Role::Administrator
    }
}

/// An immutable resource identifier minted by canonicalization.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ResourceId(String);

impl ResourceId {
    #[allow(dead_code)] // Used by the trusted canonicalization submodule.
    fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// An immutable resource identity used for a decision.
///
/// Resource canonicalization is restricted to the authorization boundary:
///
/// ```compile_fail
/// use ferro_core::authorization::{Resource, ResourceKind};
/// let _ = Resource::canonical(ResourceKind::Container, "raw-name", None, 1);
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Resource {
    kind: ResourceKind,
    id: ResourceId,
    owner: Option<PrincipalId>,
    generation: u64,
}

impl Resource {
    #[allow(dead_code)] // Used by the trusted canonicalization submodule.
    fn canonical(
        kind: ResourceKind,
        id: impl Into<String>,
        owner: Option<PrincipalId>,
        generation: u64,
    ) -> Self {
        Self {
            kind,
            id: ResourceId::new(id),
            owner,
            generation,
        }
    }

    pub fn kind(&self) -> ResourceKind {
        self.kind
    }

    pub fn id(&self) -> &ResourceId {
        &self.id
    }

    pub fn owner(&self) -> Option<&PrincipalId> {
        self.owner.as_ref()
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// A normalized mount category; raw host paths are not policy inputs.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MountClass {
    ReadOnly,
    Workspace,
    PersistentVolume,
    HostPath,
    Tmpfs,
}

/// A canonical lifecycle state at the time of authorization.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceState {
    Absent,
    Created,
    Running,
    Paused,
    Stopped,
}

/// Normalized facts that can constrain a typed action.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct RequestFacts {
    image_digest: Option<String>,
    mounts: Vec<MountClass>,
    network_ids: Vec<String>,
    requested_capabilities: Vec<String>,
    privileged: bool,
    device_classes: Vec<String>,
    lifecycle_state: Option<ResourceState>,
    readonly_rootfs: bool,
    no_new_privileges: bool,
    mount_sources_approved: Option<bool>,
    execution_digest: Option<String>,
    parent_resource_id: Option<String>,
}

impl RequestFacts {
    pub fn image_digest(&self) -> Option<&str> {
        self.image_digest.as_deref()
    }

    pub fn mounts(&self) -> &[MountClass] {
        &self.mounts
    }

    pub fn network_ids(&self) -> &[String] {
        &self.network_ids
    }

    pub fn requested_capabilities(&self) -> &[String] {
        &self.requested_capabilities
    }

    pub fn privileged(&self) -> bool {
        self.privileged
    }

    pub fn device_classes(&self) -> &[String] {
        &self.device_classes
    }

    pub fn lifecycle_state(&self) -> Option<ResourceState> {
        self.lifecycle_state
    }

    pub fn readonly_rootfs(&self) -> bool {
        self.readonly_rootfs
    }

    pub fn no_new_privileges(&self) -> bool {
        self.no_new_privileges
    }

    pub fn execution_digest(&self) -> Option<&str> {
        self.execution_digest.as_deref()
    }

    pub fn parent_resource_id(&self) -> Option<&str> {
        self.parent_resource_id.as_deref()
    }
}

/// The authenticated and normalized input to policy evaluation.
///
/// Trusted request contexts cannot be reconstructed from caller input:
///
/// ```compile_fail
/// use ferro_core::authorization::RequestContext;
/// let _: RequestContext = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RequestContext {
    request_id: String,
    principal: Option<ResolvedPrincipal>,
    action: Action,
    resource: Resource,
    facts: RequestFacts,
    fanout: Option<FanoutContext>,
}

impl RequestContext {
    #[allow(dead_code)] // Used by resolver/gate submodules, never external callers.
    fn resolved(
        request_id: impl Into<String>,
        principal: Option<ResolvedPrincipal>,
        action: Action,
        resource: Resource,
        facts: RequestFacts,
    ) -> Self {
        Self {
            request_id: request_id.into(),
            principal,
            action,
            resource,
            facts,
            fanout: None,
        }
    }

    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn principal(&self) -> Option<&ResolvedPrincipal> {
        self.principal.as_ref()
    }

    pub fn action(&self) -> Action {
        self.action
    }

    pub fn resource(&self) -> &Resource {
        &self.resource
    }

    pub fn facts(&self) -> &RequestFacts {
        &self.facts
    }
    pub fn fanout(&self) -> Option<&FanoutContext> {
        self.fanout.as_ref()
    }
    fn attach_fanout(&mut self, fanout: Option<FanoutContext>) {
        self.fanout = fanout;
    }
}

/// Rollout behavior for authorization.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationMode {
    /// Preserve existing OCI and Docker-compatible behavior.
    #[default]
    Disabled,
    /// Evaluate the policy, but do not enforce a denial.
    Shadow,
    /// Apply the native policy decision.
    Enforce,
}

/// One pinned rollout configuration shared by every privileged service boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationServiceMode {
    mode: AuthorizationMode,
    policy_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum AuthorizationServiceModeError {
    #[error("authorization service mode is invalid")]
    InvalidMode,
    #[error("enabled authorization requires a pinned policy digest")]
    MissingPolicyDigest,
    #[error("disabled authorization cannot carry a policy digest")]
    UnexpectedPolicyDigest,
    #[error("authorization service configurations contradict each other")]
    ConfigurationMismatch,
}

impl AuthorizationServiceMode {
    pub fn new(
        mode: AuthorizationMode,
        policy_digest: Option<[u8; 32]>,
    ) -> Result<Self, AuthorizationServiceModeError> {
        let policy_digest = match (mode, policy_digest) {
            (AuthorizationMode::Disabled, None) => [0; 32],
            (AuthorizationMode::Disabled, Some(_)) => {
                return Err(AuthorizationServiceModeError::UnexpectedPolicyDigest)
            }
            (_, Some(digest)) if digest != [0; 32] => digest,
            _ => return Err(AuthorizationServiceModeError::MissingPolicyDigest),
        };
        Ok(Self {
            mode,
            policy_digest,
        })
    }

    pub fn parse(
        mode: &str,
        policy_digest: Option<[u8; 32]>,
    ) -> Result<Self, AuthorizationServiceModeError> {
        let mode = match mode {
            "enforce" => AuthorizationMode::Enforce,
            "shadow" => AuthorizationMode::Shadow,
            "disabled" => AuthorizationMode::Disabled,
            _ => return Err(AuthorizationServiceModeError::InvalidMode),
        };
        Self::new(mode, policy_digest)
    }

    pub const fn mode(self) -> AuthorizationMode {
        self.mode
    }
    pub const fn policy_digest(self) -> Option<[u8; 32]> {
        match self.mode {
            AuthorizationMode::Disabled => None,
            _ => Some(self.policy_digest),
        }
    }
    pub fn require_match(self, peer: Self) -> Result<(), AuthorizationServiceModeError> {
        if self == peer {
            Ok(())
        } else {
            Err(AuthorizationServiceModeError::ConfigurationMismatch)
        }
    }
}

/// Stable machine-readable explanations for decisions.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReasonCode {
    AuthorizationDisabled,
    ShadowAllowed,
    RoleAllowed,
    UnknownPrincipal,
    ResourceOwnerMismatch,
    PrivilegedContainerDenied,
    RoleNotAuthorized,
    PolicyAdministrationDenied,
    CleanupActionDenied,
    MountSourceDenied,
    EmergencyOverride,
}

/// An effective decision and, in shadow mode, its hypothetical denial.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Decision {
    pub allowed: bool,
    pub reason: ReasonCode,
    pub matched_rule: String,
    pub policy_generation: u64,
    pub hypothetical_denial: Option<ReasonCode>,
}

/// A bounded, versioned native policy document.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    pub schema_version: u32,
    pub generation: u64,
    #[serde(default)]
    pub mode: AuthorizationMode,
}

impl PolicyDocument {
    /// Evaluate a request according to the configured rollout mode.
    pub fn evaluate(&self, request: &RequestContext) -> Decision {
        match self.mode {
            AuthorizationMode::Disabled => self.decision(
                true,
                ReasonCode::AuthorizationDisabled,
                "compatibility.disabled",
                None,
            ),
            AuthorizationMode::Shadow => {
                let hypothetical = self.enforced_decision(request);
                if hypothetical.allowed {
                    hypothetical
                } else {
                    self.decision(
                        true,
                        ReasonCode::ShadowAllowed,
                        "compatibility.shadow",
                        Some(hypothetical.reason),
                    )
                }
            }
            AuthorizationMode::Enforce => self.enforced_decision(request),
        }
    }

    fn enforced_decision(&self, request: &RequestContext) -> Decision {
        if request.facts.mount_sources_approved == Some(false) {
            return self.decision(
                false,
                ReasonCode::MountSourceDenied,
                "container.mount-source.approved-root",
                None,
            );
        }
        let Some(principal) = &request.principal else {
            return self.decision(
                false,
                ReasonCode::UnknownPrincipal,
                "principal.unknown",
                None,
            );
        };

        match principal.role {
            Role::Administrator => {
                self.decision(true, ReasonCode::RoleAllowed, "role.administrator", None)
            }
            Role::Operator if is_policy_administration(request.action) => self.decision(
                false,
                ReasonCode::PolicyAdministrationDenied,
                "role.operator.no-policy-admin",
                None,
            ),
            Role::Operator => self.decision(true, ReasonCode::RoleAllowed, "role.operator", None),
            Role::Developer
                if request.facts.privileged
                    && matches!(
                        request.action,
                        Action::ContainerCreate | Action::ContainerRun
                    ) =>
            {
                self.decision(
                    false,
                    ReasonCode::PrivilegedContainerDenied,
                    "role.developer.no-privileged-container",
                    None,
                )
            }
            Role::Developer if request.resource.owner.as_ref() != Some(&principal.id) => self
                .decision(
                    false,
                    ReasonCode::ResourceOwnerMismatch,
                    "role.developer.owner",
                    None,
                ),
            Role::Developer if is_policy_administration(request.action) => self.decision(
                false,
                ReasonCode::PolicyAdministrationDenied,
                "role.developer.no-policy-admin",
                None,
            ),
            Role::Developer => {
                self.decision(true, ReasonCode::RoleAllowed, "role.developer.owner", None)
            }
            Role::Auditor => self.decision(
                false,
                ReasonCode::RoleNotAuthorized,
                "role.auditor.read-only",
                None,
            ),
            Role::RuntimeCleanup if is_cleanup_action(request.action) => {
                self.decision(true, ReasonCode::RoleAllowed, "role.runtime-cleanup", None)
            }
            Role::RuntimeCleanup => self.decision(
                false,
                ReasonCode::CleanupActionDenied,
                "role.runtime-cleanup.deletion-only",
                None,
            ),
        }
    }

    fn decision(
        &self,
        allowed: bool,
        reason: ReasonCode,
        matched_rule: &str,
        hypothetical_denial: Option<ReasonCode>,
    ) -> Decision {
        Decision {
            allowed,
            reason,
            matched_rule: matched_rule.to_owned(),
            policy_generation: self.generation,
            hypothetical_denial,
        }
    }
}

fn is_policy_administration(action: Action) -> bool {
    matches!(action, Action::PolicyReload | Action::PolicyRollback)
}

fn is_cleanup_action(action: Action) -> bool {
    matches!(
        action,
        Action::ContainerDelete
            | Action::VolumeDelete
            | Action::VolumeUnmount
            | Action::NetworkDelete
            | Action::NetworkDetach
    )
}
