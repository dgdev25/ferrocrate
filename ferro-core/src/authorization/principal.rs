//! Kernel-backed Linux process and proxy principal resolution.

use std::{
    io,
    os::fd::{AsFd, AsRawFd, OwnedFd, RawFd},
    sync::Arc,
};

use nix::errno::Errno;
use serde::Serialize;
use thiserror::Error;

use super::{ResolvedPrincipal, Role};
use procfs::{
    KernelIdentityReader, KernelPeerCredentials, ProcReader, SystemKernelIdentityReader,
    SystemProcReader,
};

mod procfs;

#[cfg(test)]
mod tests;

/// The trusted entry point through which a caller reached the runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InvocationChannel {
    Cli,
    DockerUnix,
    Compose,
    Cri,
    Manager,
    Internal,
}

/// Closed handling policy for kernel-reported supplementary groups.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupplementaryGroupPolicy {
    Ignore,
    EffectiveGidOnly,
    AcceptKernelReported,
}

impl InvocationChannel {
    pub fn supplementary_group_policy(self) -> SupplementaryGroupPolicy {
        match self {
            Self::Cli | Self::DockerUnix | Self::Compose => {
                SupplementaryGroupPolicy::AcceptKernelReported
            }
            Self::Cri | Self::Manager => SupplementaryGroupPolicy::Ignore,
            Self::Internal => SupplementaryGroupPolicy::EffectiveGidOnly,
        }
    }
}

/// One kernel UID/GID namespace mapping range.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct IdMapEntry {
    namespace_start: u32,
    host_start: u32,
    length: u32,
}

impl IdMapEntry {
    pub fn namespace_start(&self) -> u32 {
        self.namespace_start
    }

    pub fn host_start(&self) -> u32 {
        self.host_start
    }

    pub fn length(&self) -> u32 {
        self.length
    }
}

/// Process identity facts read from the kernel and tied to one pidfd lifetime.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LinuxProcessIdentity {
    pid: u32,
    uids: [u32; 4],
    gids: [u32; 4],
    supplementary_groups: Vec<u32>,
    start_time_ticks: u64,
    boot_id: String,
    user_namespace_inode: u64,
    trusted_user_namespace: bool,
    uid_map: Vec<IdMapEntry>,
    gid_map: Vec<IdMapEntry>,
    executable_inode: u64,
}

impl LinuxProcessIdentity {
    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn uids(&self) -> [u32; 4] {
        self.uids
    }

    pub fn gids(&self) -> [u32; 4] {
        self.gids
    }

    pub fn effective_uid(&self) -> u32 {
        self.uids[1]
    }

    pub fn effective_gid(&self) -> u32 {
        self.gids[1]
    }

    pub fn supplementary_groups(&self) -> &[u32] {
        &self.supplementary_groups
    }

    pub fn start_time_ticks(&self) -> u64 {
        self.start_time_ticks
    }

    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    pub fn user_namespace_inode(&self) -> u64 {
        self.user_namespace_inode
    }

    pub fn is_trusted_user_namespace(&self) -> bool {
        self.trusted_user_namespace
    }

    pub fn uid_map(&self) -> &[IdMapEntry] {
        &self.uid_map
    }

    pub fn gid_map(&self) -> &[IdMapEntry] {
        &self.gid_map
    }

    pub fn executable_inode(&self) -> u64 {
        self.executable_inode
    }
}

/// A principal authenticated by a local transport and its kernel identity.
#[derive(Clone, Debug, Serialize)]
pub struct TransportPrincipal {
    principal: ResolvedPrincipal,
    identity: LinuxProcessIdentity,
    channel: InvocationChannel,
    #[serde(skip)]
    pidfd: Option<Arc<OwnedFd>>,
}

impl PartialEq for TransportPrincipal {
    fn eq(&self, other: &Self) -> bool {
        self.principal == other.principal
            && self.identity == other.identity
            && self.channel == other.channel
    }
}
impl Eq for TransportPrincipal {}

impl TransportPrincipal {
    pub fn principal(&self) -> &ResolvedPrincipal {
        &self.principal
    }

    pub fn identity(&self) -> &LinuxProcessIdentity {
        &self.identity
    }

    pub fn channel(&self) -> InvocationChannel {
        self.channel
    }

    /// Revalidates the retained kernel process handle and executable identity
    /// immediately before a privileged executor is entered.
    pub fn revalidate_for_execution(&self) -> Result<(), PrincipalResolutionError> {
        let pidfd = self
            .pidfd
            .as_ref()
            .ok_or(PrincipalResolutionError::PeerPidfdUnsupported)?;
        self.revalidate_with_reader(&SystemProcReader, pidfd.as_raw_fd())
    }

    fn revalidate_with_reader<R: ProcReader>(
        &self,
        reader: &R,
        pidfd: RawFd,
    ) -> Result<(), PrincipalResolutionError> {
        procfs::verify_process_identity(reader, pidfd, &self.identity)
    }
}

/// A proxy-provided identity assertion, retained as telemetry unless verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DelegatedPrincipal {
    asserted_id: String,
    authenticated: Option<ResolvedPrincipal>,
}

impl DelegatedPrincipal {
    pub fn from_untrusted_cri_metadata(asserted_id: impl Into<String>) -> Self {
        Self {
            asserted_id: asserted_id.into(),
            authenticated: None,
        }
    }

    pub fn asserted_id(&self) -> &str {
        &self.asserted_id
    }

    #[allow(dead_code)] // Reserved for an in-crate authenticated channel verifier.
    pub(crate) fn authenticated(principal: ResolvedPrincipal) -> Self {
        Self {
            asserted_id: principal.id().as_str().to_owned(),
            authenticated: Some(principal),
        }
    }
}

/// Closed delegation policy; v1 defaults to transport authority only.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DelegationPolicy {
    allow_authenticated: bool,
}

impl DelegationPolicy {
    pub fn transport_only() -> Self {
        Self::default()
    }

    #[allow(dead_code)] // Enabled only by trusted in-crate channel policy wiring.
    pub(crate) fn allow_authenticated() -> Self {
        Self {
            allow_authenticated: true,
        }
    }
}

/// The principal selected for authorization after applying proxy policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectivePrincipal {
    transport: TransportPrincipal,
    delegated: Option<DelegatedPrincipal>,
    principal: ResolvedPrincipal,
    used_delegation: bool,
}

impl EffectivePrincipal {
    pub fn transport(&self) -> &TransportPrincipal {
        &self.transport
    }

    pub fn delegated(&self) -> Option<&DelegatedPrincipal> {
        self.delegated.as_ref()
    }

    pub fn principal(&self) -> &ResolvedPrincipal {
        &self.principal
    }

    pub fn used_delegation(&self) -> bool {
        self.used_delegation
    }
}

/// Fail-closed errors from local principal resolution.
#[derive(Debug, Error)]
pub enum PrincipalResolutionError {
    #[error("operating system peer credentials are unavailable")]
    PeerCredentials(#[source] Errno),
    #[error("operating system peer pidfd lookup failed")]
    PeerPidfd(#[source] Errno),
    #[error("the kernel does not provide a peer pidfd")]
    PeerPidfdUnsupported,
    #[error("required process identity fact is unavailable: {fact}")]
    ProcUnavailable {
        fact: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("malformed process identity fact: {fact}")]
    Malformed { fact: &'static str },
    #[error("peer process changed while its identity was resolved")]
    ProcessChanged,
    #[error("peer credentials disagree with the host-visible process identity")]
    CredentialMismatch,
    #[error("peer pidfd does not refer to the credential process")]
    PidfdMismatch,
}

/// Resolves opaque principals exclusively from trusted kernel facts.
///
/// Invocation channels cannot be selected by public callers:
///
/// ```compile_fail
/// use ferro_core::authorization::{InvocationChannel, PrincipalResolver};
/// use std::os::unix::net::UnixStream;
/// let (peer, _) = UnixStream::pair().unwrap();
/// let _ = PrincipalResolver::from_peer_credentials_for_channel(
///     &peer,
///     InvocationChannel::Cri,
/// );
/// ```
pub struct PrincipalResolver;

impl PrincipalResolver {
    pub fn from_peer_credentials<Fd: AsFd>(
        fd: &Fd,
    ) -> Result<TransportPrincipal, PrincipalResolutionError> {
        Self::from_peer_credentials_for_channel(fd, InvocationChannel::DockerUnix)
    }

    pub fn from_cri_peer_credentials<Fd: AsFd>(
        fd: &Fd,
    ) -> Result<TransportPrincipal, PrincipalResolutionError> {
        Self::from_peer_credentials_for_channel(fd, InvocationChannel::Cri)
    }

    pub(crate) fn from_peer_credentials_for_channel<Fd: AsFd>(
        fd: &Fd,
        channel: InvocationChannel,
    ) -> Result<TransportPrincipal, PrincipalResolutionError> {
        Self::resolve_from_sources(&SystemKernelIdentityReader, &SystemProcReader, fd, channel)
    }

    pub fn resolve_proxy(
        transport: TransportPrincipal,
        delegated: Option<DelegatedPrincipal>,
        policy: &DelegationPolicy,
    ) -> EffectivePrincipal {
        let accepted = delegated
            .as_ref()
            .and_then(|assertion| assertion.authenticated.as_ref())
            .filter(|_| policy.allow_authenticated)
            .cloned();
        let used_delegation = accepted.is_some();
        let principal = accepted.unwrap_or_else(|| transport.principal.clone());
        EffectivePrincipal {
            transport,
            delegated,
            principal,
            used_delegation,
        }
    }

    fn resolve_from_sources<K: KernelIdentityReader, R: ProcReader, Fd: AsFd>(
        kernel: &K,
        reader: &R,
        fd: &Fd,
        channel: InvocationChannel,
    ) -> Result<TransportPrincipal, PrincipalResolutionError> {
        let peer = kernel.peer_credentials(fd)?;
        let pidfd = match kernel.peer_pidfd(fd) {
            Ok(pidfd) => pidfd,
            Err(Errno::ENOPROTOOPT) => return Err(PrincipalResolutionError::PeerPidfdUnsupported),
            Err(error) => return Err(PrincipalResolutionError::PeerPidfd(error)),
        };
        let mut principal =
            Self::resolve_with_reader(reader, peer, Some(pidfd.as_raw_fd()), channel)?;
        // The owned pidfd is deliberately retained for the full request/connection
        // lifetime through cloned `TransportPrincipal` values.
        let owned = kernel
            .into_owned_pidfd(pidfd)
            .ok_or(PrincipalResolutionError::PeerPidfdUnsupported)?;
        principal.pidfd = Some(Arc::new(owned));
        Ok(principal)
    }

    fn resolve_with_reader<R: ProcReader>(
        reader: &R,
        peer: KernelPeerCredentials,
        pidfd: Option<RawFd>,
        channel: InvocationChannel,
    ) -> Result<TransportPrincipal, PrincipalResolutionError> {
        let pidfd = pidfd.ok_or(PrincipalResolutionError::PeerPidfdUnsupported)?;
        let identity = procfs::collect_process_identity(reader, peer, pidfd, channel)?;
        let role = if identity.effective_uid() == 0 && identity.trusted_user_namespace {
            Role::Administrator
        } else {
            Role::Developer
        };
        let principal = ResolvedPrincipal::new(
            format!(
                "linux:{}:uid:{}:userns:{}",
                identity.boot_id, peer.uid, identity.user_namespace_inode
            ),
            role,
        );
        Ok(TransportPrincipal {
            principal,
            identity,
            channel,
            pidfd: None,
        })
    }
}
