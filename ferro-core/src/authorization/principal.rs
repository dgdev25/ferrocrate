//! Kernel-backed Linux process and proxy principal resolution.

use std::{
    fs, io,
    os::{
        fd::{AsFd, AsRawFd, RawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};

use nix::{
    errno::Errno,
    sys::socket::{getsockopt, sockopt},
};
use serde::Serialize;
use thiserror::Error;

use super::{ResolvedPrincipal, Role};

const MAX_PROC_FACT_BYTES: usize = 1024 * 1024;
const MAX_ID_MAP_ENTRIES: usize = 340;
const MAX_SUPPLEMENTARY_GROUPS: usize = 65_536;

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

/// Process identity facts read from the kernel and tied to one PID lifetime.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LinuxProcessIdentity {
    pid: u32,
    uids: [u32; 4],
    gids: [u32; 4],
    supplementary_groups: Vec<u32>,
    start_time_ticks: u64,
    boot_id: String,
    user_namespace_inode: u64,
    initial_user_namespace: bool,
    uid_map: Vec<IdMapEntry>,
    gid_map: Vec<IdMapEntry>,
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

    pub fn is_initial_user_namespace(&self) -> bool {
        self.initial_user_namespace
    }

    pub fn uid_map(&self) -> &[IdMapEntry] {
        &self.uid_map
    }

    pub fn gid_map(&self) -> &[IdMapEntry] {
        &self.gid_map
    }
}

/// A principal authenticated by a local transport and its kernel identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TransportPrincipal {
    principal: ResolvedPrincipal,
    identity: LinuxProcessIdentity,
    channel: InvocationChannel,
}

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

#[derive(Clone, Copy)]
struct KernelPeerCredentials {
    pid: u32,
    uid: u32,
    gid: u32,
}

trait ProcReader {
    fn read_to_string(&self, path: &Path) -> io::Result<String>;
    fn inode(&self, path: &Path) -> io::Result<u64>;
}

struct SystemProcReader;

impl ProcReader for SystemProcReader {
    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        fs::read_to_string(path)
    }

    fn inode(&self, path: &Path) -> io::Result<u64> {
        Ok(fs::metadata(path)?.ino())
    }
}

/// Resolves opaque principals exclusively from trusted kernel facts.
pub struct PrincipalResolver;

impl PrincipalResolver {
    pub fn from_peer_credentials<Fd: AsFd>(
        fd: &Fd,
    ) -> Result<TransportPrincipal, PrincipalResolutionError> {
        Self::from_peer_credentials_for_channel(fd, InvocationChannel::DockerUnix)
    }

    pub fn from_peer_credentials_for_channel<Fd: AsFd>(
        fd: &Fd,
        channel: InvocationChannel,
    ) -> Result<TransportPrincipal, PrincipalResolutionError> {
        let peer = getsockopt(fd, sockopt::PeerCredentials)
            .map_err(PrincipalResolutionError::PeerCredentials)?;
        let pid = u32::try_from(peer.pid())
            .map_err(|_| PrincipalResolutionError::Malformed { fact: "peer pid" })?;
        if pid == 0 {
            return Err(PrincipalResolutionError::Malformed { fact: "peer pid" });
        }
        let pidfd = match getsockopt(fd, sockopt::PeerPidfd) {
            Ok(pidfd) => Some(pidfd),
            Err(Errno::ENOPROTOOPT) => None,
            Err(error) => return Err(PrincipalResolutionError::PeerPidfd(error)),
        };
        Self::resolve_with_reader(
            &SystemProcReader,
            KernelPeerCredentials {
                pid,
                uid: peer.uid(),
                gid: peer.gid(),
            },
            pidfd.as_ref().map(AsRawFd::as_raw_fd),
            channel,
        )
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

    fn resolve_with_reader<R: ProcReader>(
        reader: &R,
        peer: KernelPeerCredentials,
        pidfd: Option<RawFd>,
        channel: InvocationChannel,
    ) -> Result<TransportPrincipal, PrincipalResolutionError> {
        if let Some(pidfd) = pidfd {
            verify_pidfd(reader, pidfd, peer.pid)?;
        }
        let proc_dir = PathBuf::from(format!("/proc/{}", peer.pid));
        let first_stat = read_fact(reader, &proc_dir.join("stat"), "stat")?;
        let (stat_pid, start_time_ticks) = parse_stat(&first_stat)?;
        if stat_pid != peer.pid {
            return Err(PrincipalResolutionError::ProcessChanged);
        }
        let status = read_fact(reader, &proc_dir.join("status"), "status")?;
        let uids = parse_status_ids(&status, "Uid:", "uids")?;
        let gids = parse_status_ids(&status, "Gid:", "gids")?;
        if uids[1] != peer.uid || gids[1] != peer.gid {
            return Err(PrincipalResolutionError::CredentialMismatch);
        }
        let supplementary_groups = parse_groups(&status)?;
        let uid_map = parse_id_map(
            &read_fact(reader, &proc_dir.join("uid_map"), "uid map")?,
            "uid map",
        )?;
        let gid_map = parse_id_map(
            &read_fact(reader, &proc_dir.join("gid_map"), "gid map")?,
            "gid map",
        )?;
        let user_namespace_inode = inode_fact(reader, &proc_dir.join("ns/user"), "user namespace")?;
        let boot_id = read_fact(
            reader,
            Path::new("/proc/sys/kernel/random/boot_id"),
            "boot id",
        )?
        .trim()
        .to_owned();
        if uuid::Uuid::parse_str(&boot_id).is_err() {
            return Err(PrincipalResolutionError::Malformed { fact: "boot id" });
        }
        let second_stat = read_fact(reader, &proc_dir.join("stat"), "stat")?;
        let (second_pid, second_start) = parse_stat(&second_stat)?;
        if second_pid != peer.pid || second_start != start_time_ticks {
            return Err(PrincipalResolutionError::ProcessChanged);
        }
        if let Some(pidfd) = pidfd {
            verify_pidfd(reader, pidfd, peer.pid)?;
        }
        let identity = LinuxProcessIdentity {
            pid: peer.pid,
            uids,
            gids,
            supplementary_groups,
            start_time_ticks,
            boot_id,
            user_namespace_inode,
            initial_user_namespace: is_initial_id_map(&uid_map) && is_initial_id_map(&gid_map),
            uid_map,
            gid_map,
        };
        let host_administrator = identity.effective_uid() == 0
            && identity.initial_user_namespace
            && identity.uid_map.iter().any(|entry| {
                entry.namespace_start == 0 && entry.host_start == 0 && entry.length > 0
            });
        let role = if host_administrator {
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
        })
    }
}

fn read_fact<R: ProcReader>(
    reader: &R,
    path: &Path,
    fact: &'static str,
) -> Result<String, PrincipalResolutionError> {
    let value = reader
        .read_to_string(path)
        .map_err(|source| PrincipalResolutionError::ProcUnavailable { fact, source })?;
    if value.len() > MAX_PROC_FACT_BYTES {
        return Err(PrincipalResolutionError::Malformed { fact });
    }
    Ok(value)
}

fn inode_fact<R: ProcReader>(
    reader: &R,
    path: &Path,
    fact: &'static str,
) -> Result<u64, PrincipalResolutionError> {
    reader
        .inode(path)
        .map_err(|source| PrincipalResolutionError::ProcUnavailable { fact, source })
}

fn parse_stat(value: &str) -> Result<(u32, u64), PrincipalResolutionError> {
    let (pid, rest) = value
        .split_once(' ')
        .ok_or(PrincipalResolutionError::Malformed { fact: "stat" })?;
    let fields = rest
        .rsplit_once(") ")
        .ok_or(PrincipalResolutionError::Malformed { fact: "stat" })?
        .1
        .split_whitespace()
        .collect::<Vec<_>>();
    let pid = pid
        .parse()
        .map_err(|_| PrincipalResolutionError::Malformed { fact: "stat" })?;
    let start_time = fields
        .get(19)
        .ok_or(PrincipalResolutionError::Malformed { fact: "stat" })?
        .parse()
        .map_err(|_| PrincipalResolutionError::Malformed { fact: "stat" })?;
    Ok((pid, start_time))
}

fn parse_status_ids(
    status: &str,
    prefix: &str,
    fact: &'static str,
) -> Result<[u32; 4], PrincipalResolutionError> {
    let values = status
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .ok_or(PrincipalResolutionError::Malformed { fact })?
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<Vec<u32>, _>>()
        .map_err(|_| PrincipalResolutionError::Malformed { fact })?;
    values
        .try_into()
        .map_err(|_| PrincipalResolutionError::Malformed { fact })
}

fn parse_groups(status: &str) -> Result<Vec<u32>, PrincipalResolutionError> {
    let groups = status
        .lines()
        .find_map(|line| line.strip_prefix("Groups:"))
        .ok_or(PrincipalResolutionError::Malformed { fact: "groups" })?
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<Vec<u32>, _>>()
        .map_err(|_| PrincipalResolutionError::Malformed { fact: "groups" })?;
    if groups.len() > MAX_SUPPLEMENTARY_GROUPS {
        return Err(PrincipalResolutionError::Malformed { fact: "groups" });
    }
    Ok(groups)
}

fn parse_id_map(
    value: &str,
    fact: &'static str,
) -> Result<Vec<IdMapEntry>, PrincipalResolutionError> {
    let entries = value
        .lines()
        .map(|line| {
            let values = line
                .split_whitespace()
                .map(str::parse)
                .collect::<Result<Vec<u32>, _>>()
                .map_err(|_| PrincipalResolutionError::Malformed { fact })?;
            let [namespace_start, host_start, length]: [u32; 3] = values
                .try_into()
                .map_err(|_| PrincipalResolutionError::Malformed { fact })?;
            if length == 0
                || namespace_start.checked_add(length - 1).is_none()
                || host_start.checked_add(length - 1).is_none()
            {
                return Err(PrincipalResolutionError::Malformed { fact });
            }
            Ok(IdMapEntry {
                namespace_start,
                host_start,
                length,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if entries.is_empty() || entries.len() > MAX_ID_MAP_ENTRIES {
        return Err(PrincipalResolutionError::Malformed { fact });
    }
    Ok(entries)
}

fn is_initial_id_map(entries: &[IdMapEntry]) -> bool {
    entries
        == [IdMapEntry {
            namespace_start: 0,
            host_start: 0,
            length: u32::MAX,
        }]
}

fn verify_pidfd<R: ProcReader>(
    reader: &R,
    pidfd: RawFd,
    expected_pid: u32,
) -> Result<(), PrincipalResolutionError> {
    let fdinfo = read_fact(
        reader,
        &PathBuf::from(format!("/proc/self/fdinfo/{pidfd}")),
        "peer pidfd",
    )?;
    let pid = fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("Pid:"))
        .and_then(|value| value.trim().parse::<u32>().ok());
    if pid == Some(expected_pid) {
        Ok(())
    } else {
        Err(PrincipalResolutionError::PidfdMismatch)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        collections::{HashMap, HashSet, VecDeque},
        io,
        path::Path,
    };

    use super::*;

    const PID: u32 = 4242;
    const BOOT_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

    #[derive(Default)]
    struct FakeProcReader {
        contents: RefCell<HashMap<String, VecDeque<String>>>,
        inodes: HashMap<String, u64>,
        denied: HashSet<String>,
    }

    impl FakeProcReader {
        fn fixture() -> Self {
            let mut reader = Self::default();
            reader.insert(format!("/proc/{PID}/stat"), stat_line(PID, 777));
            reader.insert(
                format!("/proc/{PID}/status"),
                "Name:\tworker\nUid:\t1000\t1001\t1002\t1003\nGid:\t2000\t2001\t2002\t2003\nGroups:\t20 30\n",
            );
            reader.insert(format!("/proc/{PID}/uid_map"), "0 0 4294967295\n");
            reader.insert(format!("/proc/{PID}/gid_map"), "0 0 4294967295\n");
            reader.insert("/proc/sys/kernel/random/boot_id", BOOT_ID);
            reader.inodes.insert(format!("/proc/{PID}/ns/user"), 100);
            reader.inodes.insert("/proc/1/ns/user".into(), 100);
            reader
        }

        fn insert(&mut self, path: impl Into<String>, contents: impl Into<String>) {
            self.contents
                .get_mut()
                .insert(path.into(), VecDeque::from([contents.into()]));
        }

        fn sequence(&mut self, path: impl Into<String>, contents: Vec<String>) {
            self.contents.get_mut().insert(path.into(), contents.into());
        }
    }

    impl ProcReader for FakeProcReader {
        fn read_to_string(&self, path: &Path) -> io::Result<String> {
            let key = path.to_string_lossy().into_owned();
            if self.denied.contains(&key) {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            let mut contents = self.contents.borrow_mut();
            let values = contents
                .get_mut(&key)
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            if values.len() > 1 {
                Ok(values.pop_front().expect("non-empty fake read sequence"))
            } else {
                values
                    .front()
                    .cloned()
                    .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
            }
        }

        fn inode(&self, path: &Path) -> io::Result<u64> {
            self.inodes
                .get(path.to_string_lossy().as_ref())
                .copied()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }
    }

    fn credentials(uid: u32, gid: u32) -> KernelPeerCredentials {
        KernelPeerCredentials { pid: PID, uid, gid }
    }

    fn resolve(
        reader: &FakeProcReader,
        credentials: KernelPeerCredentials,
    ) -> Result<TransportPrincipal, PrincipalResolutionError> {
        PrincipalResolver::resolve_with_reader(
            reader,
            credentials,
            None,
            InvocationChannel::DockerUnix,
        )
    }

    #[test]
    fn host_visible_ids_and_supplementary_groups_are_bound() {
        let principal = resolve(&FakeProcReader::fixture(), credentials(1001, 2001))
            .expect("resolved identity");

        assert_eq!(principal.identity().uids(), [1000, 1001, 1002, 1003]);
        assert_eq!(principal.identity().gids(), [2000, 2001, 2002, 2003]);
        assert_eq!(principal.identity().supplementary_groups(), &[20, 30]);
    }

    #[test]
    fn process_lifetime_boot_and_namespace_facts_are_bound() {
        let principal = resolve(&FakeProcReader::fixture(), credentials(1001, 2001))
            .expect("resolved identity");
        let identity = principal.identity();

        assert_eq!(identity.start_time_ticks(), 777);
        assert_eq!(identity.boot_id(), BOOT_ID);
        assert_eq!(identity.user_namespace_inode(), 100);
        assert!(identity.is_initial_user_namespace());
        assert_eq!(identity.uid_map()[0].host_start(), 0);
        assert_eq!(identity.gid_map()[0].length(), u32::MAX);
    }

    #[test]
    fn namespace_root_is_not_host_administrator() {
        let mut reader = FakeProcReader::fixture();
        reader.insert(
            format!("/proc/{PID}/status"),
            "Name:\tworker\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t0\n",
        );
        reader.insert(format!("/proc/{PID}/uid_map"), "0 100000 65536\n");
        reader.insert(format!("/proc/{PID}/gid_map"), "0 100000 65536\n");
        reader.inodes.insert(format!("/proc/{PID}/ns/user"), 200);

        let principal = resolve(&reader, credentials(0, 0)).expect("namespace identity");

        assert!(!principal.principal().is_host_administrator());
        assert_eq!(principal.principal().role(), Role::Developer);
    }

    #[test]
    fn initial_namespace_root_is_host_administrator() {
        let mut reader = FakeProcReader::fixture();
        reader.insert(
            format!("/proc/{PID}/status"),
            "Name:\tworker\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t0\n",
        );

        let principal = resolve(&reader, credentials(0, 0)).expect("host identity");

        assert!(principal.principal().is_host_administrator());
        assert_eq!(principal.principal().role(), Role::Administrator);
    }

    #[test]
    fn pid_reuse_between_proc_reads_fails_closed() {
        let mut reader = FakeProcReader::fixture();
        reader.sequence(
            format!("/proc/{PID}/stat"),
            vec![stat_line(PID, 777), stat_line(PID, 778)],
        );

        let error = resolve(&reader, credentials(1001, 2001)).expect_err("PID reuse rejected");

        assert!(matches!(error, PrincipalResolutionError::ProcessChanged));
    }

    #[test]
    fn inaccessible_proc_identity_fails_closed() {
        let mut reader = FakeProcReader::fixture();
        reader.denied.insert(format!("/proc/{PID}/status"));

        let error =
            resolve(&reader, credentials(1001, 2001)).expect_err("unreadable proc rejected");

        assert!(matches!(
            error,
            PrincipalResolutionError::ProcUnavailable { fact: "status", .. }
        ));
    }

    #[test]
    fn authenticated_delegation_precedes_the_transport_principal_when_policy_allows_it() {
        let transport = resolve(&FakeProcReader::fixture(), credentials(1001, 2001))
            .expect("transport identity");
        let delegated = DelegatedPrincipal::authenticated(ResolvedPrincipal::new(
            "workload:tenant-a:builder",
            Role::Operator,
        ));

        let effective = PrincipalResolver::resolve_proxy(
            transport,
            Some(delegated),
            &DelegationPolicy::allow_authenticated(),
        );

        assert_eq!(
            effective.principal().id().as_str(),
            "workload:tenant-a:builder"
        );
        assert_eq!(effective.principal().role(), Role::Operator);
        assert!(effective.used_delegation());
    }

    fn stat_line(pid: u32, start_time: u64) -> String {
        format!(
            "{pid} (worker with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 {start_time} 0\n"
        )
    }
}
