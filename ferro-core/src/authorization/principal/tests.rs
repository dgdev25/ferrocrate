use std::{
    cell::RefCell,
    collections::{HashMap, HashSet, VecDeque},
    io,
    os::fd::{AsFd, AsRawFd, RawFd},
    os::unix::net::UnixStream,
    path::Path,
};

use nix::errno::Errno;

use super::{
    procfs::{KernelIdentityReader, KernelPeerCredentials, ProcReader},
    *,
};

const PID: u32 = 4242;
const PIDFD: RawFd = 99;
const BOOT_ID: &str = "123e4567-e89b-12d3-a456-426614174000";

struct FakePidfd;

impl AsRawFd for FakePidfd {
    fn as_raw_fd(&self) -> RawFd {
        PIDFD
    }
}

struct UnsupportedPidfdKernel;

impl KernelIdentityReader for UnsupportedPidfdKernel {
    type PidFd = FakePidfd;

    fn peer_credentials<Fd: AsFd>(
        &self,
        _fd: &Fd,
    ) -> Result<KernelPeerCredentials, PrincipalResolutionError> {
        Ok(credentials(1001, 2001))
    }

    fn peer_pidfd<Fd: AsFd>(&self, _fd: &Fd) -> Result<Self::PidFd, Errno> {
        Err(Errno::ENOPROTOOPT)
    }
}

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
        reader.inodes.insert(format!("/proc/{PID}/exe"), 9001);
        reader.inodes.insert("/proc/self/ns/user".into(), 100);
        reader.insert(
            format!("/proc/self/fdinfo/{PIDFD}"),
            format!("Pid:\t{PID}\n"),
        );
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
    resolve_for_channel(reader, credentials, InvocationChannel::DockerUnix)
}

fn resolve_for_channel(
    reader: &FakeProcReader,
    credentials: KernelPeerCredentials,
    channel: InvocationChannel,
) -> Result<TransportPrincipal, PrincipalResolutionError> {
    PrincipalResolver::resolve_with_reader(
        reader,
        credentials,
        Some(PIDFD),
        channel,
        PeerAuthMode::Pidfd,
    )
}

#[test]
fn host_visible_ids_and_supplementary_groups_are_bound() {
    let principal =
        resolve(&FakeProcReader::fixture(), credentials(1001, 2001)).expect("resolved identity");

    assert_eq!(principal.identity().uids(), [1000, 1001, 1002, 1003]);
    assert_eq!(principal.identity().gids(), [2000, 2001, 2002, 2003]);
    assert_eq!(principal.identity().supplementary_groups(), &[20, 30]);
}

#[test]
fn process_lifetime_boot_and_namespace_facts_are_bound() {
    let principal =
        resolve(&FakeProcReader::fixture(), credentials(1001, 2001)).expect("resolved identity");
    let identity = principal.identity();

    assert_eq!(identity.start_time_ticks(), 777);
    assert_eq!(identity.boot_id(), BOOT_ID);
    assert_eq!(identity.user_namespace_inode(), 100);
    assert!(identity.is_trusted_user_namespace());
    assert_eq!(identity.executable_inode(), 9001);
    assert_eq!(identity.uid_map()[0].host_start(), 0);
    assert_eq!(identity.gid_map()[0].length(), u32::MAX);
}

#[test]
fn executable_replacement_is_rejected_before_execution() {
    let mut reader = FakeProcReader::fixture();
    let principal = resolve(&reader, credentials(1001, 2001)).expect("resolved identity");
    reader.inodes.insert(format!("/proc/{PID}/exe"), 9002);

    let error = principal
        .revalidate_with_reader(&reader, Some(PIDFD))
        .expect_err("changed executable rejected");

    assert!(matches!(error, PrincipalResolutionError::ProcessChanged));
}

#[test]
fn identity_maps_in_a_different_user_namespace_do_not_grant_host_administrator() {
    let mut reader = FakeProcReader::fixture();
    reader.insert(
        format!("/proc/{PID}/status"),
        "Name:\tworker\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nGroups:\t0\n",
    );
    reader.inodes.insert(format!("/proc/{PID}/ns/user"), 200);

    let principal = resolve(&reader, credentials(0, 0)).expect("namespace identity");

    assert!(!principal.identity().is_trusted_user_namespace());
    assert!(!principal.principal().is_host_administrator());
    assert_eq!(principal.principal().role(), Role::Developer);
}

#[test]
fn missing_peer_pidfd_fails_closed_without_a_start_time_fallback() {
    let error = PrincipalResolver::resolve_with_reader(
        &FakeProcReader::fixture(),
        credentials(1001, 2001),
        None,
        InvocationChannel::DockerUnix,
        PeerAuthMode::Pidfd,
    )
    .expect_err("missing pidfd rejected");

    assert!(matches!(
        error,
        PrincipalResolutionError::PeerPidfdUnsupported
    ));
}

#[test]
fn unsupported_kernel_peer_pidfd_error_fails_at_the_socket_boundary() {
    let (peer, _other_end) = UnixStream::pair().expect("socket pair");

    let error = PrincipalResolver::resolve_from_sources(
        &UnsupportedPidfdKernel,
        &FakeProcReader::fixture(),
        &peer,
        InvocationChannel::DockerUnix,
        PeerAuthMode::Pidfd,
    )
    .expect_err("unsupported kernel rejected");

    assert!(matches!(
        error,
        PrincipalResolutionError::PeerPidfdUnsupported
    ));
}

#[test]
fn unsupported_kernel_peer_pidfd_uses_explicit_legacy_peercred_policy() {
    let (peer, _other_end) = UnixStream::pair().expect("socket pair");

    let principal = PrincipalResolver::resolve_from_sources(
        &UnsupportedPidfdKernel,
        &FakeProcReader::fixture(),
        &peer,
        InvocationChannel::DockerUnix,
        PeerAuthMode::LegacyPeercred,
    )
    .expect("explicit legacy fallback resolves peer credentials");

    assert_eq!(principal.identity().effective_uid(), 1001);
    assert_eq!(principal.identity().effective_gid(), 2001);
    assert_eq!(principal.peer_auth_mode(), PeerAuthMode::LegacyPeercred);
}

#[test]
fn legacy_peercred_revalidation_rejects_process_replacement() {
    let mut reader = FakeProcReader::fixture();
    let principal = PrincipalResolver::resolve_with_reader(
        &reader,
        credentials(1001, 2001),
        None,
        InvocationChannel::DockerUnix,
        PeerAuthMode::LegacyPeercred,
    )
    .expect("legacy identity");
    reader.inodes.insert(format!("/proc/{PID}/exe"), 9002);

    let error = principal
        .revalidate_with_reader(&reader, None)
        .expect_err("changed executable rejected");
    assert!(matches!(error, PrincipalResolutionError::ProcessChanged));
}

#[test]
fn unsupported_peer_pidfd_explains_secure_kernel_requirement() {
    let message = PrincipalResolutionError::PeerPidfdUnsupported.to_string();
    assert!(message.contains("SO_PEERPIDFD"));
    assert!(message.contains("secure CRI peer identity"));
    assert!(message.contains("upgrade the kernel"));
    assert!(message.contains("--peer-auth legacy-peercred"));
}

#[test]
fn pidfd_for_a_different_process_fails_closed() {
    let mut reader = FakeProcReader::fixture();
    reader.insert(
        format!("/proc/self/fdinfo/{PIDFD}"),
        format!("Pid:\t{}\n", PID + 1),
    );

    let error = resolve(&reader, credentials(1001, 2001)).expect_err("foreign pidfd rejected");

    assert!(matches!(error, PrincipalResolutionError::PidfdMismatch));
}

#[test]
fn every_invocation_channel_has_a_closed_supplementary_group_policy() {
    let expected = [
        (
            InvocationChannel::Cli,
            SupplementaryGroupPolicy::AcceptKernelReported,
        ),
        (
            InvocationChannel::DockerUnix,
            SupplementaryGroupPolicy::AcceptKernelReported,
        ),
        (
            InvocationChannel::Compose,
            SupplementaryGroupPolicy::AcceptKernelReported,
        ),
        (InvocationChannel::Cri, SupplementaryGroupPolicy::Ignore),
        (InvocationChannel::Manager, SupplementaryGroupPolicy::Ignore),
        (
            InvocationChannel::Internal,
            SupplementaryGroupPolicy::EffectiveGidOnly,
        ),
    ];

    for (channel, policy) in expected {
        assert_eq!(channel.supplementary_group_policy(), policy);
    }
}

#[test]
fn channel_policy_is_applied_to_supplementary_groups() {
    let mut reader = FakeProcReader::fixture();
    reader.insert(
        format!("/proc/{PID}/status"),
        "Name:\tworker\nUid:\t1000\t1001\t1002\t1003\nGid:\t2000\t2001\t2002\t2003\nGroups:\t20 2001 30\n",
    );

    let cri = resolve_for_channel(&reader, credentials(1001, 2001), InvocationChannel::Cri)
        .expect("CRI identity");
    let internal = resolve_for_channel(
        &reader,
        credentials(1001, 2001),
        InvocationChannel::Internal,
    )
    .expect("internal identity");

    assert!(cri.identity().supplementary_groups().is_empty());
    assert_eq!(internal.identity().supplementary_groups(), &[2001]);
}

#[test]
fn trusted_namespace_root_is_host_administrator() {
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

    let error = resolve(&reader, credentials(1001, 2001)).expect_err("unreadable proc rejected");

    assert!(matches!(
        error,
        PrincipalResolutionError::ProcUnavailable { fact: "status", .. }
    ));
}

#[test]
fn authenticated_delegation_precedes_the_transport_principal_when_policy_allows_it() {
    let transport =
        resolve(&FakeProcReader::fixture(), credentials(1001, 2001)).expect("transport identity");
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
