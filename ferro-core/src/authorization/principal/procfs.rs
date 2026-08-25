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

use super::{
    IdMapEntry, InvocationChannel, LinuxProcessIdentity, PrincipalResolutionError,
    SupplementaryGroupPolicy,
};

const MAX_PROC_FACT_BYTES: usize = 1024 * 1024;
const MAX_ID_MAP_ENTRIES: usize = 340;
const MAX_SUPPLEMENTARY_GROUPS: usize = 65_536;

#[derive(Clone, Copy)]
pub(super) struct KernelPeerCredentials {
    pub(super) pid: u32,
    pub(super) uid: u32,
    pub(super) gid: u32,
}

pub(super) trait KernelIdentityReader {
    type PidFd: AsRawFd;

    fn peer_credentials<Fd: AsFd>(
        &self,
        fd: &Fd,
    ) -> Result<KernelPeerCredentials, PrincipalResolutionError>;

    fn peer_pidfd<Fd: AsFd>(&self, fd: &Fd) -> Result<Self::PidFd, Errno>;

    fn retain_owned_pidfd(&self, _pidfd: Self::PidFd) -> Option<std::os::fd::OwnedFd> {
        None
    }
}

pub(super) struct SystemKernelIdentityReader;

impl KernelIdentityReader for SystemKernelIdentityReader {
    type PidFd = std::os::fd::OwnedFd;

    fn peer_credentials<Fd: AsFd>(
        &self,
        fd: &Fd,
    ) -> Result<KernelPeerCredentials, PrincipalResolutionError> {
        let peer = getsockopt(fd, sockopt::PeerCredentials)
            .map_err(PrincipalResolutionError::PeerCredentials)?;
        let pid = u32::try_from(peer.pid())
            .map_err(|_| PrincipalResolutionError::Malformed { fact: "peer pid" })?;
        if pid == 0 {
            return Err(PrincipalResolutionError::Malformed { fact: "peer pid" });
        }
        Ok(KernelPeerCredentials {
            pid,
            uid: peer.uid(),
            gid: peer.gid(),
        })
    }

    fn peer_pidfd<Fd: AsFd>(&self, fd: &Fd) -> Result<Self::PidFd, Errno> {
        getsockopt(fd, sockopt::PeerPidfd)
    }

    fn retain_owned_pidfd(&self, pidfd: Self::PidFd) -> Option<std::os::fd::OwnedFd> {
        Some(pidfd)
    }
}

pub(super) trait ProcReader {
    fn read_to_string(&self, path: &Path) -> io::Result<String>;
    fn inode(&self, path: &Path) -> io::Result<u64>;
}

pub(super) struct SystemProcReader;

impl ProcReader for SystemProcReader {
    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        fs::read_to_string(path)
    }

    fn inode(&self, path: &Path) -> io::Result<u64> {
        Ok(fs::metadata(path)?.ino())
    }
}

pub(super) fn collect_process_identity<R: ProcReader>(
    reader: &R,
    peer: KernelPeerCredentials,
    pidfd: Option<RawFd>,
    channel: InvocationChannel,
) -> Result<LinuxProcessIdentity, PrincipalResolutionError> {
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
    let supplementary_groups = apply_group_policy(
        parse_groups(&status)?,
        peer.gid,
        channel.supplementary_group_policy(),
    );
    let uid_map = parse_id_map(
        &read_fact(reader, &proc_dir.join("uid_map"), "uid map")?,
        "uid map",
    )?;
    let gid_map = parse_id_map(
        &read_fact(reader, &proc_dir.join("gid_map"), "gid map")?,
        "gid map",
    )?;
    let user_namespace_inode = inode_fact(reader, &proc_dir.join("ns/user"), "user namespace")?;
    let executable_inode = inode_fact(reader, &proc_dir.join("exe"), "executable identity")?;
    let trusted_user_namespace_inode = inode_fact(
        reader,
        Path::new("/proc/self/ns/user"),
        "trusted user namespace",
    )?;
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
    Ok(LinuxProcessIdentity {
        pid: peer.pid,
        uids,
        gids,
        supplementary_groups,
        start_time_ticks,
        boot_id,
        user_namespace_inode,
        trusted_user_namespace: user_namespace_inode == trusted_user_namespace_inode,
        uid_map,
        gid_map,
        executable_inode,
    })
}

pub(super) fn verify_legacy_process_identity<R: ProcReader>(
    reader: &R,
    identity: &LinuxProcessIdentity,
) -> Result<(), PrincipalResolutionError> {
    let proc_dir = PathBuf::from(format!("/proc/{}", identity.pid()));
    let stat = read_fact(reader, &proc_dir.join("stat"), "stat")?;
    let (pid, start) = parse_stat(&stat)?;
    let executable_inode = inode_fact(reader, &proc_dir.join("exe"), "executable identity")?;
    if pid != identity.pid()
        || start != identity.start_time_ticks()
        || executable_inode != identity.executable_inode()
    {
        return Err(PrincipalResolutionError::ProcessChanged);
    }
    Ok(())
}

pub(super) fn verify_process_identity<R: ProcReader>(
    reader: &R,
    pidfd: RawFd,
    identity: &LinuxProcessIdentity,
) -> Result<(), PrincipalResolutionError> {
    verify_pidfd(reader, pidfd, identity.pid())?;
    let proc_dir = PathBuf::from(format!("/proc/{}", identity.pid()));
    let stat = read_fact(reader, &proc_dir.join("stat"), "stat")?;
    let (pid, start) = parse_stat(&stat)?;
    let executable_inode = inode_fact(reader, &proc_dir.join("exe"), "executable identity")?;
    if pid != identity.pid()
        || start != identity.start_time_ticks()
        || executable_inode != identity.executable_inode()
    {
        return Err(PrincipalResolutionError::ProcessChanged);
    }
    Ok(())
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

fn apply_group_policy(
    groups: Vec<u32>,
    effective_gid: u32,
    policy: SupplementaryGroupPolicy,
) -> Vec<u32> {
    match policy {
        SupplementaryGroupPolicy::Ignore => Vec::new(),
        SupplementaryGroupPolicy::EffectiveGidOnly => groups
            .into_iter()
            .filter(|group| *group == effective_gid)
            .collect(),
        SupplementaryGroupPolicy::AcceptKernelReported => groups,
    }
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
