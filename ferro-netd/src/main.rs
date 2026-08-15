mod grants;
mod policy;
mod protocol;
mod server;

use base64::Engine;
use ed25519_dalek::VerifyingKey;
use grants::{GrantLedger, GrantVerifier};
use nix::sys::socket::{
    getsockopt, recvmsg, sockopt::PeerCredentials, ControlMessageOwned, MsgFlags,
};
use policy::Policy;
use protocol::{response_frame, MAX_FRAME_BYTES};
use server::NetdServer;
use std::{
    fs,
    io::Write,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    time::{SystemTime, UNIX_EPOCH},
};

fn main() {
    let agent_uid = std::env::var("FERROCRATE_AGENT_UID")
        .expect("FERROCRATE_AGENT_UID is required")
        .parse::<u32>()
        .expect("FERROCRATE_AGENT_UID must be numeric");
    let key = std::env::var("FERROCRATE_NETD_SIGNING_KEY")
        .expect("FERROCRATE_NETD_SIGNING_KEY is required");
    let cluster =
        std::env::var("FERROCRATE_CLUSTER_ID").expect("FERROCRATE_CLUSTER_ID is required");
    let node = std::env::var("FERROCRATE_NODE_ID").expect("FERROCRATE_NODE_ID is required");
    let policy = Policy::new(cluster, node, &key).expect("invalid manager signing key");
    let mut server = match std::env::var("FERROCRATE_NETD_WG_PRIVATE_KEY_PATH") {
        Ok(path) => NetdServer::with_wireguard(
            agent_uid,
            policy,
            path.into(),
            std::env::var("FERROCRATE_NETD_WG_LISTEN_PORT")
                .unwrap_or_else(|_| "51820".into())
                .parse()
                .expect("FERROCRATE_NETD_WG_LISTEN_PORT must be numeric"),
        ),
        Err(_) => NetdServer::new(agent_uid, policy),
    };
    let grant_key = std::env::var("FERROCRATE_NETD_GRANT_PUBLIC_KEY")
        .expect("FERROCRATE_NETD_GRANT_PUBLIC_KEY is required");
    let grant_key = base64::engine::general_purpose::STANDARD
        .decode(grant_key)
        .expect("grant public key must be base64");
    let grant_key = VerifyingKey::from_bytes(
        grant_key
            .as_slice()
            .try_into()
            .expect("grant public key must be 32 bytes"),
    )
    .expect("invalid grant public key");
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .expect("kernel boot ID is required")
        .trim()
        .to_owned();
    let grant_journal = std::env::var("FERROCRATE_NETD_GRANT_JOURNAL")
        .unwrap_or_else(|_| "/var/lib/ferrocrate/netd-grants.json".into());
    let grant_issuer = std::env::var("FERROCRATE_NETD_GRANT_ISSUER")
        .unwrap_or_else(|_| "ferrocrate-runtime".into());
    let grant_key_id = std::env::var("FERROCRATE_NETD_GRANT_KEY_ID")
        .expect("FERROCRATE_NETD_GRANT_KEY_ID is required");
    server = server.with_grants(GrantVerifier::new(
        grant_key,
        grant_issuer,
        grant_key_id,
        boot_id,
        GrantLedger::open(grant_journal.into()).expect("grant journal unavailable"),
    ));
    if let Ok(path) = std::env::var("FERROCRATE_NETD_STATE") {
        server = server
            .load_journal(path.into())
            .expect("invalid netd ownership journal");
    }
    let path = std::env::var("FERROCRATE_NETD_SOCKET")
        .unwrap_or_else(|_| "/run/ferrocrate/netd.sock".to_string());
    if let Some(parent) = std::path::Path::new(&path).parent() {
        std::fs::create_dir_all(parent).expect("socket directory");
    }
    if std::path::Path::new(&path).exists() {
        std::fs::remove_file(&path).expect("stale socket");
    }
    let listener = UnixListener::bind(path).expect("bind Unix socket");
    fs::set_permissions(
        std::env::var("FERROCRATE_NETD_SOCKET")
            .unwrap_or_else(|_| "/run/ferrocrate/netd.sock".into()),
        fs::Permissions::from_mode(0o660),
    )
    .expect("secure socket ACL");
    restrict_privileges().expect("failed to restrict netd privileges");
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(stream) => stream,
            Err(_) => continue,
        };
        let credentials = match getsockopt(&stream, PeerCredentials) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let peer_uid = credentials.uid();
        if peer_uid != agent_uid {
            continue;
        }
        let expected_exe = match std::env::var("FERROCRATE_AGENT_EXE") {
            Ok(value) => value,
            Err(_) => continue,
        };
        let peer =
            match authenticate_peer_process(credentials.pid(), std::path::Path::new(&expected_exe))
            {
                Ok(peer) => peer,
                Err(()) => continue,
            };
        let mut prefix = [0_u8; 4];
        if receive_prefix_without_descriptors(&stream, &mut prefix).is_err() {
            continue;
        }
        let length = u32::from_be_bytes(prefix) as usize;
        let mut frame = prefix.to_vec();
        if length <= MAX_FRAME_BYTES {
            let mut body = vec![0_u8; length];
            if receive_body_without_descriptors(&stream, &mut body).is_err() {
                continue;
            }
            frame.extend(body);
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        if !peer.still_valid() {
            continue;
        }
        let response = server.handle_peer(peer_uid, &frame, now);
        if let Ok(bytes) = response_frame(&response) {
            let _ = stream.write_all(&bytes);
        }
    }
}

fn receive_prefix_without_descriptors(
    stream: &std::os::unix::net::UnixStream,
    prefix: &mut [u8; 4],
) -> Result<(), ()> {
    use std::os::fd::AsRawFd;
    let mut iov = [std::io::IoSliceMut::new(prefix)];
    let mut cmsg = nix::cmsg_space!([std::os::fd::RawFd; 1]);
    let message = recvmsg::<()>(
        stream.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg),
        MsgFlags::MSG_WAITALL,
    )
    .map_err(|_| ())?;
    if message.bytes != 4 {
        return Err(());
    }
    if message
        .cmsgs()
        .map_err(|_| ())?
        .any(|item| matches!(item, ControlMessageOwned::ScmRights(_)))
    {
        return Err(());
    }
    Ok(())
}

fn receive_body_without_descriptors(
    stream: &std::os::unix::net::UnixStream,
    body: &mut [u8],
) -> Result<(), ()> {
    use std::os::fd::AsRawFd;
    let mut offset = 0;
    while offset < body.len() {
        let mut iov = [std::io::IoSliceMut::new(&mut body[offset..])];
        let mut cmsg = nix::cmsg_space!([std::os::fd::RawFd; 1]);
        let message = recvmsg::<()>(
            stream.as_raw_fd(),
            &mut iov,
            Some(&mut cmsg),
            MsgFlags::empty(),
        )
        .map_err(|_| ())?;
        if message.bytes == 0
            || message
                .cmsgs()
                .map_err(|_| ())?
                .any(|item| matches!(item, ControlMessageOwned::ScmRights(_)))
        {
            return Err(());
        }
        offset += message.bytes;
    }
    Ok(())
}

struct AuthenticatedPeer {
    _pidfd: std::os::fd::OwnedFd,
    pid: i32,
    executable: std::path::PathBuf,
    start_time: String,
}

impl AuthenticatedPeer {
    fn still_valid(&self) -> bool {
        read_peer_identity(self.pid)
            .is_ok_and(|(exe, start)| exe == self.executable && start == self.start_time)
    }
}

fn authenticate_peer_process(
    pid: i32,
    expected: &std::path::Path,
) -> Result<AuthenticatedPeer, ()> {
    // A pidfd pins the credential PID before any procfs identity lookup. Kernels
    // without pidfd_open are deliberately unsupported at this boundary.
    let raw_pid = pid;
    let pid = rustix::process::Pid::from_raw(raw_pid).ok_or(())?;
    let pidfd =
        rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).map_err(|_| ())?;
    let (actual, start_time) = read_peer_identity(raw_pid)?;
    if actual != expected {
        return Err(());
    }
    Ok(AuthenticatedPeer {
        _pidfd: pidfd,
        pid: raw_pid,
        executable: actual,
        start_time,
    })
}

fn read_peer_identity(pid: i32) -> Result<(std::path::PathBuf, String), ()> {
    let actual = fs::read_link(format!("/proc/{pid}/exe")).map_err(|_| ())?;
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|_| ())?;
    let start_time = stat
        .rsplit(')')
        .next()
        .and_then(|value| value.split_whitespace().nth(19))
        .ok_or(())?
        .to_owned();
    Ok((actual, start_time))
}

#[cfg(test)]
mod tests {
    use super::{authenticate_peer_process, receive_prefix_without_descriptors};

    #[test]
    fn peer_executable_is_bound_through_pidfd() {
        let pid = std::process::id() as i32;
        let executable = std::fs::read_link(format!("/proc/{pid}/exe")).unwrap();
        assert!(authenticate_peer_process(pid, &executable)
            .unwrap()
            .still_valid());
        assert!(authenticate_peer_process(
            pid,
            std::path::Path::new("/definitely/not/ferro-agent")
        )
        .is_err());
    }

    #[test]
    fn rejects_scm_rights_at_the_transport_boundary() {
        use std::os::fd::AsRawFd;
        let (receiver, sender) = std::os::unix::net::UnixStream::pair().unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();
        let bytes = 4_u32.to_be_bytes();
        let iov = [std::io::IoSlice::new(&bytes)];
        let rights = [file.as_raw_fd()];
        let control = [nix::sys::socket::ControlMessage::ScmRights(&rights)];
        nix::sys::socket::sendmsg::<()>(
            sender.as_raw_fd(),
            &iov,
            &control,
            nix::sys::socket::MsgFlags::empty(),
            None,
        )
        .unwrap();
        assert!(receive_prefix_without_descriptors(&receiver, &mut [0; 4]).is_err());
    }
}

fn restrict_privileges() -> Result<(), Box<dyn std::error::Error>> {
    nix::sys::prctl::set_no_new_privs()?;
    let allowed: caps::CapsHashSet = [
        caps::Capability::CAP_NET_ADMIN,
        caps::Capability::CAP_BPF,
        caps::Capability::CAP_PERFMON,
    ]
    .into_iter()
    .collect();
    caps::set(None, caps::CapSet::Effective, &allowed)?;
    caps::set(None, caps::CapSet::Permitted, &allowed)?;
    caps::set(None, caps::CapSet::Inheritable, &allowed)?;
    caps::clear(None, caps::CapSet::Ambient)?;
    Ok(())
}
