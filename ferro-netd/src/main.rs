use base64::Engine;
use ed25519_dalek::VerifyingKey;
use ferro_core::authorization::{AuthorizationMode, AuthorizationServiceMode};
use ferro_netd::{
    grants::{GrantLedger, GrantVerifier},
    policy::Policy,
    server::NetdServer,
    transport::serve_authenticated_one,
};
use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};
use serde::Deserialize;
use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixListener},
    time::{SystemTime, UNIX_EPOCH},
};

fn main() {
    let service_mode = authorization_service_mode().expect("invalid authorization service mode");
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
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .expect("kernel boot ID is required")
        .trim()
        .to_owned();
    server = server.with_authorization_identity(service_mode, boot_id.clone());
    let grant_journal = std::env::var("FERROCRATE_NETD_GRANT_JOURNAL")
        .unwrap_or_else(|_| "/var/lib/ferrocrate/netd-grants.json".into());
    let grant_issuer = std::env::var("FERROCRATE_NETD_GRANT_ISSUER")
        .unwrap_or_else(|_| "ferrocrate-runtime".into());
    match service_mode.mode() {
        AuthorizationMode::Disabled => {
            if std::env::var_os("FERROCRATE_NETD_GRANT_PUBLIC_KEYS_JSON").is_some()
                || std::env::var_os("FERROCRATE_NETD_GRANT_PUBLIC_KEY").is_some()
            {
                panic!("disabled netd cannot configure grant verification keys");
            }
        }
        AuthorizationMode::Enforce | AuthorizationMode::Shadow => {
            server = server.with_grants(
                load_grant_verifier(
                    grant_issuer,
                    boot_id,
                    GrantLedger::open(grant_journal.into()).expect("grant journal unavailable"),
                )
                .expect("invalid bounded grant verification keyring"),
            );
        }
    }
    let state_path = std::env::var("FERROCRATE_NETD_STATE")
        .expect("FERROCRATE_NETD_STATE is required for durable revision replay protection");
    server = server
        .load_journal(state_path.into())
        .expect("invalid netd ownership journal");
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
    let expected_exe = std::env::var("FERROCRATE_AGENT_EXE")
        .expect("FERROCRATE_AGENT_EXE is required for peer attestation");
    loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        let _ = serve_authenticated_one(
            &listener,
            &mut server,
            agent_uid,
            std::path::Path::new(&expected_exe),
            now,
        );
    }
}

fn authorization_service_mode() -> Result<AuthorizationServiceMode, String> {
    let mode = std::env::var("FERROCRATE_AUTHORIZATION_MODE")
        .map_err(|_| "FERROCRATE_AUTHORIZATION_MODE is required".to_string())?;
    let digest = std::env::var("FERROCRATE_AUTHORIZATION_POLICY_DIGEST")
        .ok()
        .map(|value| {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(value)
                .map_err(|_| "policy digest must be base64")?;
            bytes
                .try_into()
                .map_err(|_| "policy digest must decode to 32 bytes")
        })
        .transpose()?;
    AuthorizationServiceMode::parse(&mode, digest).map_err(|error| error.to_string())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationKeyConfig {
    key_id: String,
    public_key: String,
    status: KeyStatus,
}

#[derive(Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum KeyStatus {
    Active,
    Overlap,
    Retired,
}

fn load_grant_verifier(
    issuer: String,
    boot_id: String,
    ledger: GrantLedger,
) -> Result<GrantVerifier, String> {
    let encoded = std::env::var("FERROCRATE_NETD_GRANT_KEYRING_JSON")
        .map_err(|_| "FERROCRATE_NETD_GRANT_KEYRING_JSON is required".to_string())?;
    if encoded.len() > 16 * 1024 {
        return Err("keyring exceeds 16 KiB".into());
    }
    let entries: Vec<VerificationKeyConfig> =
        serde_json::from_str(&encoded).map_err(|_| "keyring JSON is invalid".to_string())?;
    if entries.is_empty() || entries.len() > 8 {
        return Err("keyring must contain 1..=8 entries".into());
    }
    let mut active = entries
        .iter()
        .filter(|entry| entry.status != KeyStatus::Retired);
    let first = active
        .next()
        .ok_or_else(|| "keyring has no active verification key".to_string())?;
    let decode = |entry: &VerificationKeyConfig| -> Result<VerifyingKey, String> {
        if entry.key_id.is_empty() || entry.key_id.len() > 64 {
            return Err("invalid key ID".into());
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&entry.public_key)
            .map_err(|_| "public key is not base64".to_string())?;
        VerifyingKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| "public key must be 32 bytes".to_string())?,
        )
        .map_err(|_| "invalid public key".to_string())
    };
    let mut verifier = GrantVerifier::new(decode(first)?, issuer, &first.key_id, boot_id, ledger);
    for entry in active {
        verifier
            .add_verification_key(&entry.key_id, decode(entry)?)
            .map_err(|error| error.to_string())?;
    }
    Ok(verifier)
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
