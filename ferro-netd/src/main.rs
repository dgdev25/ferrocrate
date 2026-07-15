mod policy;
mod protocol;
mod server;

use std::{io::{Read, Write}, os::unix::net::UnixListener, time::{SystemTime, UNIX_EPOCH}};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use policy::Policy;
use protocol::{response_frame, MAX_FRAME_BYTES};
use server::NetdServer;

fn main() {
    let _uid = std::env::var("FERROCRATE_AGENT_UID").expect("FERROCRATE_AGENT_UID is required").parse::<u32>().expect("FERROCRATE_AGENT_UID must be numeric");
    let key = std::env::var("FERROCRATE_NETD_SIGNING_KEY").expect("FERROCRATE_NETD_SIGNING_KEY is required");
    let cluster = std::env::var("FERROCRATE_CLUSTER_ID").expect("FERROCRATE_CLUSTER_ID is required");
    let node = std::env::var("FERROCRATE_NODE_ID").expect("FERROCRATE_NODE_ID is required");
    let policy = Policy::new(cluster, node, &key).expect("invalid manager signing key");
    let mut server = match std::env::var("FERROCRATE_NETD_WG_PRIVATE_KEY_PATH") {
        Ok(path) => NetdServer::with_wireguard(_uid, policy, path.into(), std::env::var("FERROCRATE_NETD_WG_LISTEN_PORT").unwrap_or_else(|_| "51820".into()).parse().expect("FERROCRATE_NETD_WG_LISTEN_PORT must be numeric")),
        Err(_) => NetdServer::new(_uid, policy),
    };
    if let Ok(path) = std::env::var("FERROCRATE_NETD_STATE") {
        server = server.load_journal(path.into()).expect("invalid netd ownership journal");
    }
    let path = std::env::var("FERROCRATE_NETD_SOCKET").unwrap_or_else(|_| "/run/ferrocrate/netd.sock".to_string());
    if let Some(parent) = std::path::Path::new(&path).parent() { std::fs::create_dir_all(parent).expect("socket directory"); }
    if std::path::Path::new(&path).exists() { std::fs::remove_file(&path).expect("stale socket"); }
    let listener = UnixListener::bind(path).expect("bind Unix socket");
    restrict_privileges().expect("failed to restrict netd privileges");
    for stream in listener.incoming() {
        let mut stream = match stream { Ok(stream) => stream, Err(_) => continue };
        let peer_uid = getsockopt(&stream, PeerCredentials).map(|credentials| credentials.uid()).unwrap_or(u32::MAX);
        let mut prefix = [0_u8; 4];
        if stream.read_exact(&mut prefix).is_err() { continue; }
        let length = u32::from_be_bytes(prefix) as usize;
        let mut frame = prefix.to_vec();
        if length <= MAX_FRAME_BYTES {
            let mut body = vec![0_u8; length];
            if stream.read_exact(&mut body).is_err() { continue; }
            frame.extend(body);
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |duration| duration.as_secs());
        let response = server.handle_peer(peer_uid, &frame, now);
        if let Ok(bytes) = response_frame(&response) { let _ = stream.write_all(&bytes); }
    }
}

fn restrict_privileges() -> Result<(), Box<dyn std::error::Error>> {
    nix::sys::prctl::set_no_new_privs()?;
    let allowed: caps::CapsHashSet = [
        caps::Capability::CAP_NET_ADMIN,
        caps::Capability::CAP_BPF,
        caps::Capability::CAP_PERFMON,
    ].into_iter().collect();
    caps::set(None, caps::CapSet::Effective, &allowed)?;
    caps::set(None, caps::CapSet::Permitted, &allowed)?;
    caps::set(None, caps::CapSet::Inheritable, &allowed)?;
    caps::clear(None, caps::CapSet::Ambient)?;
    Ok(())
}
