mod policy;
mod protocol;
mod server;

use std::os::unix::net::UnixListener;
use policy::Policy;

fn main() {
    let _uid = std::env::var("FERROCRATE_AGENT_UID").expect("FERROCRATE_AGENT_UID is required").parse::<u32>().expect("FERROCRATE_AGENT_UID must be numeric");
    let key = std::env::var("FERROCRATE_NETD_SIGNING_KEY").expect("FERROCRATE_NETD_SIGNING_KEY is required");
    let cluster = std::env::var("FERROCRATE_CLUSTER_ID").expect("FERROCRATE_CLUSTER_ID is required");
    let node = std::env::var("FERROCRATE_NODE_ID").expect("FERROCRATE_NODE_ID is required");
    let _policy = Policy::new(cluster, node, &key).expect("invalid manager signing key");
    let path = std::env::var("FERROCRATE_NETD_SOCKET").unwrap_or_else(|_| "/run/ferrocrate/netd.sock".to_string());
    if let Some(parent) = std::path::Path::new(&path).parent() { std::fs::create_dir_all(parent).expect("socket directory"); }
    if std::path::Path::new(&path).exists() { std::fs::remove_file(&path).expect("stale socket"); }
    let _listener = UnixListener::bind(path).expect("bind Unix socket");
    loop { std::thread::park(); }
}
