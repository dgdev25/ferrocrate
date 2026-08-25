//! Opt-in LAN image mirror discovery and integrity helpers.

use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

pub const SERVICE_TYPE: &str = "_ferrocrate-registry._tcp.local.";
const MIRROR_NONCE_TTL: Duration = Duration::from_secs(30);

#[derive(Default)]
pub struct MirrorNonceStore {
    issued: HashMap<String, Instant>,
}

impl MirrorNonceStore {
    pub fn issue(&mut self) -> String {
        self.issue_at(Instant::now())
    }

    fn issue_at(&mut self, now: Instant) -> String {
        self.issued.retain(|_, issued| now.duration_since(*issued) <= MIRROR_NONCE_TTL);
        let nonce = hex::encode(rand::random::<[u8; 32]>());
        self.issued.insert(nonce.clone(), now);
        nonce
    }

    pub fn verify_and_consume(
        &mut self,
        secret: &str,
        nonce: &str,
        digest: &str,
        supplied_auth: &str,
    ) -> bool {
        self.verify_and_consume_at(secret, nonce, digest, supplied_auth, Instant::now())
    }

    fn verify_and_consume_at(
        &mut self,
        secret: &str,
        nonce: &str,
        digest: &str,
        supplied_auth: &str,
        now: Instant,
    ) -> bool {
        let Some(issued) = self.issued.remove(nonce) else { return false };
        if now.duration_since(issued) > MIRROR_NONCE_TTL { return false; }
        constant_time_eq(
            mirror_request_auth(secret, nonce, digest).as_bytes(),
            supplied_auth.as_bytes(),
        )
    }
}

pub fn mirror_request_auth(secret: &str, nonce: &str, digest: &str) -> String {
    let mut message = Vec::with_capacity(nonce.len() + digest.len());
    message.extend_from_slice(nonce.as_bytes());
    message.extend_from_slice(digest.as_bytes());
    hex::encode(hmac_sha256(secret.as_bytes(), &message))
}

pub fn mirror_peer_proof(secret: &str, nonce: &str) -> String {
    let mut message = Vec::with_capacity(4 + nonce.len());
    message.extend_from_slice(b"peer");
    message.extend_from_slice(nonce.as_bytes());
    hex::encode(hmac_sha256(secret.as_bytes(), &message))
}

pub fn verify_peer_proof(secret: &str, nonce: &str, supplied: Option<&str>) -> bool {
    supplied.is_some_and(|proof| {
        constant_time_eq(mirror_peer_proof(secret, nonce).as_bytes(), proof.as_bytes())
    })
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut normalized = [0u8; BLOCK];
    if key.len() > BLOCK {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_key = [0x36u8; BLOCK];
    let mut outer_key = [0x5cu8; BLOCK];
    for index in 0..BLOCK {
        inner_key[index] ^= normalized[index];
        outer_key[index] ^= normalized[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_key);
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_key);
    outer.update(inner);
    outer.finalize().into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    for index in 0..left.len().max(right.len()) {
        difference |= usize::from(left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0));
    }
    difference == 0
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerAdvertisement {
    pub instance_id: String,
    pub digests: BTreeSet<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MirrorPeer {
    pub instance_id: String,
    pub address: IpAddr,
    pub port: u16,
    pub digests: BTreeSet<String>,
}

#[derive(Clone, Debug)]
pub struct DiscoveryReport {
    pub peers: Vec<MirrorPeer>,
    pub elapsed: Duration,
    pub mdns_peers: usize,
    pub probed: bool,
}

impl MirrorPeer {
    pub fn base_url(&self) -> String {
        match self.address {
            IpAddr::V4(address) => format!("http://{address}:{}", self.port),
            IpAddr::V6(address) => format!("http://[{address}]:{}", self.port),
        }
    }
}

pub fn discover(timeout: Duration, wanted_digest: Option<&str>) -> Result<Vec<MirrorPeer>, String> {
    discover_report(timeout, wanted_digest).map(|report| report.peers)
}

pub fn discover_report(
    timeout: Duration,
    wanted_digest: Option<&str>,
) -> Result<DiscoveryReport, String> {
    use mdns_sd::{ServiceDaemon, ServiceEvent};
    let started = Instant::now();
    let daemon = ServiceDaemon::new().map_err(|error| error.to_string())?;
    let receiver = daemon.browse(SERVICE_TYPE).map_err(|error| error.to_string())?;
    let deadline = Instant::now() + timeout;
    let mut peers = std::env::var("FERROCRATE_LAN_MIRROR_PEERS")
        .ok()
        .into_iter()
        .flat_map(|value| value.split(',').map(str::to_owned).collect::<Vec<_>>())
        .filter_map(|value| value.parse::<std::net::SocketAddr>().ok())
        .map(|address| MirrorPeer {
            instance_id: format!("static-{}", address.ip()),
            address: address.ip(),
            port: address.port(),
            digests: BTreeSet::new(),
        })
        .collect::<Vec<_>>();
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        let Ok(event) = receiver.recv_timeout(remaining.min(Duration::from_millis(100))) else {
            continue;
        };
        if let ServiceEvent::ServiceResolved(info) = event {
            let properties = info.get_properties().iter().map(|property| {
                (property.key().to_ascii_lowercase(), property.val_str().to_string())
            });
            let Some(advertisement) = parse_txt(properties) else { continue };
            for address in info.get_addresses() {
                peers.push(MirrorPeer {
                    instance_id: advertisement.instance_id.clone(),
                    address: *address,
                    port: info.get_port(),
                    digests: advertisement.digests.clone(),
                });
            }
        }
    }
    let mdns_peers = peers.len();
    let probe_port = std::env::var("FERROCRATE_LAN_MIRROR_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(7422);
    let mut probe_peers = probe_local_slash24(probe_port);
    let probed = true;
    peers.append(&mut probe_peers);
    peers.sort_by_key(|peer| {
        let preferred = wanted_digest.is_some_and(|digest| peer.digests.contains(digest));
        (!preferred, peer.instance_id.clone(), peer.address)
    });
    peers.dedup_by(|left, right| left.address == right.address && left.port == right.port);
    Ok(DiscoveryReport {
        peers,
        elapsed: started.elapsed(),
        mdns_peers,
        probed,
    })
}

pub fn probe_candidates(local: Ipv4Addr) -> Vec<Ipv4Addr> {
    let [a, b, c, _] = local.octets();
    (1..=254)
        .map(|last| Ipv4Addr::new(a, b, c, last))
        .filter(|candidate| *candidate != local)
        .collect()
}

pub fn parse_probe_headers(instance: &str, digests: &str) -> Option<PeerAdvertisement> {
    parse_txt([
        ("instance".to_string(), instance.to_string()),
        ("digests".to_string(), digests.to_string()),
    ])
}

pub fn discovery_summary(elapsed: Duration, peers: usize, probed: bool) -> String {
    format!(
        "lan mirror: browsed {} ms, {peers} peers{}",
        elapsed.as_millis(),
        if probed { "; unicast /24 probe attempted" } else { "" }
    )
}

fn probe_local_slash24(port: u16) -> Vec<MirrorPeer> {
    use std::sync::mpsc;
    let local_addresses = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|interface| match interface.ip() {
            IpAddr::V4(ip) if ip.is_private() && !ip.is_loopback() => Some(ip),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let candidates = local_addresses
        .iter()
        .flat_map(|address| probe_candidates(*address))
        .collect::<BTreeSet<_>>();
    let (sender, receiver) = mpsc::channel();
    let Ok(client) = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_millis(200))
        .timeout(Duration::from_millis(200))
        .build()
    else {
        return Vec::new();
    };
    std::thread::scope(|scope| {
        for address in candidates {
            let sender = sender.clone();
            let client = client.clone();
            scope.spawn(move || {
                let Ok(response) = client.get(format!("http://{address}:{port}/v2/")).send() else { return };
                if !response.status().is_success() { return; }
                let instance = response.headers().get("x-ferrocrate-instance").and_then(|value| value.to_str().ok()).unwrap_or("");
                let digests = response.headers().get("x-ferrocrate-digests").and_then(|value| value.to_str().ok()).unwrap_or("");
                if let Some(advertisement) = parse_probe_headers(instance, digests) {
                    let _ = sender.send(MirrorPeer {
                        instance_id: advertisement.instance_id,
                        address: IpAddr::V4(address),
                        port,
                        digests: advertisement.digests,
                    });
                }
            });
        }
    });
    drop(sender);
    receiver.into_iter().collect()
}

pub fn register(
    instance_id: &str,
    address: IpAddr,
    port: u16,
    digests: &[String],
) -> Result<mdns_sd::ServiceDaemon, String> {
    use mdns_sd::{ServiceDaemon, ServiceInfo};
    let daemon = ServiceDaemon::new().map_err(|error| error.to_string())?;
    let digest_list = digests.iter().take(6).cloned().collect::<Vec<_>>().join(",");
    let properties = [("instance", instance_id), ("digests", digest_list.as_str())];
    let hostname = format!("{instance_id}.local.");
    let service = ServiceInfo::new(
        SERVICE_TYPE,
        instance_id,
        &hostname,
        address,
        port,
        &properties[..],
    )
    .map_err(|error| error.to_string())?;
    daemon.register(service).map_err(|error| error.to_string())?;
    Ok(daemon)
}

pub fn parse_txt(properties: impl IntoIterator<Item = (String, String)>) -> Option<PeerAdvertisement> {
    let values = properties.into_iter().collect::<std::collections::BTreeMap<_, _>>();
    let instance_id = values.get("instance")?.trim().to_string();
    if instance_id.is_empty() {
        return None;
    }
    let digests = values
        .get("digests")
        .into_iter()
        .flat_map(|value| value.split(','))
        .filter(|value| valid_sha256_digest(value))
        .map(str::to_string)
        .collect();
    Some(PeerAdvertisement { instance_id, digests })
}

pub fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn verify_bytes(bytes: &[u8], expected: &str) -> bool {
    valid_sha256_digest(expected) && format!("sha256:{:x}", Sha256::digest(bytes)) == expected
}

pub fn verified_peer_or_fallback<E>(
    peer: Option<Vec<u8>>,
    expected: &str,
    fallback: impl FnOnce() -> Result<Vec<u8>, E>,
) -> Result<(Vec<u8>, bool), E> {
    if let Some(bytes) = peer.filter(|bytes| verify_bytes(bytes, expected)) {
        return Ok((bytes, true));
    }
    fallback().map(|bytes| (bytes, false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_announcement_and_ignores_invalid_digest_hints() {
        let good = format!("sha256:{}", "a".repeat(64));
        let advert = parse_txt([
            ("instance".to_string(), "host-a".to_string()),
            ("digests".to_string(), format!("bad,{good}")),
        ])
        .expect("valid advertisement");
        assert_eq!(advert.instance_id, "host-a");
        assert_eq!(advert.digests, BTreeSet::from([good]));
    }

    #[test]
    fn rejects_missing_instance_id() {
        assert!(parse_txt([("digests".to_string(), String::new())]).is_none());
    }

    #[test]
    fn digest_verification_rejects_mismatched_content() {
        let expected = format!("sha256:{:x}", Sha256::digest(b"expected"));
        assert!(verify_bytes(b"expected", &expected));
        assert!(!verify_bytes(b"tampered", &expected));
    }

    #[test]
    fn mismatch_falls_back_to_registry_bytes() {
        let expected = format!("sha256:{:x}", Sha256::digest(b"registry"));
        let (bytes, from_peer) = verified_peer_or_fallback(
            Some(b"corrupt".to_vec()),
            &expected,
            || Ok::<_, ()>(b"registry".to_vec()),
        ).expect("fallback succeeds");
        assert_eq!(bytes, b"registry");
        assert!(!from_peer);
    }

    #[test]
    fn probe_candidates_cover_local_slash24_but_not_self_or_network_edges() {
        let candidates = probe_candidates("192.168.122.9".parse().unwrap());
        assert_eq!(candidates.len(), 253);
        assert!(!candidates.contains(&"192.168.122.0".parse().unwrap()));
        assert!(!candidates.contains(&"192.168.122.9".parse().unwrap()));
        assert!(!candidates.contains(&"192.168.122.255".parse().unwrap()));
        assert!(candidates.contains(&"192.168.122.1".parse().unwrap()));
    }

    #[test]
    fn probe_metadata_parses_instance_and_digest_hints() {
        let digest = format!("sha256:{}", "b".repeat(64));
        let advert = parse_probe_headers("host-a", &digest).expect("probe metadata");
        assert_eq!(advert.instance_id, "host-a");
        assert_eq!(advert.digests, BTreeSet::from([digest]));
        assert!(parse_probe_headers("", "").is_none());
    }

    #[test]
    fn discovery_summary_keeps_zero_peer_result_visible() {
        assert_eq!(
            discovery_summary(Duration::from_millis(5000), 0, true),
            "lan mirror: browsed 5000 ms, 0 peers; unicast /24 probe attempted"
        );
    }

    #[test]
    fn mirror_auth_rejects_wrong_secret_and_consumes_nonce() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let mut nonces = MirrorNonceStore::default();
        let nonce = nonces.issue_at(Instant::now());
        let wrong = mirror_request_auth("wrong", &nonce, &digest);
        assert!(!nonces.verify_and_consume_at("right", &nonce, &digest, &wrong, Instant::now()));
        let nonce = nonces.issue_at(Instant::now());
        let right = mirror_request_auth("right", &nonce, &digest);
        assert!(nonces.verify_and_consume_at("right", &nonce, &digest, &right, Instant::now()));
        assert!(!nonces.verify_and_consume_at("right", &nonce, &digest, &right, Instant::now()));
    }

    #[test]
    fn mirror_auth_rejects_expired_nonce() {
        let issued = Instant::now();
        let digest = format!("sha256:{}", "b".repeat(64));
        let mut nonces = MirrorNonceStore::default();
        let nonce = nonces.issue_at(issued);
        let auth = mirror_request_auth("secret", &nonce, &digest);
        assert!(!nonces.verify_and_consume_at(
            "secret",
            &nonce,
            &digest,
            &auth,
            issued + Duration::from_secs(31),
        ));
    }

    #[test]
    fn client_rejects_missing_or_invalid_peer_proof() {
        let nonce = "00".repeat(32);
        assert!(!verify_peer_proof("secret", &nonce, None));
        assert!(!verify_peer_proof("secret", &nonce, Some(&"00".repeat(32))));
        let proof = mirror_peer_proof("secret", &nonce);
        assert!(verify_peer_proof("secret", &nonce, Some(&proof)));
    }
}
