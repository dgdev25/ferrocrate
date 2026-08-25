//! Opt-in LAN image mirror discovery and integrity helpers.

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub const SERVICE_TYPE: &str = "_ferrocrate-registry._tcp.local.";

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

impl MirrorPeer {
    pub fn base_url(&self) -> String {
        match self.address {
            IpAddr::V4(address) => format!("http://{address}:{}", self.port),
            IpAddr::V6(address) => format!("http://[{address}]:{}", self.port),
        }
    }
}

pub fn discover(timeout: Duration, wanted_digest: Option<&str>) -> Result<Vec<MirrorPeer>, String> {
    use mdns_sd::{ServiceDaemon, ServiceEvent};
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
    peers.sort_by_key(|peer| {
        let preferred = wanted_digest.is_some_and(|digest| peer.digests.contains(digest));
        (!preferred, peer.instance_id.clone(), peer.address)
    });
    peers.dedup_by(|left, right| left.address == right.address && left.port == right.port);
    Ok(peers)
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
}
