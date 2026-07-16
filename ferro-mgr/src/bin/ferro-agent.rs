use std::{collections::BTreeMap, net::Ipv4Addr, path::PathBuf};

use ferro_mgr::agent::{ipam::Ipam, local_api::{LocalApi, OverlayConfig}};
use ipnet::Ipv4Net;

fn required(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is required"))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime_uid = required("FERROCRATE_AGENT_RUNTIME_UID")?.parse::<u32>()?;
    let lease_expiry = required("FERROCRATE_AGENT_LEASE_EXPIRY_UNIX")?.parse::<i64>()?;
    let pool = required("FERROCRATE_AGENT_IPV4_POOL")?.parse::<Ipv4Net>()?;
    let gateway = required("FERROCRATE_AGENT_IPV4_GATEWAY")?.parse::<Ipv4Addr>()?;
    let state = PathBuf::from(required("FERROCRATE_AGENT_IPAM_STATE")?);
    let socket = PathBuf::from(required("FERROCRATE_AGENT_SOCKET")?);
    let reserved = std::env::var("FERROCRATE_AGENT_IPV4_RESERVED").unwrap_or_default()
        .split(',').filter(|entry| !entry.is_empty()).map(str::parse).collect::<Result<Vec<Ipv4Addr>, _>>()?;
    let overlays = std::env::var("FERROCRATE_AGENT_OVERLAYS_JSON").unwrap_or_else(|_| "{}".into());
    let overlays = serde_json::from_str::<BTreeMap<String, OverlayConfig>>(&overlays)?;
    let ipam = Ipam::with_state(pool, gateway, reserved, state)?;
    let api = LocalApi::new(runtime_uid, lease_expiry, ipam);
    for (overlay_id, config) in overlays { api.register_overlay(overlay_id, config)?; }
    api.serve_unix(socket)?;
    Ok(())
}
