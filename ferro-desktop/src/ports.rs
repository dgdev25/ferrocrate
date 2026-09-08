use std::collections::HashSet;
use std::net::{Ipv4Addr, TcpListener};

#[derive(Debug, PartialEq, Eq)]
pub struct PortProbe {
    pub port: u16,
    pub available: bool,
    pub suggested: u16,
}

/// Probes IPv4 TCP on the runtime host. Suggestions are advisory: launch must
/// still handle another process binding between this check and container start.
pub fn probe_ports(ports: &[u16], excluded: &[u16]) -> Result<Vec<PortProbe>, String> {
    if ports.len() > 32
        || ports.contains(&0)
        || ports.iter().collect::<HashSet<_>>().len() != ports.len()
    {
        return Err("request up to 32 distinct nonzero TCP ports".into());
    }
    let mut held = Vec::new();
    let mut results = Vec::new();
    for &port in ports {
        let preferred = if excluded.contains(&port) {
            None
        } else {
            TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).ok()
        };
        let available = preferred.is_some();
        let listener = match preferred {
            Some(listener) => listener,
            None => {
                let mut chosen = None;
                for _ in 0..128 {
                    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0))
                        .map_err(|error| error.to_string())?;
                    let candidate = listener
                        .local_addr()
                        .map_err(|error| error.to_string())?
                        .port();
                    if !excluded.contains(&candidate) && !ports.contains(&candidate) {
                        chosen = Some(listener);
                        break;
                    }
                }
                chosen.ok_or("no alternative TCP port found")?
            }
        };
        results.push(PortProbe {
            port,
            available,
            suggested: listener
                .local_addr()
                .map_err(|error| error.to_string())?
                .port(),
        });
        held.push(listener);
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn occupied_host_port_gets_a_different_bindable_suggestion() {
        let occupied = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let port = occupied.local_addr().unwrap().port();
        let result = probe_ports(&[port], &[]).unwrap();
        assert!(!result[0].available);
        assert_ne!(result[0].suggested, port);
        assert!(TcpListener::bind((Ipv4Addr::UNSPECIFIED, result[0].suggested)).is_ok());
    }
    #[test]
    fn declared_container_ports_are_excluded_even_without_a_listener() {
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let result = probe_ports(&[port], &[port]).unwrap();
        assert!(!result[0].available);
        assert_ne!(result[0].suggested, port);
    }
    #[test]
    fn duplicate_zero_and_unbounded_requests_fail_closed() {
        assert!(probe_ports(&[0], &[]).is_err());
        assert!(probe_ports(&[8080, 8080], &[]).is_err());
        assert!(probe_ports(&(1..34).collect::<Vec<_>>(), &[]).is_err());
    }
}
