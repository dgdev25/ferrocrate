use super::*;

pub(crate) use ferro_desktop::launch::PortOwner;
use ferro_desktop::launch::{published_owners, verify_replacement};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct LaunchPort {
    pub port: u16,
    pub available: bool,
    pub suggested: u16,
    #[serde(default)]
    pub conflict: Option<PortOwner>,
}

pub(crate) fn preflight(ports: &[u16]) -> Result<Vec<LaunchPort>, String> {
    if ports.is_empty() {
        return Ok(Vec::new());
    }
    if ports.len() > 32
        || ports.contains(&0)
        || ports.iter().collect::<std::collections::HashSet<_>>().len() != ports.len()
    {
        return Err("request up to 32 distinct nonzero TCP ports".into());
    }
    let backend = desktop_backend()?;
    let list = run_backend_command_with(
        backend,
        "ferrocrate",
        &[
            "ps".into(),
            "--all".into(),
            "--format".into(),
            "json".into(),
        ],
        &[],
        Vec::new(),
    );
    if !list.ok {
        return Err(format!("Cannot inspect port ownership: {}", list.stderr));
    }
    let records: JsonValue =
        serde_json::from_str(&list.stdout).map_err(|error| error.to_string())?;
    let excluded: Vec<u16> = records
        .as_array()
        .ok_or("invalid container list")?
        .iter()
        .filter(|record| {
            record
                .get("State")
                .or_else(|| record.get("status"))
                .and_then(JsonValue::as_str)
                == Some("running")
        })
        .flat_map(|record| {
            record
                .get("Ports")
                .or_else(|| record.get("ports"))
                .and_then(JsonValue::as_array)
                .into_iter()
                .flatten()
        })
        .filter(|mapping| mapping.get("Type").or_else(|| mapping.get("protocol")).and_then(JsonValue::as_str).unwrap_or("tcp") == "tcp")
        .filter_map(|mapping| {
            mapping
                .get("PublicPort")
                .or_else(|| mapping.get("host_port"))
                .and_then(JsonValue::as_u64)
                .and_then(|port| u16::try_from(port).ok())
        })
        .collect();
    let mut args = vec![
        "port-probe".to_string(),
        "--ports".to_string(),
        ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(","),
    ];
    if !excluded.is_empty() {
        args.extend([
            "--exclude".into(),
            excluded
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
        ]);
    }
    // Explicit selected-backend dispatch: never use the macOS local-helper fallback.
    let probe = run_backend_command_with(backend, "ferro-desktop", &args, &[], Vec::new());
    if !probe.ok {
        return Err(format!("Runtime-host port probe failed. Install the matching FerroCrate desktop helper on that host. {}", probe.stderr));
    }
    let mut results: Vec<LaunchPort> =
        serde_json::from_str(&probe.stdout).map_err(|error| error.to_string())?;
    if results.len() != ports.len()
        || results
            .iter()
            .zip(ports)
            .any(|(probe, port)| probe.port != *port || probe.suggested == 0)
    {
        return Err("invalid runtime-host port probe response".into());
    }
    for result in &mut results {
        let owners = published_owners(&records, result.port)?;
        if owners.len() == 1 {
            result.conflict = owners.into_iter().next();
        }
        if result.conflict.is_some() {
            result.available = false;
        }
    }
    Ok(results)
}

pub(crate) fn replace(
    port: u16,
    expected: PortOwner,
    confirmation: String,
) -> Result<CommandResult, String> {
    let current = preflight(&[port])?;
    verify_replacement(&expected, current[0].conflict.as_ref(), &confirmation)?;
    let stopped = run_desktop_action(DesktopAction::StopContainer, Some(expected.id.clone()));
    if !stopped.ok {
        return Ok(stopped);
    }
    // Full IDs remain the destructive target. Re-read identity after stopping so a
    // disappearing container or failed inspection cannot trigger a different removal.
    let detail = get_container_detail(expected.id.clone())?;
    if detail.id != expected.id
        || detail.name.trim_start_matches('/') != expected.name
        || detail.image != expected.image
    {
        return Err("Container identity changed after stopping; removal cancelled.".into());
    }
    Ok(run_desktop_action(
        DesktopAction::RemoveContainer,
        Some(expected.id),
    ))
}
