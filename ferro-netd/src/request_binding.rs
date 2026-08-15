use crate::protocol::{NetdRequest, RejectionCode};
use ferro_core::authorization::helper_grant::{GrantAction, GrantParameters};

pub(crate) fn request_parameters(
    request: &NetdRequest,
) -> Result<(GrantAction, GrantParameters), RejectionCode> {
    let (action, operation, fields) = match request {
        NetdRequest::ApplyOverlay {
            overlay_id,
            mode,
            peers,
            routes,
            addresses,
        } => {
            let interfaces = crate::interface_identity::overlay_interfaces(overlay_id);
            (
                GrantAction::NetworkCreate,
                "overlay.apply",
                vec![
                    ("overlay_id".into(), overlay_id.clone()),
                    ("overlay_mode".into(), mode.as_str().into()),
                    ("bridge_ifname".into(), interfaces.bridge.clone()),
                    ("wireguard_ifname".into(), interfaces.wireguard.clone()),
                    ("address_interface".into(), interfaces.bridge.clone()),
                    (
                        "route_interface".into(),
                        match mode {
                            crate::protocol::OverlayMode::WireGuard => interfaces.wireguard.clone(),
                            crate::protocol::OverlayMode::BridgeOnly => interfaces.bridge.clone(),
                        },
                    ),
                    (
                        "forwarding_required".into(),
                        (*mode == crate::protocol::OverlayMode::WireGuard).to_string(),
                    ),
                    (
                        "peers".into(),
                        serde_json::to_string(peers).map_err(|_| RejectionCode::InvalidFrame)?,
                    ),
                    (
                        "routes".into(),
                        serde_json::to_string(routes).map_err(|_| RejectionCode::InvalidFrame)?,
                    ),
                    (
                        "addresses".into(),
                        serde_json::to_string(addresses)
                            .map_err(|_| RejectionCode::InvalidFrame)?,
                    ),
                ],
            )
        }
        NetdRequest::RemoveOverlay { overlay_id } => {
            (GrantAction::NetworkDelete, "overlay.delete", {
                let interfaces = crate::interface_identity::overlay_interfaces(overlay_id);
                vec![
                    ("overlay_id".into(), overlay_id.clone()),
                    ("bridge_ifname".into(), interfaces.bridge),
                    ("wireguard_ifname".into(), interfaces.wireguard),
                ]
            })
        }
        NetdRequest::AttachEndpoint {
            overlay_id,
            endpoint_id,
            netns,
        } => (GrantAction::NetworkAttach, "endpoint.attach", {
            let interfaces = crate::interface_identity::overlay_interfaces(overlay_id);
            vec![
                ("overlay_id".into(), overlay_id.clone()),
                ("bridge_ifname".into(), interfaces.bridge),
                ("endpoint_id".into(), endpoint_id.clone()),
                ("netns".into(), netns.clone().unwrap_or_default()),
            ]
        }),
        NetdRequest::DetachEndpoint {
            overlay_id,
            endpoint_id,
        } => (GrantAction::NetworkDetach, "endpoint.detach", {
            let interfaces = crate::interface_identity::overlay_interfaces(overlay_id);
            vec![
                ("overlay_id".into(), overlay_id.clone()),
                ("bridge_ifname".into(), interfaces.bridge),
                ("endpoint_id".into(), endpoint_id.clone()),
            ]
        }),
        NetdRequest::Inspect { overlay_id } => (
            GrantAction::NetworkInspect,
            "overlay.inspect",
            vec![("overlay_id".into(), overlay_id.clone())],
        ),
    };
    GrantParameters::new(operation, fields, vec![])
        .map(|p| (action, p))
        .map_err(|_| RejectionCode::PolicyViolation)
}

pub(crate) fn request_overlay_id(request: &NetdRequest) -> &str {
    match request {
        NetdRequest::ApplyOverlay { overlay_id, .. }
        | NetdRequest::RemoveOverlay { overlay_id }
        | NetdRequest::AttachEndpoint { overlay_id, .. }
        | NetdRequest::DetachEndpoint { overlay_id, .. }
        | NetdRequest::Inspect { overlay_id } => overlay_id,
    }
}
