use crate::protocol::{NetdRequest, RejectionCode};
use ferro_core::authorization::helper_grant::{GrantAction, GrantParameters};

pub(crate) fn request_parameters(
    request: &NetdRequest,
) -> Result<(GrantAction, GrantParameters), RejectionCode> {
    let (action, operation, fields) = match request {
        NetdRequest::ApplyOverlay {
            overlay_id,
            peers,
            routes,
            addresses,
        } => (
            GrantAction::NetworkCreate,
            "overlay.apply",
            vec![
                ("overlay_id".into(), overlay_id.clone()),
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
                    serde_json::to_string(addresses).map_err(|_| RejectionCode::InvalidFrame)?,
                ),
            ],
        ),
        NetdRequest::RemoveOverlay { overlay_id } => (
            GrantAction::NetworkDelete,
            "overlay.delete",
            vec![("overlay_id".into(), overlay_id.clone())],
        ),
        NetdRequest::AttachEndpoint {
            overlay_id,
            endpoint_id,
            netns,
        } => (
            GrantAction::NetworkAttach,
            "endpoint.attach",
            vec![
                ("overlay_id".into(), overlay_id.clone()),
                ("endpoint_id".into(), endpoint_id.clone()),
                ("netns".into(), netns.clone().unwrap_or_default()),
            ],
        ),
        NetdRequest::DetachEndpoint {
            overlay_id,
            endpoint_id,
        } => (
            GrantAction::NetworkDetach,
            "endpoint.detach",
            vec![
                ("overlay_id".into(), overlay_id.clone()),
                ("endpoint_id".into(), endpoint_id.clone()),
            ],
        ),
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
