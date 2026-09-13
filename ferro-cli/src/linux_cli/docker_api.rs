//! Shared Docker HTTP API routing helpers.

/// Remove a valid Docker API version prefix before route dispatch.
///
/// The Docker client can send both `/containers/json` and
/// `/v1.45/containers/json`. Invalid version-like paths must reach the normal
/// router unchanged so that it can return the correct error response.
pub(super) fn normalize_docker_api_path(path: &str) -> String {
    if !path.starts_with("/v") {
        return path.to_string();
    }

    let mut parts = path.splitn(3, '/');
    let first = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    let rest = parts.next();
    if !first.is_empty() || version.len() < 2 || !version.starts_with('v') {
        return path.to_string();
    }

    let version_body = &version[1..];
    let valid = version_body
        .chars()
        .all(|ch| ch.is_ascii_digit() || ch == '.')
        && version_body.chars().any(|ch| ch.is_ascii_digit());
    if !valid {
        return path.to_string();
    }

    match rest {
        Some(rest) if !rest.is_empty() => format!("/{rest}"),
        _ => "/".to_string(),
    }
}
