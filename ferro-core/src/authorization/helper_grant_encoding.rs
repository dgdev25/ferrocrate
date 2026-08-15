use super::helper_grant::{GrantClaims, GrantParameters};

impl GrantParameters {
    pub(crate) fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

pub fn signing_bytes(claims: &GrantClaims) -> Vec<u8> {
    let mut out = b"ferrocrate.helper-grant\0".to_vec();
    out.extend_from_slice(&claims.schema_version.to_be_bytes());
    push_text(&mut out, &claims.request_id);
    out.push(claims.action as u8);
    push_text(&mut out, &claims.resource.resource_uuid);
    out.extend_from_slice(&claims.resource.generation.to_be_bytes());
    out.extend_from_slice(&claims.parameter_digest);
    push_text(&mut out, &claims.boot_id);
    out.extend_from_slice(&claims.wall_deadline_secs.to_be_bytes());
    out.extend_from_slice(&claims.monotonic_deadline_millis.to_be_bytes());
    out.extend_from_slice(&claims.nonce);
    out.extend_from_slice(&claims.operation_id);
    out.extend_from_slice(&claims.request_digest);
    out.extend_from_slice(&claims.precondition_digest);
    out.extend_from_slice(&claims.recovery_recipe_digest);
    push_text(&mut out, &claims.issuer);
    push_text(&mut out, &claims.key_id);
    out.push(claims.kind as u8);
    push_optional_text(&mut out, claims.origin_request_id.as_deref());
    match claims.live_identity_digest {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value);
        }
        None => out.push(0),
    }
    out
}

pub(super) fn push_text(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

pub(super) fn is_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

fn push_optional_text(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(value) => {
            out.push(1);
            push_text(out, value);
        }
        None => out.push(0),
    }
}
