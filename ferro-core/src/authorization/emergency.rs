use std::sync::atomic::{AtomicBool, Ordering};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::{Action, ResolvedPrincipal};

/// Opaque, single-use break-glass authority. Construction requires a valid
/// offline recovery signature; callers cannot directly set or mutate scope.
#[derive(Debug)]
pub struct EmergencyAuthority {
    action: Action,
    resource: String,
    resource_generation: u64,
    boot_id: String,
    deadline_uptime_ns: u64,
    principal: String,
    policy_digest: [u8; 32],
    operation_id: [u8; 16],
    consumed: AtomicBool,
}

impl EmergencyAuthority {
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        signed_payload: &[u8],
        signature: [u8; 64],
        recovery_key: [u8; 32],
        action: Action,
        resource: String,
        resource_generation: u64,
        boot_id: String,
        deadline_uptime_ns: u64,
        principal: &ResolvedPrincipal,
        policy_digest: [u8; 32],
        operation_id: [u8; 16],
    ) -> Result<Self, EmergencyAuthorityError> {
        let key = VerifyingKey::from_bytes(&recovery_key).map_err(|_| EmergencyAuthorityError)?;
        key.verify(signed_payload, &Signature::from_bytes(&signature))
            .map_err(|_| EmergencyAuthorityError)?;
        let payload = std::str::from_utf8(signed_payload).map_err(|_| EmergencyAuthorityError)?;
        let fields = payload.lines().collect::<Vec<_>>();
        if fields.len() != 6
            || fields[0] != "FERROCRATE-EMERGENCY-APPROVAL-V1"
            || fields[1] != boot_id
            || fields[2] != action_name(action)
            || fields[3] != format!("container:{resource}")
            || fields[4].len() < 16
            || fields[5] != deadline_uptime_ns.to_string()
            || resource_generation == 0
        {
            return Err(EmergencyAuthorityError);
        }
        Ok(Self {
            action,
            resource,
            resource_generation,
            boot_id,
            deadline_uptime_ns,
            principal: principal.id().as_str().to_owned(),
            policy_digest,
            operation_id,
            consumed: AtomicBool::new(false),
        })
    }

    pub(crate) fn consume(
        &self,
        action: Action,
        resource: &str,
        generation: u64,
        principal: &ResolvedPrincipal,
        policy_digest: [u8; 32],
        operation_id: [u8; 16],
    ) -> Result<(), EmergencyAuthorityError> {
        if self.action != action
            || self.resource != resource
            || self.resource_generation != generation
            || self.principal != principal.id().as_str()
            || self.policy_digest != policy_digest
            || self.operation_id != operation_id
            || current_boot_id().as_deref() != Some(self.boot_id.as_str())
            || uptime_ns().is_none_or(|now| now >= self.deadline_uptime_ns)
            || self.consumed.swap(true, Ordering::AcqRel)
        {
            return Err(EmergencyAuthorityError);
        }
        Ok(())
    }
}

fn action_name(action: Action) -> &'static str {
    match action {
        Action::ContainerStop => "container.stop",
        Action::ContainerKill => "container.kill",
        Action::ContainerDelete => "container.remove",
        _ => "unsupported",
    }
}

fn current_boot_id() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|v| v.trim().to_owned())
}

fn uptime_ns() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/uptime").ok()?;
    let seconds: f64 = text.split_whitespace().next()?.parse().ok()?;
    Some((seconds * 1_000_000_000.0) as u64)
}

#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("emergency authority is invalid, expired, out of scope, or already consumed")]
pub struct EmergencyAuthorityError;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::Role;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn authority_is_exact_scope_single_use_and_signature_bound() {
        let key = SigningKey::from_bytes(&[0x71; 32]);
        let boot = current_boot_id().unwrap();
        let deadline = uptime_ns().unwrap() + 10_000_000_000;
        let payload = format!("FERROCRATE-EMERGENCY-APPROVAL-V1\n{boot}\ncontainer.stop\ncontainer:abc\nnonce-0123456789\n{deadline}\n");
        let signature = key.sign(payload.as_bytes()).to_bytes();
        let principal = ResolvedPrincipal::new("host-admin", Role::Administrator);
        let authority = EmergencyAuthority::verify(
            payload.as_bytes(),
            signature,
            key.verifying_key().to_bytes(),
            Action::ContainerStop,
            "abc".into(),
            7,
            boot,
            deadline,
            &principal,
            [9; 32],
            [8; 16],
        )
        .unwrap();

        assert!(authority
            .consume(
                Action::ContainerStop,
                "other",
                7,
                &principal,
                [9; 32],
                [8; 16]
            )
            .is_err());
        assert!(authority
            .consume(
                Action::ContainerStop,
                "abc",
                7,
                &principal,
                [9; 32],
                [8; 16]
            )
            .is_ok());
        assert!(authority
            .consume(
                Action::ContainerStop,
                "abc",
                7,
                &principal,
                [9; 32],
                [8; 16]
            )
            .is_err());
    }
}
