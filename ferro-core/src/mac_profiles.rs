use thiserror::Error;

#[derive(Debug, Error)]
pub enum MacProfileError {
    #[error("container id is required")]
    MissingContainerId,
    #[error("container id contains invalid characters")]
    InvalidContainerId,
}

fn validate_container_id(container_id: &str) -> Result<(), MacProfileError> {
    let value = container_id.trim();
    if value.is_empty() {
        return Err(MacProfileError::MissingContainerId);
    }
    if value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(MacProfileError::InvalidContainerId);
    }
    Ok(())
}

pub fn generate_apparmor_profile(container_id: &str) -> Result<String, MacProfileError> {
    validate_container_id(container_id)?;

    Ok(format!(
        // Keep the generated profile self-contained.  Distribution-provided
        // abstraction includes can reference optional tunables (for example
        // `@{HOMEDIRS}`), causing an explicitly enabled profile to fail closed
        // before the workload starts on otherwise valid hosts.
        "profile ferrocrate-{id} flags=(attach_disconnected,mediate_deleted) {{\n  network,\n  file,\n  capability,\n  deny /proc/kcore rw,\n}}\n",
        id = container_id
    ))
}

pub fn generate_selinux_policy(container_id: &str) -> Result<String, MacProfileError> {
    validate_container_id(container_id)?;

    Ok(format!(
        "policy_module(ferrocrate_{id}, 1.0)\n\nrequire {{\n  type unconfined_t;\n  class file {{ read write open }};\n}}\n\nallow unconfined_t self:file {{ read write open }};\n",
        id = container_id
    ))
}

#[cfg(test)]
mod tests {
    use super::{generate_apparmor_profile, generate_selinux_policy, MacProfileError};

    #[test]
    fn generates_apparmor_profile() {
        let profile = generate_apparmor_profile("abc123").expect("profile");
        assert!(profile.contains("profile ferrocrate-abc123"));
        assert!(profile.contains("deny /proc/kcore"));
        assert!(!profile.contains("#include"));
    }

    #[test]
    fn generates_selinux_policy() {
        let policy = generate_selinux_policy("abc123").expect("policy");
        assert!(policy.contains("policy_module(ferrocrate_abc123"));
    }

    #[test]
    fn rejects_path_traversal_and_shell_characters() {
        for id in [
            "../escape",
            "name/child",
            "name;command",
            "name with spaces",
        ] {
            assert!(matches!(
                generate_apparmor_profile(id),
                Err(MacProfileError::InvalidContainerId)
            ));
            assert!(matches!(
                generate_selinux_policy(id),
                Err(MacProfileError::InvalidContainerId)
            ));
        }
    }
}
