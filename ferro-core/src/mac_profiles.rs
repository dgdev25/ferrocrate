use thiserror::Error;

#[derive(Debug, Error)]
pub enum MacProfileError {
    #[error("container id is required")]
    MissingContainerId,
}

pub fn generate_apparmor_profile(container_id: &str) -> Result<String, MacProfileError> {
    if container_id.trim().is_empty() {
        return Err(MacProfileError::MissingContainerId);
    }

    Ok(format!(
        "profile ferrocrate-{id} flags=(attach_disconnected,mediate_deleted) {{\n  #include <abstractions/base>\n  network,\n  file,\n  capability,\n  deny /proc/kcore rw,\n}}\n",
        id = container_id
    ))
}

pub fn generate_selinux_policy(container_id: &str) -> Result<String, MacProfileError> {
    if container_id.trim().is_empty() {
        return Err(MacProfileError::MissingContainerId);
    }

    Ok(format!(
        "policy_module(ferrocrate_{id}, 1.0)\n\nrequire {{\n  type unconfined_t;\n  class file {{ read write open }};\n}}\n\nallow unconfined_t self:file {{ read write open }};\n",
        id = container_id
    ))
}

#[cfg(test)]
mod tests {
    use super::{generate_apparmor_profile, generate_selinux_policy};

    #[test]
    fn generates_apparmor_profile() {
        let profile = generate_apparmor_profile("abc123").expect("profile");
        assert!(profile.contains("profile ferrocrate-abc123"));
        assert!(profile.contains("deny /proc/kcore"));
    }

    #[test]
    fn generates_selinux_policy() {
        let policy = generate_selinux_policy("abc123").expect("policy");
        assert!(policy.contains("policy_module(ferrocrate_abc123"));
    }
}
