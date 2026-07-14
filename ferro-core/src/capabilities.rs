use caps::{CapSet, Capability, CapsHashSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CapabilityError {
    #[error("capabilities operation failed: {0}")]
    Caps(#[from] caps::errors::CapsError),
}

/// Drop all capabilities for the current process (bounding, effective, permitted, inheritable).
pub fn drop_all_capabilities() -> Result<(), CapabilityError> {
    if let Err(err) = caps::clear(None, CapSet::Bounding) {
        if !is_unprivileged_bounding_drop(&err) {
            return Err(err.into());
        }
    }
    if let Err(err) = caps::clear(None, CapSet::Effective) {
        if !is_nonfatal_cap_error(&err) {
            return Err(err.into());
        }
    }
    if let Err(err) = caps::clear(None, CapSet::Permitted) {
        if !is_nonfatal_cap_error(&err) {
            return Err(err.into());
        }
    }
    if let Err(err) = caps::clear(None, CapSet::Inheritable) {
        if !is_nonfatal_cap_error(&err) {
            return Err(err.into());
        }
    }
    Ok(())
}

/// Return current capabilities for a specific capability set.
pub fn get_capabilities(set: CapSet) -> Result<caps::CapsHashSet, CapabilityError> {
    Ok(caps::read(None, set)?)
}

pub fn set_capabilities(caps_to_set: &[Capability]) -> Result<(), CapabilityError> {
    let set: CapsHashSet = caps_to_set.iter().copied().collect();
    for cap in caps::all() {
        if !set.contains(&cap) {
            if let Err(err) = caps::drop(None, CapSet::Bounding, cap) {
                if !is_kernel_without_bounding_caps(&err) {
                    return Err(err.into());
                }
            }
        }
    }
    if let Err(err) = caps::set(None, CapSet::Permitted, &set) {
        if !is_nonfatal_cap_error(&err) {
            return Err(err.into());
        }
    }
    if let Err(err) = caps::set(None, CapSet::Inheritable, &set) {
        if !is_nonfatal_cap_error(&err) {
            return Err(err.into());
        }
    }
    if let Err(err) = caps::set(None, CapSet::Effective, &set) {
        if !is_nonfatal_cap_error(&err) {
            return Err(err.into());
        }
    }
    Ok(())
}

fn is_unprivileged_bounding_drop(err: &caps::errors::CapsError) -> bool {
    let message = err.to_string();
    message.contains("Operation not permitted")
        || message.contains("operation not permitted")
        || is_kernel_without_bounding_caps(err)
}

fn is_kernel_without_bounding_caps(err: &caps::errors::CapsError) -> bool {
    let message = err.to_string();
    message.contains("Invalid argument") || message.contains("invalid argument")
}

fn is_nonfatal_cap_error(err: &caps::errors::CapsError) -> bool {
    let message = err.to_string();
    message.contains("Invalid argument")
        || message.contains("invalid argument")
        || message.contains("Operation not permitted")
        || message.contains("operation not permitted")
}

#[cfg(test)]
mod tests {
    use super::{drop_all_capabilities, get_capabilities};
    use caps::CapSet;

    #[test]
    fn reads_current_effective_caps() {
        let caps = get_capabilities(CapSet::Effective).expect("read caps");
        assert!(caps.is_empty() || !caps.is_empty());
    }

    #[test]
    fn drop_all_caps_is_idempotent() {
        if std::env::var_os("FERRO_CAP_DROP_CHILD").is_some() {
            drop_all_capabilities().expect("drop capabilities");
            let after = get_capabilities(CapSet::Effective).expect("read caps");
            assert!(after.is_empty());
            return;
        }

        let current_exe = std::env::current_exe().expect("current test executable");
        let status = std::process::Command::new(current_exe)
            .env("FERRO_CAP_DROP_CHILD", "1")
            .arg("capabilities::tests::drop_all_caps_is_idempotent")
            .arg("--exact")
            .status()
            .expect("spawn capability drop child");
        assert!(status.success());
    }
}
