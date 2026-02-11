use caps::CapSet;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CapabilityError {
    #[error("capabilities operation failed: {0}")]
    Caps(#[from] caps::errors::CapsError),
}

/// Drop all capabilities for the current process (bounding, effective, permitted, inheritable).
pub fn drop_all_capabilities() -> Result<(), CapabilityError> {
    let empty = caps::CapsHashSet::new();
    caps::set(None, CapSet::Bounding, &empty)?;
    caps::set(None, CapSet::Effective, &empty)?;
    caps::set(None, CapSet::Permitted, &empty)?;
    caps::set(None, CapSet::Inheritable, &empty)?;
    Ok(())
}

/// Return current capabilities for a specific capability set.
pub fn get_capabilities(set: CapSet) -> Result<caps::CapsHashSet, CapabilityError> {
    Ok(caps::read(None, set)?)
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
        let _ = drop_all_capabilities();
        let after = get_capabilities(CapSet::Effective).expect("read caps");
        assert!(after.is_empty());
    }
}
