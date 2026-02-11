use nix::sched::{CloneFlags, unshare};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamespaceType {
    Pid,
    Network,
    Ipc,
    Uts,
    Mount,
    User,
}

#[derive(Debug, Error)]
pub enum NamespaceError {
    #[error("failed to create namespaces: {0}")]
    Unshare(#[from] nix::Error),
}

/// Build clone flags for a set of namespaces.
pub fn namespace_flags(namespaces: &[NamespaceType]) -> CloneFlags {
    namespaces
        .iter()
        .fold(CloneFlags::empty(), |flags, ns| flags | ns.clone_flag())
}

/// Create Linux namespaces for the current process using `unshare(2)`.
pub fn create_namespaces(namespaces: &[NamespaceType]) -> Result<(), NamespaceError> {
    let flags = namespace_flags(namespaces);
    if flags.is_empty() {
        return Ok(());
    }

    unshare(flags)?;
    Ok(())
}

impl NamespaceType {
    fn clone_flag(self) -> CloneFlags {
        match self {
            NamespaceType::Pid => CloneFlags::CLONE_NEWPID,
            NamespaceType::Network => CloneFlags::CLONE_NEWNET,
            NamespaceType::Ipc => CloneFlags::CLONE_NEWIPC,
            NamespaceType::Uts => CloneFlags::CLONE_NEWUTS,
            NamespaceType::Mount => CloneFlags::CLONE_NEWNS,
            NamespaceType::User => CloneFlags::CLONE_NEWUSER,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{NamespaceType, namespace_flags};
    use nix::sched::CloneFlags;

    #[test]
    fn builds_expected_flags_for_phase_one_namespaces() {
        let flags = namespace_flags(&[
            NamespaceType::Pid,
            NamespaceType::Network,
            NamespaceType::Ipc,
            NamespaceType::Uts,
            NamespaceType::Mount,
        ]);

        assert!(flags.contains(CloneFlags::CLONE_NEWPID));
        assert!(flags.contains(CloneFlags::CLONE_NEWNET));
        assert!(flags.contains(CloneFlags::CLONE_NEWIPC));
        assert!(flags.contains(CloneFlags::CLONE_NEWUTS));
        assert!(flags.contains(CloneFlags::CLONE_NEWNS));
    }

    #[test]
    fn returns_empty_flags_for_empty_namespace_set() {
        assert!(namespace_flags(&[]).is_empty());
    }
}
