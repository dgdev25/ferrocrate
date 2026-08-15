#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OverlayInterfaces {
    pub(crate) bridge: String,
    pub(crate) wireguard: String,
}

pub(crate) fn overlay_interfaces(canonical_overlay: &str) -> OverlayInterfaces {
    let value = ferro_core::managed_overlay::managed_interface_identities(canonical_overlay);
    OverlayInterfaces {
        bridge: value.bridge_ifname,
        wireguard: value.wireguard_ifname,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_names_are_stable_distinct_and_linux_bounded() {
        let first = overlay_interfaces("overlay-a");
        assert_eq!(first, overlay_interfaces("overlay-a"));
        assert_ne!(first.bridge, first.wireguard);
        assert!(first.bridge.len() <= 15 && first.wireguard.len() <= 15);
        assert_ne!(first, overlay_interfaces("overlay-b"));
    }
}
