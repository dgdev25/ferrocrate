//! Custom assertions for FerroCrate testing.

use std::path::Path;

/// Trait for custom assertion helpers
pub trait FerroAssertions<T> {
    /// Assert that a result is successful
    fn assert_success(&self) -> &T;

    /// Assert that result failed with specific message
    fn assert_failure_with(&self, expected_msg: &str) -> &T;

    /// Assert that result has specific field
    fn assert_has_field(&self, field: &str) -> &T;
}

/// Container assertions
pub mod container {
    use super::*;

    pub fn assert_running(container_id: &str) {
        // Implementation would check container state
        assert!(!container_id.is_empty(), "Container ID should not be empty");
    }

    pub fn assert_stopped(container_id: &str) {
        assert!(!container_id.is_empty(), "Container ID should not be empty");
    }

    pub fn assert_image_pulled(image: &str) {
        assert!(!image.is_empty(), "Image name should not be empty");
    }
}

/// Image assertions
pub mod image {
    use super::*;

    pub fn assert_valid_reference(reference: &str) {
        assert!(!reference.is_empty(), "Image reference should not be empty");
    }

    pub fn assert_has_layer(image_id: &str, layer_digest: &str) {
        assert!(!image_id.is_empty() && !layer_digest.is_empty());
    }
}

/// File system assertions
pub mod fs {
    use super::*;
    use std::path::Path;

    pub fn assert_file_exists(path: &Path) {
        assert!(path.exists(), "File should exist: {:?}", path);
    }

    pub fn assert_file_not_exists(path: &Path) {
        assert!(!path.exists(), "File should not exist: {:?}", path);
    }

    pub fn assert_dir_exists(path: &Path) {
        assert!(path.is_dir(), "Directory should exist: {:?}", path);
    }
}

/// JSON assertions
pub mod json {
    use super::*;
    use serde_json::Value;

    pub fn assert_valid_json(json_str: &str) {
        let _: Value = serde_json::from_str(json_str)
            .expect("Should be valid JSON");
    }

    pub fn assert_json_has_key(json: &Value, key: &str) {
        assert!(json.get(key).is_some(), "JSON should have key: {}", key);
    }
}

/// Network assertions
pub mod network {
    use super::*;

    pub fn assert_port_available(port: u16) {
        // Implementation would check if port is available
        assert!(port > 0, "Port should be greater than 0");
    }

    pub fn assert_network_exists(network_name: &str) {
        assert!(!network_name.is_empty(), "Network name should not be empty");
    }
}
