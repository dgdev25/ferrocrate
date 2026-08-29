//! Property-based tests for production image reference parsing.

use ferro_core::registry::{parse_image_reference, ReferenceSeparator};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Test that valid image references roundtrip through production canonicalization.
    #[test]
    fn image_ref_roundtrips(
        registry in prop::option::of("[a-z]{2,10}\\.[a-z]{2,10}"),
        name in "[a-z]([a-z0-9_-]*[a-z0-9])?",
        tag in prop::option::of("[a-z0-9_.-]{1,30}"),
    ) {
        let original = match (registry, tag) {
            (Some(reg), Some(t)) => format!("{}/{}:{}", reg, name, t),
            (Some(reg), None) => format!("{}/{}", reg, name),
            (None, Some(t)) => format!("{}:{}", name, t),
            (None, None) => name.clone(),
        };

        let canonical = parse_image_reference(&original)
            .map_err(|error| TestCaseError::fail(error.to_string()))?
            .canonical();
        let roundtripped = parse_image_reference(&canonical)
            .map_err(|error| TestCaseError::fail(error.to_string()))?
            .canonical();

        prop_assert_eq!(roundtripped, canonical);
    }

    /// Test that parser never panics on any input
    #[test]
    fn parser_never_panics(input in "\\PC*") {
        let _ = parse_image_reference(&input); // Must not panic
    }

    /// Test name extraction is always valid
    #[test]
    fn name_extraction_valid(input in "[a-z0-9._/-]{1,100}") {
        if let Ok(parsed) = parse_image_reference(&input) {
            prop_assert!(!parsed.repository.is_empty());
            prop_assert!(parsed.repository.chars().all(|c|
                c.is_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '/'
            ));
        }
    }

    /// Test that empty input is rejected
    #[test]
    fn empty_rejected(input in prop::string::string_regex("").unwrap()) {
        let result = parse_image_reference(&input);
        prop_assert!(result.is_err());
    }

    /// Test that shell metacharacters are rejected
    #[test]
    fn shell_chars_rejected(bad_char in "[;&|`$()<>]") {
        let input = format!("ubuntu:latest{}", bad_char);
        let result = parse_image_reference(&input);
        prop_assert!(result.is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_image_parsing() {
        let img = parse_image_reference("nginx").unwrap();
        assert_eq!(img.registry, "registry-1.docker.io");
        assert_eq!(img.repository, "library/nginx");
        assert_eq!(img.reference, "latest");
        assert_eq!(img.separator, ReferenceSeparator::Tag);
    }

    #[test]
    fn tagged_image_parsing() {
        let img = parse_image_reference("nginx:alpine").unwrap();
        assert_eq!(img.repository, "library/nginx");
        assert_eq!(img.reference, "alpine");
        assert_eq!(img.separator, ReferenceSeparator::Tag);
    }

    #[test]
    fn registry_image_parsing() {
        let img = parse_image_reference("registry.example.com/nginx:alpine").unwrap();
        assert_eq!(img.registry, "registry.example.com");
        assert_eq!(img.repository, "nginx");
        assert_eq!(img.reference, "alpine");
        assert_eq!(img.separator, ReferenceSeparator::Tag);
    }

    #[test]
    fn digest_image_parsing() {
        let img = parse_image_reference(
            "nginx@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
        assert_eq!(img.repository, "library/nginx");
        assert_eq!(
            img.reference,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(img.separator, ReferenceSeparator::Digest);
    }
}
