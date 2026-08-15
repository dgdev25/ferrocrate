//! Property-based tests for image reference parsing.
//!
//! Uses proptest for fuzzing to ensure parser handles all edge cases.

use proptest::prelude::*;

// Simple image reference parser for testing
fn parse_image_reference(input: &str) -> Result<ImageRef, String> {
    let input = input.trim();

    if input.is_empty() {
        return Err("empty reference".to_string());
    }

    // Check for invalid characters
    if input.chars().any(|c| {
        !c.is_alphanumeric() && c != '.' && c != '-' && c != '_' && c != '/' && c != ':' && c != '@'
    }) {
        return Err("invalid character".to_string());
    }

    // Parse registry/host
    let (registry, rest) = if input.contains('/') {
        let parts: Vec<&str> = input.splitn(2, '/').collect();
        if parts[0].contains(':')
            || parts[0].contains('.')
            || !parts[0]
                .chars()
                .all(|c| c.is_lowercase() || c.is_numeric() || c == '-' || c == '_')
        {
            (Some(parts[0].to_string()), parts[1])
        } else {
            (None, input)
        }
    } else {
        (None, input)
    };

    // Parse tag/digest
    let (name, tag, digest) = if rest.contains('@') {
        let parts: Vec<&str> = rest.splitn(2, '@').collect();
        (parts[0].to_string(), None, Some(parts[1].to_string()))
    } else if rest.contains(':') {
        let parts: Vec<&str> = rest.rsplitn(2, ':').collect();
        (parts[1].to_string(), Some(parts[0].to_string()), None)
    } else {
        (rest.to_string(), None, None)
    };

    if name.is_empty() {
        return Err("empty name".to_string());
    }

    Ok(ImageRef {
        registry,
        name,
        tag,
        digest,
    })
}

#[derive(Debug, Clone)]
struct ImageRef {
    registry: Option<String>,
    name: String,
    tag: Option<String>,
    digest: Option<String>,
}

impl ImageRef {
    fn to_string_ref(&self) -> String {
        let mut result = String::new();
        if let Some(reg) = &self.registry {
            result.push_str(reg);
            result.push('/');
        }
        result.push_str(&self.name);
        if let Some(tag) = &self.tag {
            result.push(':');
            result.push_str(tag);
        }
        if let Some(digest) = &self.digest {
            result.push('@');
            result.push_str(digest);
        }
        result
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Test that valid image references roundtrip through parsing
    #[test]
    fn image_ref_roundtrips(
        registry in prop::option::of("[a-z]{2,10}\\.[a-z]{2,10}"),
        name in "[a-z][a-z0-9_-]{0,30}",
        tag in prop::option::of("[a-z0-9_.-]{1,30}"),
    ) {
        let original = match (registry, tag) {
            (Some(reg), Some(t)) => format!("{}/{}:{}", reg, name, t),
            (Some(reg), None) => format!("{}/{}", reg, name),
            (None, Some(t)) => format!("{}:{}", name, t),
            (None, None) => name.clone(),
        };

        let parsed = parse_image_reference(&original)
            .map_err(TestCaseError::fail)?;
        let roundtripped = parsed.to_string_ref();

        prop_assert_eq!(roundtripped, original);
    }

    /// Test that parser never panics on any input
    #[test]
    fn parser_never_panics(input in "\\PC*") {
        let _ = parse_image_reference(&input); // Must not panic
    }

    /// Test name extraction is always valid
    #[test]
    fn name_extraction_valid(input in "[a-z0-9._/-]{1,100}") {
        if let Ok(ref parsed) = parse_image_reference(&input) {
            prop_assert!(!parsed.name.is_empty());
            prop_assert!(parsed.name.chars().all(|c|
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
        assert_eq!(img.name, "nginx");
        assert!(img.tag.is_none());
        assert!(img.digest.is_none());
    }

    #[test]
    fn tagged_image_parsing() {
        let img = parse_image_reference("nginx:alpine").unwrap();
        assert_eq!(img.name, "nginx");
        assert_eq!(img.tag, Some("alpine".to_string()));
    }

    #[test]
    fn registry_image_parsing() {
        let img = parse_image_reference("registry.example.com/nginx:alpine").unwrap();
        assert_eq!(img.registry, Some("registry.example.com".to_string()));
        assert_eq!(img.name, "nginx");
        assert_eq!(img.tag, Some("alpine".to_string()));
    }

    #[test]
    fn digest_image_parsing() {
        let img = parse_image_reference("nginx@sha256:abc123").unwrap();
        assert_eq!(img.name, "nginx");
        assert_eq!(img.digest, Some("sha256:abc123".to_string()));
    }
}
