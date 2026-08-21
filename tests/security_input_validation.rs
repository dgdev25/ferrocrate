//! Security tests for input validation and attack prevention.
//!
//! These tests run the adversarial corpus against the production validator
//! `ferro_core::image_security::validate_image_reference` so the CLI test
//! target cannot drift from the enforced behavior.

use ferro_core::image_security::validate_image_reference;

/// Adversarial image-reference corpus with the production error fragment
/// each input must produce.
pub struct SecurityTestCase {
    pub name: &'static str,
    pub input: &'static str,
    pub expected_error: &'static str,
}

/// Image name security test cases
pub const IMAGE_NAME_TEST_CASES: &[SecurityTestCase] = &[
    // Path Traversal Attacks
    SecurityTestCase {
        name: "path_traversal_parent",
        input: "../../../etc/passwd",
        expected_error: "path traversal",
    },
    SecurityTestCase {
        name: "path_traversal_encoded",
        input: "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        expected_error: "invalid characters",
    },
    SecurityTestCase {
        name: "path_traversal_null_byte",
        input: "image.tar\x00../../../etc/passwd",
        expected_error: "invalid characters",
    },
    SecurityTestCase {
        name: "path_traversal_component_in_registry",
        input: "registry.example.com/../repo",
        expected_error: "path traversal",
    },
    // Command Injection
    SecurityTestCase {
        name: "command_injection_semicolon",
        input: "ubuntu; rm -rf /",
        expected_error: "invalid characters",
    },
    SecurityTestCase {
        name: "command_injection_pipe",
        input: "ubuntu | cat /etc/passwd",
        expected_error: "invalid characters",
    },
    SecurityTestCase {
        name: "command_injection_backtick",
        input: "ubuntu`whoami`",
        expected_error: "invalid characters",
    },
    SecurityTestCase {
        name: "command_injection_dollar",
        input: "ubuntu$(id)",
        expected_error: "invalid characters",
    },
    // Shell Metacharacters
    SecurityTestCase {
        name: "shell_ampersand",
        input: "ubuntu && cat /etc/shadow",
        expected_error: "invalid characters",
    },
    SecurityTestCase {
        name: "shell_redirect",
        input: "ubuntu > /etc/passwd",
        expected_error: "invalid characters",
    },
    SecurityTestCase {
        name: "shell_newline",
        input: "ubuntu\nRUN cat /etc/shadow",
        expected_error: "invalid characters",
    },
    // Image Name Attacks
    SecurityTestCase {
        name: "image_name_unicode",
        input: "ubuntu<script>alert(1)</script>",
        expected_error: "invalid characters",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_image_name_security_cases() {
        for case in IMAGE_NAME_TEST_CASES {
            let result = validate_image_reference(case.input);
            assert!(
                result.is_err(),
                "Test '{}' should have failed but got: {:?}",
                case.name,
                result
            );
            let error = result.unwrap_err();
            assert!(
                error.to_lowercase().contains(case.expected_error),
                "Test '{}' expected error containing '{}', got: {}",
                case.name,
                case.expected_error,
                error
            );
        }
    }

    #[test]
    fn test_valid_image_names() {
        let valid_names = [
            "ubuntu",
            "ubuntu:latest",
            "nginx:alpine",
            "registry.example.com/image:v1",
            "gcr.io/project/image@sha256:abc123",
            "registry:5000/repo@sha256:abc",
            "foo..bar/baz:tag",
        ];

        for name in valid_names {
            assert!(validate_image_reference(name).is_ok(), "Should accept: {name}");
        }
    }
}
