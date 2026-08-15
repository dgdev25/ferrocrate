//! Security tests for input validation and attack prevention.

/// Test cases for malicious input
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
        expected_error: "path traversal",
    },
    SecurityTestCase {
        name: "path_traversal_null_byte",
        input: "image.tar\x00../../../etc/passwd",
        expected_error: "null byte",
    },
    // Command Injection
    SecurityTestCase {
        name: "command_injection_semicolon",
        input: "ubuntu; rm -rf /",
        expected_error: "invalid character",
    },
    SecurityTestCase {
        name: "command_injection_pipe",
        input: "ubuntu | cat /etc/passwd",
        expected_error: "invalid character",
    },
    SecurityTestCase {
        name: "command_injection_backtick",
        input: "ubuntu`whoami`",
        expected_error: "invalid character",
    },
    SecurityTestCase {
        name: "command_injection_dollar",
        input: "ubuntu$(id)",
        expected_error: "invalid character",
    },
    // Shell Metacharacters
    SecurityTestCase {
        name: "shell_ampersand",
        input: "ubuntu && cat /etc/shadow",
        expected_error: "invalid character",
    },
    SecurityTestCase {
        name: "shell_redirect",
        input: "ubuntu > /etc/passwd",
        expected_error: "invalid character",
    },
    SecurityTestCase {
        name: "shell_newline",
        input: "ubuntu\nRUN cat /etc/shadow",
        expected_error: "newline",
    },
    // Image Name Attacks
    SecurityTestCase {
        name: "image_name_unicode",
        input: "ubuntu<script>alert(1)</script>",
        expected_error: "invalid character",
    },
];

/// Volume mount security test cases (format: "source:dest")
pub const VOLUME_MOUNT_TEST_CASES: &[SecurityTestCase] = &[
    SecurityTestCase {
        name: "docker_socket_mount",
        input: "/var/run/docker.sock:/var/run/docker.sock",
        expected_error: "docker socket",
    },
    SecurityTestCase {
        name: "proc_mount",
        input: "/proc:/host/proc",
        expected_error: "proc mount",
    },
    SecurityTestCase {
        name: "root_filesystem",
        input: "/:/host",
        expected_error: "root mount",
    },
];

/// Validate image name for security issues
pub fn validate_image_name(input: &str) -> Result<String, String> {
    let input = input.trim();

    // Check length
    if input.is_empty() {
        return Err("empty image name".to_string());
    }
    if input.len() > 255 {
        return Err("image name too long".to_string());
    }

    // Check for null bytes
    if input.contains('\0') {
        return Err("null byte in image name".to_string());
    }

    // Check for newlines
    if input.contains('\n') || input.contains('\r') {
        return Err("newline in image name".to_string());
    }

    // Check for shell metacharacters
    let dangerous_chars = [';', '|', '&', '`', '$', '(', ')', '<', '>', '"', '\''];
    if input.chars().any(|c| dangerous_chars.contains(&c)) {
        return Err("dangerous character in image name".to_string());
    }

    // Check for path traversal
    if input.contains("..") || input.contains('~') {
        return Err("path traversal attempt".to_string());
    }

    // Validate format
    if !input.chars().all(|c| {
        c.is_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '/' || c == ':' || c == '@'
    }) {
        return Err("invalid character in image name".to_string());
    }

    Ok(input.to_string())
}

/// Validate volume mount for security issues
pub fn validate_volume_mount(source: &str, dest: &str) -> Result<(), String> {
    // Prevent docker socket mounting
    if source.contains("docker.sock") || dest.contains("docker.sock") {
        return Err("docker socket mounting not allowed".to_string());
    }

    // Prevent proc mounting
    if source == "/proc" || dest.starts_with("/proc") {
        return Err("/proc mounting not allowed".to_string());
    }

    // Prevent root filesystem mounting
    if source == "/" {
        return Err("root filesystem mounting not allowed".to_string());
    }

    // Check for path traversal in source
    if source.contains("..") {
        return Err("path traversal in volume source".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_image_name_security_cases() {
        for case in IMAGE_NAME_TEST_CASES {
            let result = validate_image_name(case.input);
            assert!(
                result.is_err(),
                "Test '{}' should have failed but got: {:?}",
                case.name,
                result
            );
            let error = result.unwrap_err();
            assert!(
                error.to_lowercase().contains(case.expected_error)
                    || error.to_lowercase().contains("dangerous")
                    || error.to_lowercase().contains("invalid"),
                "Test '{}' expected error containing '{}', got: {}",
                case.name,
                case.expected_error,
                error
            );
        }
    }

    #[test]
    fn test_volume_mount_security_cases() {
        for case in VOLUME_MOUNT_TEST_CASES {
            // Parse "source:dest" format
            let parts: Vec<&str> = case.input.splitn(2, ':').collect();
            assert_eq!(parts.len(), 2, "Invalid test case format: {}", case.input);

            let result = validate_volume_mount(parts[0], parts[1]);
            assert!(
                result.is_err(),
                "Test '{}' should have failed but got: Ok(())",
                case.name
            );
            let error = result.unwrap_err();
            assert!(
                error.to_lowercase().contains(case.expected_error)
                    || error.to_lowercase().contains("not allowed"),
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
        ];

        for name in valid_names {
            assert!(validate_image_name(name).is_ok(), "Should accept: {}", name);
        }
    }

    #[test]
    fn test_volume_mount_security() {
        // Should reject dangerous mounts
        assert!(validate_volume_mount("/var/run/docker.sock", "/var/run/docker.sock").is_err());
        assert!(validate_volume_mount("/proc", "/host/proc").is_err());
        assert!(validate_volume_mount("/", "/host").is_err());
        assert!(validate_volume_mount("../../../etc", "/etc").is_err());

        // Should accept safe mounts
        assert!(validate_volume_mount("/data", "/data").is_ok());
        assert!(validate_volume_mount("./local", "/app/local").is_ok());
    }
}
