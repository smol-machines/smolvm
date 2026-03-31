//! Shared API validation utilities.

use crate::api::error::ApiError;

/// Validate a resource name with common API rules.
///
/// Rules:
/// - Length: 1..=max_len characters
/// - Allowed characters: alphanumeric, hyphen (-), underscore (_)
/// - Must start with a letter or digit
/// - Cannot end with a hyphen
/// - No consecutive hyphens
/// - No path separators (/, \)
pub fn validate_resource_name(name: &str, kind: &str, max_len: usize) -> Result<(), ApiError> {
    let first_char = name
        .chars()
        .next()
        .ok_or_else(|| ApiError::BadRequest(format!("{} name cannot be empty", kind)))?;

    if name.len() > max_len {
        return Err(ApiError::BadRequest(format!(
            "{} name too long: {} characters (max {})",
            kind,
            name.len(),
            max_len
        )));
    }

    if !first_char.is_ascii_alphanumeric() {
        return Err(ApiError::BadRequest(format!(
            "{} name must start with a letter or digit",
            kind
        )));
    }

    if name.ends_with('-') {
        return Err(ApiError::BadRequest(format!(
            "{} name cannot end with a hyphen",
            kind
        )));
    }

    let mut prev_was_hyphen = false;
    for c in name.chars() {
        if c == '-' {
            if prev_was_hyphen {
                return Err(ApiError::BadRequest(format!(
                    "{} name cannot contain consecutive hyphens",
                    kind
                )));
            }
            prev_was_hyphen = true;
        } else {
            prev_was_hyphen = false;
        }

        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
            if c == '/' || c == '\\' {
                return Err(ApiError::BadRequest(format!(
                    "{} name cannot contain path separators",
                    kind
                )));
            }
            return Err(ApiError::BadRequest(format!(
                "{} name contains invalid character: '{}'",
                kind, c
            )));
        }
    }

    Ok(())
}

/// Validate that a command is not empty.
pub fn validate_command(cmd: &[String]) -> Result<(), ApiError> {
    if cmd.is_empty() {
        return Err(ApiError::BadRequest("command cannot be empty".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_resource_name() {
        for kind in ["machine", "machine"] {
            let max_len = 40;

            // Valid names
            let valid = [
                "test",
                "my-resource",
                "my_resource",
                "test123",
                "123test",
                "a",
                "test-resource-123",
                "TEST_RESOURCE",
            ];
            for name in valid {
                assert!(
                    validate_resource_name(name, kind, max_len).is_ok(),
                    "expected '{}' to be valid for {}",
                    name,
                    kind
                );
            }

            // Max length boundary
            assert!(validate_resource_name(&"a".repeat(40), kind, max_len).is_ok());
            assert!(validate_resource_name(&"a".repeat(41), kind, max_len).is_err());

            // Invalid names
            let invalid = [
                ("", "empty"),
                ("-test", "starts with hyphen"),
                ("_test", "starts with underscore"),
                (".test", "starts with dot"),
                ("test-", "ends with hyphen"),
                ("test--name", "consecutive hyphens"),
                ("test/name", "forward slash"),
                ("test\\name", "backslash"),
                ("test name", "space"),
                ("test@name", "at sign"),
                ("../test", "path traversal"),
                ("test.name", "dot"),
                ("test:name", "colon"),
                ("test#name", "hash"),
            ];
            for (name, desc) in invalid {
                assert!(
                    validate_resource_name(name, kind, max_len).is_err(),
                    "expected '{}' ({}) to be invalid for {}",
                    name,
                    desc,
                    kind
                );
            }
        }
    }

    #[test]
    fn test_validate_command() {
        assert!(validate_command(&[]).is_err());
        assert!(validate_command(&["echo".to_string()]).is_ok());
        assert!(validate_command(&["echo".to_string(), "hello".to_string()]).is_ok());
    }
}
