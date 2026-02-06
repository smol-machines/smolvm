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
