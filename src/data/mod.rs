//! Canonical shared data models and constants for smolvm.

/// Shared constants used across the runtime and adapters.
pub mod consts;
/// Canonical disk type metadata shared by storage helpers.
pub mod disk;
/// Canonical error types used by the shared data layer.
#[path = "errors.rs"]
pub mod error;
/// Canonical network-related data models.
pub mod network;
/// Canonical resource configuration data models.
pub mod resources;
/// Canonical storage and mount data models.
pub mod storage;

/// Target VM identifier used by shared operations.
pub enum VmTarget {
    /// The default micro vm
    Default,
    /// A specifically named micro vm
    Named(String),
}

impl VmTarget {
    /// Return the stable VM name for this target.
    pub fn name(&self) -> &str {
        match self {
            Self::Default => "default",
            Self::Named(name) => name.as_str(),
        }
    }
}

impl From<&str> for VmTarget {
    fn from(name: &str) -> VmTarget {
        if name == "default" {
            VmTarget::Default
        } else {
            VmTarget::Named(String::from(name))
        }
    }
}

/// Sanity upper bound on VM name length.
///
/// The on-disk layout uses a fixed-length hash of the name as the directory
/// name (see [`crate::agent::vm_data_dir`]), so name length doesn't affect
/// the socket path or any other filesystem budget. This constant is purely
/// a UX cap to reject obviously-absurd input (500+ char names).
pub const MAX_VM_NAME_LENGTH: usize = 128;

/// Validate a persisted VM name.
pub fn validate_vm_name(name: &str, label: &str) -> Result<(), String> {
    let first_char = name
        .chars()
        .next()
        .ok_or_else(|| format!("{label} cannot be empty"))?;

    if name.len() > MAX_VM_NAME_LENGTH {
        return Err(format!(
            "{label} too long: {} characters (max {})",
            name.len(),
            MAX_VM_NAME_LENGTH
        ));
    }

    if !first_char.is_ascii_alphanumeric() {
        return Err(format!("{label} must start with a letter or digit"));
    }

    if name.ends_with('-') {
        return Err(format!("{label} cannot end with a hyphen"));
    }

    let mut prev_was_hyphen = false;
    for c in name.chars() {
        if c == '-' {
            if prev_was_hyphen {
                return Err(format!("{label} cannot contain consecutive hyphens"));
            }
            prev_was_hyphen = true;
        } else {
            prev_was_hyphen = false;
        }

        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
            if c == '/' || c == '\\' {
                return Err(format!("{label} cannot contain path separators"));
            }

            return Err(format!("{label} contains invalid character: '{c}'"));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_vm_name_accepts_valid_names() {
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
                validate_vm_name(name, "machine name").is_ok(),
                "expected '{name}' to be valid"
            );
        }
    }

    #[test]
    fn validate_vm_name_enforces_max_length() {
        assert!(validate_vm_name(&"a".repeat(MAX_VM_NAME_LENGTH), "machine name").is_ok());
        assert!(validate_vm_name(&"a".repeat(MAX_VM_NAME_LENGTH + 1), "machine name").is_err());
    }

    #[test]
    fn validate_vm_name_rejects_invalid_names() {
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
                validate_vm_name(name, "machine name").is_err(),
                "expected '{name}' ({desc}) to be invalid"
            );
        }
    }

    #[test]
    fn validate_vm_name_formats_with_label() {
        assert_eq!(
            validate_vm_name("test/name", "machine name").unwrap_err(),
            "machine name cannot contain path separators"
        );
    }
}
