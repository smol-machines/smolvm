//! Credential policy types, re-exported from `smolvm-protocol`, plus
//! placeholder minting.

pub use smolvm_protocol::credentials::{
    covered_by_allow_list, CredentialBinding, CredentialPolicy, InjectionLocation, PolicyError,
    DEFAULT_METHODS, PLACEHOLDER_PREFIX,
};
use std::collections::BTreeMap;

/// Build a fresh placeholder for a binding.
///
/// Placeholders are opaque and unique per machine; the interceptor matches
/// them exactly, so a guest cannot guess a sibling machine's placeholder and a
/// stray token never collides with real header syntax.
pub fn generate_placeholder(binding: &str) -> String {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random).expect("operating system randomness");
    let suffix: String = random.iter().map(|b| format!("{b:02X}")).collect();
    let tag: String = binding
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("{PLACEHOLDER_PREFIX}{tag}_{suffix}")
}

/// Mint one placeholder per binding. Callers persist the result with the
/// machine: placeholders must stay stable for the machine's lifetime so
/// processes captured in a checkpoint or fork keep working after restore.
pub fn generate_placeholders(policy: &CredentialPolicy) -> BTreeMap<String, String> {
    policy
        .credentials
        .iter()
        .map(|b| (b.name.clone(), generate_placeholder(&b.name)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_are_prefixed_tagged_and_unique() {
        let policy: CredentialPolicy = serde_json::from_str(
            r#"{"credentials":[
                {"name":"notion","environment_variable":"NOTION_API_KEY","allowed_hosts":["api.notion.com"]},
                {"name":"git-hub","environment_variable":"GITHUB_TOKEN","allowed_hosts":["api.github.com"]}
            ]}"#,
        )
        .unwrap();
        let placeholders = generate_placeholders(&policy);
        assert!(placeholders["notion"].starts_with("SMOL_PLACEHOLDER_NOTION_"));
        assert!(placeholders["git-hub"].starts_with("SMOL_PLACEHOLDER_GIT_HUB_"));
        assert_ne!(placeholders["notion"], generate_placeholder("notion"));
        assert!(placeholders
            .values()
            .all(|p| p.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')));
    }
}
