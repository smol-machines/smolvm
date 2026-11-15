use serde::Deserialize;
use std::collections::HashSet;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Entry {
    pub name: String,
    pub kind: String,
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Listing {
    pub path: String,
    pub entries: Vec<Entry>,
}

pub fn validate_path(path: &str) -> Result<(), String> {
    if !path.starts_with('/') || path.contains('\0') {
        return Err("Enter an absolute Linux path, such as /workspace.".into());
    }
    Ok(())
}

pub fn join(parent: &str, name: &str) -> String {
    format!("{}/{name}", parent.trim_end_matches('/'))
}

pub fn parent(path: &str) -> String {
    path.trim_end_matches('/')
        .rsplit_once('/')
        .map(|(p, _)| if p.is_empty() { "/" } else { p })
        .unwrap_or("/")
        .into()
}

impl Listing {
    pub fn parse(bytes: &[u8], expected: &str) -> Result<Self, String> {
        let mut listing: Self =
            serde_json::from_slice(bytes).map_err(|e| format!("Cannot read this folder: {e}"))?;
        if listing.path != expected {
            return Err("The runtime returned a different folder.".into());
        }
        let mut names = HashSet::new();
        for entry in &listing.entries {
            if entry.name.is_empty()
                || matches!(entry.name.as_str(), "." | "..")
                || entry.name.contains(['/', '\0'])
                || !names.insert(&entry.name)
            {
                return Err("The runtime returned an invalid directory entry.".into());
            }
        }
        listing
            .entries
            .sort_by(|a, b| (a.kind != "dir", &a.name).cmp(&(b.kind != "dir", &b.name)));
        Ok(listing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn listings_preserve_names_but_reject_paths_and_duplicates() {
        let list = Listing::parse(br#"{"path":"/workspace","entries":[{"name":"a ; $(true)\n.txt","kind":"file","size":8},{"name":"z","kind":"dir","size":0},{"name":"dangling","kind":"symlink","size":0}]}"#, "/workspace").unwrap();
        assert_eq!(list.entries[0].name, "z");
        assert_eq!(
            join("/workspace/", &list.entries[1].name),
            "/workspace/a ; $(true)\n.txt"
        );
        for name in ["", ".", "..", "../bad", "a/b", "nul\0"] {
            let value =
                serde_json::json!({"path":"/", "entries":[{"name":name,"kind":"file","size":0}]});
            assert!(Listing::parse(&serde_json::to_vec(&value).unwrap(), "/").is_err());
        }
        assert!(Listing::parse(br#"{"path":"/","entries":[{"name":"a","kind":"file","size":0},{"name":"a","kind":"file","size":0}]}"#, "/").is_err());
        assert!(Listing::parse(br#"{"path":"/other","entries":[]}"#, "/").is_err());
        assert_eq!(parent("/workspace/a/"), "/workspace");
        assert_eq!(parent("/"), "/");
    }
}
