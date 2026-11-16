use serde::Deserialize;
use std::collections::HashSet;

#[derive(Clone, Debug)]
pub enum Request {
    List {
        target: String,
        path: String,
    },
    Transfer {
        target: String,
        guest: String,
        local: std::path::PathBuf,
        upload: bool,
    },
}

impl Request {
    pub fn target(&self) -> &str {
        match self {
            Self::List { target, .. } | Self::Transfer { target, .. } => target,
        }
    }
    pub fn mutates(&self) -> bool {
        matches!(self, Self::Transfer { .. })
    }
    pub fn machine_operation(self) -> crate::model::Operation {
        match self {
            Self::List { target, path } => {
                crate::model::Operation::ListFiles { name: target, path }
            }
            Self::Transfer {
                target,
                guest,
                local,
                upload,
            } => crate::model::Operation::TransferFile {
                name: target,
                guest,
                local,
                upload,
            },
        }
    }
}

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

/// Successful folder visits only; a failed read must not move the cursor.
#[derive(Default)]
pub struct History {
    paths: Vec<String>,
    cursor: usize,
}

impl History {
    pub fn back(&self) -> Option<(usize, &str)> {
        self.cursor
            .checked_sub(1)
            .map(|index| (index, self.paths[index].as_str()))
    }

    pub fn forward(&self) -> Option<(usize, &str)> {
        self.paths
            .get(self.cursor + 1)
            .map(|path| (self.cursor + 1, path.as_str()))
    }

    pub fn record(&mut self, path: &str, target: Option<usize>) {
        if let Some(index) = target
            && self.paths.get(index).is_some_and(|p| p == path)
        {
            self.cursor = index;
            return;
        }
        if self.paths.get(self.cursor).is_some_and(|p| p == path) {
            return;
        }
        self.paths.truncate(self.cursor + 1);
        self.paths.push(path.to_owned());
        if self.paths.len() > 64 {
            self.paths.remove(0);
        }
        self.cursor = self.paths.len() - 1;
    }
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
    fn folder_history_preserves_forward_on_refresh_and_branches_on_new_visit() {
        let mut history = History::default();
        assert!(history.back().is_none());
        assert!(history.forward().is_none());
        history.record("/workspace", None);
        history.record("/workspace/src", None);
        history.record("/workspace/src/lib", None);
        let (index, path) = history.back().unwrap();
        let path = path.to_owned();
        // Merely requesting a folder (including a failed request) changes nothing.
        assert_eq!(history.back(), Some((1, "/workspace/src")));
        history.record(&path, Some(index));
        history.record(&path, None);
        assert_eq!(history.forward(), Some((2, "/workspace/src/lib")));
        history.record("/other", None);
        assert!(history.forward().is_none());
        assert_eq!(history.back(), Some((1, "/workspace/src")));
        for index in 0..100 {
            history.record(&format!("/folder-{index}"), None);
        }
        assert_eq!(history.paths.len(), 64);
        assert_eq!(history.back(), Some((62, "/folder-98")));
        history.record("/literal/../path", None);
        assert_eq!(history.paths.last().unwrap(), "/literal/../path");
    }
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
