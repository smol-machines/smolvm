//! Structured file access to the running machine's workload filesystem.
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct FilesCmd {
    #[arg(long)]
    pub name: String,
    #[command(subcommand)]
    pub command: FilesAction,
}

#[derive(Subcommand, Debug)]
pub enum FilesAction {
    /// List a directory without following its child symlinks
    List {
        path: String,
        #[arg(long)]
        json: bool,
    },
    /// Upload one regular file, replacing the destination atomically
    Upload {
        source: PathBuf,
        destination: String,
    },
    /// Upload a folder into exactly the destination, merging existing directories
    UploadFolder {
        source: PathBuf,
        destination: String,
    },
    /// Download one file, replacing the local destination atomically
    Download {
        source: String,
        destination: PathBuf,
    },
    /// Stream a directory as a tar archive without following symbolic links
    Archive {
        source: String,
        destination: PathBuf,
    },
}

fn validate_path(path: &str) -> smolvm::Result<()> {
    if !path.starts_with('/') || path.contains('\0') {
        return Err(smolvm::Error::config(
            "files",
            "Use an absolute guest path.",
        ));
    }
    Ok(())
}

impl FilesCmd {
    pub fn run(self) -> smolvm::Result<()> {
        let guest = match &self.command {
            FilesAction::List { path, .. } => path,
            FilesAction::Upload { destination, .. }
            | FilesAction::UploadFolder { destination, .. } => destination,
            FilesAction::Download { source, .. } | FilesAction::Archive { source, .. } => source,
        };
        validate_path(guest)?;
        let db = smolvm::db::SmolvmDb::open()?;
        let record = db
            .get_vm(&self.name)?
            .ok_or_else(|| smolvm::Error::vm_not_found(&self.name))?;
        // This only connects to an existing guest; browsing never boots one.
        let (manager, mut client) = super::vm_common::ensure_running_and_connect(&Some(self.name))?;
        manager.detach();
        client.use_target(smolvm::workload::machine_target(&record))?;
        let archive = matches!(self.command, FilesAction::Archive { .. });
        match self.command {
            FilesAction::UploadFolder {
                source,
                destination,
            } => {
                let mut progress = super::ProgressBar::new("Uploading folder", None);
                let size =
                    client.upload_directory(&source, &destination, |sent| progress.update(sent))?;
                progress.finish(size);
            }
            FilesAction::List { path, json } => {
                let entries = client.list_directory(&path)?;
                if json {
                    println!("{}", serde_json::json!({"path": path, "entries": entries}));
                } else {
                    for entry in entries {
                        println!("{}\t{}\t{}", entry.kind, entry.size, entry.name);
                    }
                }
            }
            FilesAction::Upload {
                source,
                destination,
            } => {
                if !std::fs::metadata(&source)
                    .map_err(|e| smolvm::Error::agent("stat upload", e.to_string()))?
                    .is_file()
                {
                    return Err(smolvm::Error::config(
                        "files",
                        "Choose a regular file to upload.",
                    ));
                }
                let file = std::fs::File::open(&source)
                    .map_err(|e| smolvm::Error::agent("open upload", e.to_string()))?;
                let metadata = file
                    .metadata()
                    .map_err(|e| smolvm::Error::agent("stat upload", e.to_string()))?;
                if !metadata.is_file() {
                    return Err(smolvm::Error::config(
                        "files",
                        "Choose a regular file to upload.",
                    ));
                }
                let mut progress = super::ProgressBar::new("Uploading file", Some(metadata.len()));
                client.write_file_from_reader_with_progress(
                    &destination,
                    file,
                    metadata.len(),
                    Default::default(),
                    |sent| progress.update(sent),
                )?;
                progress.finish(metadata.len());
            }
            FilesAction::Download {
                source,
                destination,
            }
            | FilesAction::Archive {
                source,
                destination,
            } => {
                let mut progress = super::ProgressBar::new(
                    if archive {
                        "Downloading folder archive"
                    } else {
                        "Downloading file"
                    },
                    None,
                );
                let parent = destination
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(std::path::Path::new("."));
                let staging = tempfile::Builder::new()
                    .prefix(".smol-download-")
                    .tempdir_in(parent)
                    .map_err(|e| smolvm::Error::agent("stage download", e.to_string()))?;
                let payload = staging.path().join("payload");
                let size = if archive {
                    client.archive_directory_to_path(&source, &payload, |received| {
                        progress.update(received)
                    })?
                } else {
                    client.read_file_to_path(&source, &payload, |received| {
                        progress.update(received)
                    })?
                };
                std::fs::rename(&payload, &destination)
                    .map_err(|e| smolvm::Error::agent("save download", e.to_string()))?;
                progress.finish(size);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        files: FilesCmd,
    }
    #[test]
    fn file_arguments_do_not_confuse_host_drive_or_colons_with_machine_names() {
        let parsed = Cli::try_parse_from([
            "files",
            "--name",
            "dev",
            "upload",
            r"C:\project files\input.txt",
            "/workspace/a:b",
        ])
        .unwrap();
        assert_eq!(parsed.files.name, "dev");
        let FilesAction::Upload {
            source,
            destination,
        } = parsed.files.command
        else {
            panic!("upload");
        };
        assert_eq!(source, PathBuf::from(r"C:\project files\input.txt"));
        assert_eq!(destination, "/workspace/a:b");
        let parsed = Cli::try_parse_from([
            "files",
            "--name",
            "dev",
            "archive",
            "/workspace/a:b",
            r"C:\project files\folder.tar",
        ])
        .unwrap();
        let FilesAction::Archive {
            source,
            destination,
        } = parsed.files.command
        else {
            panic!("archive");
        };
        assert_eq!(source, "/workspace/a:b");
        assert_eq!(destination, PathBuf::from(r"C:\project files\folder.tar"));

        let parsed = Cli::try_parse_from([
            "files",
            "--name",
            "dev",
            "upload-folder",
            r"C:\project files\folder",
            "/workspace/a:b",
        ])
        .unwrap();
        let FilesAction::UploadFolder {
            source,
            destination,
        } = parsed.files.command
        else {
            panic!("upload-folder");
        };
        assert_eq!(source, PathBuf::from(r"C:\project files\folder"));
        assert_eq!(destination, "/workspace/a:b");

        assert!(validate_path("relative").is_err());
        assert!(validate_path("/workspace/with space ; $(true)").is_ok());
    }
}
