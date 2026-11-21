use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub(super) struct FilesCmd {
    #[command(flatten)]
    socket: super::SocketArg,
    /// Container name or ID
    #[arg(long)]
    container: String,
    #[command(subcommand)]
    action: FileAction,
}

#[derive(Subcommand, Debug)]
enum FileAction {
    /// List immediate children, including hidden files, without downloading contents
    List {
        /// Absolute path inside the container
        path: String,
        /// Print directory metadata as JSON
        #[arg(long)]
        json: bool,
    },
}

impl FilesCmd {
    pub(super) fn run(self) -> smolvm::Result<()> {
        let config = self.socket.config()?;
        let FileAction::List { path, json } = self.action;
        let listing = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(smolvm::engine::files::list_directory(
                &config.socket,
                &self.container,
                &path,
            ))?;
        if json {
            println!(
                "{}",
                serde_json::to_string(&listing).map_err(std::io::Error::other)?
            );
        } else {
            for entry in listing.entries {
                // Quote names so control characters cannot forge extra rows.
                println!(
                    "{:<8} {:>12} {}",
                    entry.kind,
                    entry.size,
                    serde_json::to_string(&entry.name).map_err(std::io::Error::other)?
                );
            }
        }
        Ok(())
    }
}
