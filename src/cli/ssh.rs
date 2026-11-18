use clap::Args;

#[derive(Args, Debug)]
pub struct Configure {
    /// Machine to expose through the generated SSH configuration
    #[arg(long)]
    name: String,
}
impl Configure {
    pub fn run(self) -> smolvm::Result<()> {
        let connection = smolvm::ssh::configure(&self.name)
            .map_err(|e| smolvm::Error::config("configure SSH", format!("{e:#}")))?;
        println!(
            "{}",
            serde_json::to_string(&connection).map_err(std::io::Error::other)?
        );
        Ok(())
    }
}

#[derive(Args, Debug)]
pub struct Proxy {
    /// Generated path context prevents shell expansion and selects the correct state
    #[arg(long)]
    context_hex: String,
}
impl Proxy {
    pub fn run(self) -> smolvm::Result<()> {
        let action = || -> anyhow::Result<()> {
            let name = smolvm::ssh::proxy_machine(&self.context_hex)?;
            // Validate identity before starting anything. A stale config must
            // not create a replacement machine or silently trust a new key.
            let record = smolvm::db::SmolvmDb::open()?
                .get_vm(&name)?
                .ok_or_else(|| anyhow::anyhow!("selected machine does not exist"))?;
            let manager = smolvm::agent::AgentManager::for_vm(&name)?;
            if record.paused_checkpoint.is_some() || !manager.is_running() {
                let action = if record.paused_checkpoint.is_some() {
                    "resume"
                } else {
                    "start"
                };
                let status = std::process::Command::new(std::env::current_exe()?)
                    .args(["machine", action, "--name", &name])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::inherit())
                    .status()?;
                anyhow::ensure!(
                    status.success(),
                    "could not start the selected machine for SSH"
                );
            }
            smolvm::ssh::proxy(&name)
        };
        action().map_err(|e| smolvm::Error::config("SSH connection", format!("{e:#}")))
    }
}
