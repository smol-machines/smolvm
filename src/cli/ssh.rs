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
            smolvm::ssh::proxy(&name)
        };
        action().map_err(|e| smolvm::Error::config("SSH connection", format!("{e:#}")))
    }
}
