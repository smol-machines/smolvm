use anyhow::{Context, Result};
use smolvm_secret_broker::{Broker, Config};

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let path = args
        .next()
        .context("usage: smolvm-secret-broker HOST_CONFIG.json")?;
    anyhow::ensure!(
        args.next().is_none(),
        "expected one host configuration file"
    );
    let config: Config = serde_json::from_slice(&std::fs::read(path)?)?;
    let broker = Broker::new(config)?;
    let listener = tokio::net::TcpListener::bind(broker.listen_address()).await?;
    println!("credential broker listening on {}", listener.local_addr()?);
    tokio::select! {
        result = broker.serve(listener) => result,
        result = tokio::signal::ctrl_c() => { result?; Ok(()) }
    }
}
