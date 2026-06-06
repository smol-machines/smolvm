//! Shared `--proxy` / `--no-proxy` flags for subcommands that pull images.
//!
//! Flatten this struct into a subcommand's `Args` derive to expose the flags
//! consistently. The values flow into `AgentRequest::Pull` and are set on
//! the `crane` subprocess as `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`.

use clap::Args;

#[derive(Args, Debug, Clone, Default)]
pub struct ProxyOpts {
    /// Proxy URL used for the in-VM image pull (sets HTTP_PROXY and HTTPS_PROXY
    /// on the registry client). Example: `http://192.168.127.254:3128`.
    #[arg(long, value_name = "URL", global = false)]
    pub proxy: Option<String>,

    /// Comma-separated NO_PROXY list of hosts/CIDRs that bypass the proxy
    /// during image pull. Example: `127.0.0.1,localhost,.internal`.
    #[arg(long, value_name = "LIST", global = false)]
    pub no_proxy: Option<String>,
}

impl ProxyOpts {
    pub fn proxy(&self) -> Option<&str> {
        self.proxy.as_deref()
    }

    pub fn no_proxy(&self) -> Option<&str> {
        self.no_proxy.as_deref()
    }
}
