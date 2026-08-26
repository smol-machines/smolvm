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
    /// Proxy URL for the in-VM image pull: the explicit `--proxy` flag, else the
    /// standard proxy environment variables (`HTTPS_PROXY`/`HTTP_PROXY`/
    /// `ALL_PROXY`, upper- or lower-case), so it works out of the box on a
    /// proxy-only network the way curl/docker/go do.
    pub fn proxy(&self) -> Option<String> {
        self.proxy.clone().or_else(|| {
            first_nonempty_env(&[
                "HTTPS_PROXY",
                "https_proxy",
                "HTTP_PROXY",
                "http_proxy",
                "ALL_PROXY",
                "all_proxy",
            ])
        })
    }

    /// NO_PROXY bypass list: the `--no-proxy` flag, else `NO_PROXY`/`no_proxy`.
    pub fn no_proxy(&self) -> Option<String> {
        self.no_proxy
            .clone()
            .or_else(|| first_nonempty_env(&["NO_PROXY", "no_proxy"]))
    }

    /// [`Self::proxy`], with a loopback proxy host translated to an address the
    /// GUEST can reach.
    ///
    /// `https_proxy=http://localhost:8118` means "the proxy on my machine", but
    /// passed verbatim into a machine it points at the machine's own loopback,
    /// where nothing listens — under TSI guest-loopback connections stay inside
    /// the guest by design. The host's non-loopback address IS reachable from
    /// the guest (TSI executes outbound connects host-side; virtio-net NATs
    /// through the host), so a loopback proxy host is rewritten to the host's
    /// primary outbound IP. When the proxy only listens on loopback the rewrite
    /// cannot help, and this fails up front with what to change instead of
    /// letting the pull die on an opaque in-guest "connection refused".
    pub fn resolved_proxy(&self) -> smolvm::Result<Option<String>> {
        self.proxy()
            .map(|raw| resolve_loopback_proxy(&raw))
            .transpose()
    }
}

/// Rewrite `raw`'s host to the host machine's primary outbound IP when it is a
/// loopback address; pass every other URL through untouched.
fn resolve_loopback_proxy(raw: &str) -> smolvm::Result<String> {
    let Some((host, port)) = proxy_authority(raw) else {
        return Ok(raw.to_string());
    };
    if !is_loopback_host(&host) {
        return Ok(raw.to_string());
    }

    // The host's outbound IP: a connected UDP socket consults the routing
    // table without sending a packet, so this works on proxy-only networks too
    // (they still route somewhere; the address is what matters, not delivery).
    let outbound = std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            Ok(s.local_addr()?.ip())
        })
        .map_err(|e| {
            smolvm::Error::config(
                "--proxy",
                format!(
                    "proxy '{raw}' points at this host's loopback, which inside a \
                     machine is the machine itself; could not determine a host \
                     address the guest can reach ({e}) — pass --proxy with an \
                     address reachable from the guest (e.g. this host's LAN IP)"
                ),
            )
        })?;

    // Probe the rewritten target from the host. A proxy bound only to loopback
    // is unreachable from the guest no matter what we rewrite to; say so now.
    if let Some(port) = port {
        let target = std::net::SocketAddr::new(outbound, port);
        let timeout = std::time::Duration::from_millis(800);
        if std::net::TcpStream::connect_timeout(&target, timeout).is_err() {
            let loopback: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
            let hint = if std::net::TcpStream::connect_timeout(&loopback, timeout).is_ok() {
                format!(
                    "the proxy answers on 127.0.0.1:{port} but not {target}, so it is \
                     bound to loopback only; bind it to a non-loopback address \
                     (e.g. 0.0.0.0)"
                )
            } else {
                format!("nothing answered on {target} or 127.0.0.1:{port}")
            };
            return Err(smolvm::Error::config(
                "--proxy",
                format!(
                    "proxy '{raw}' is not reachable from inside a machine \
                     (localhost there is the machine itself): {hint}, or pass \
                     --proxy with an address reachable from the guest"
                ),
            ));
        }
    }

    let rewritten = replace_proxy_host(raw, &host, &outbound.to_string());
    tracing::info!(
        original = %raw,
        rewritten = %rewritten,
        "loopback proxy host rewritten to the host's outbound address for guest reachability"
    );
    Ok(rewritten)
}

/// Extract (host, port) from a proxy URL's authority, tolerating a missing
/// scheme, userinfo, and bracketed IPv6. Returns `None` when no host is found.
fn proxy_authority(raw: &str) -> Option<(String, Option<u16>)> {
    let rest = raw.split_once("://").map_or(raw, |(_, r)| r);
    let authority = rest.split(['/', '?']).next()?;
    let hostport = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let (host, port) = if let Some(v6) = hostport.strip_prefix('[') {
        let (host, tail) = v6.split_once(']')?;
        (host, tail.strip_prefix(':'))
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (hostport, None),
        }
    };
    if host.is_empty() {
        return None;
    }
    Some((host.to_string(), port.and_then(|p| p.parse().ok())))
}

/// True for hosts that resolve to this machine's loopback.
fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Replace the first occurrence of `host` in `raw` (the authority parsed from
/// it) with `new_host`, keeping brackets off IPv4 and preserving everything
/// else byte-for-byte.
fn replace_proxy_host(raw: &str, host: &str, new_host: &str) -> String {
    let needle = if raw.contains(&format!("[{host}]")) {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    raw.replacen(&needle, new_host, 1)
}

/// First environment variable in `names` that is set to a non-empty value.
fn first_nonempty_env(names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|n| std::env::var(n).ok().filter(|v| !v.trim().is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_fallback_picks_first_nonempty_in_order() {
        // Isolated names so the test never races real proxy vars.
        let a = "SMOLVM_TEST_PROXY_A_q7";
        let b = "SMOLVM_TEST_PROXY_B_q7";
        std::env::remove_var(a);
        std::env::remove_var(b);
        assert_eq!(first_nonempty_env(&[a, b]), None);
        std::env::set_var(b, "http://b:3128");
        assert_eq!(
            first_nonempty_env(&[a, b]).as_deref(),
            Some("http://b:3128")
        );
        // Whitespace-only is treated as unset; earlier-listed wins once real.
        std::env::set_var(a, "   ");
        assert_eq!(
            first_nonempty_env(&[a, b]).as_deref(),
            Some("http://b:3128")
        );
        std::env::set_var(a, "http://a:3128");
        assert_eq!(
            first_nonempty_env(&[a, b]).as_deref(),
            Some("http://a:3128")
        );
        std::env::remove_var(a);
        std::env::remove_var(b);
    }

    #[test]
    fn authority_parsing_handles_proxy_url_shapes() {
        let cases = [
            ("http://localhost:8118", ("localhost", Some(8118))),
            ("http://user:pw@127.0.0.1:3128", ("127.0.0.1", Some(3128))),
            ("socks5://[::1]:1080", ("::1", Some(1080))),
            ("localhost:8118", ("localhost", Some(8118))),
            ("http://proxy.corp.example", ("proxy.corp.example", None)),
            ("http://10.0.0.7:3128/path", ("10.0.0.7", Some(3128))),
        ];
        for (raw, (host, port)) in cases {
            assert_eq!(
                proxy_authority(raw),
                Some((host.to_string(), port)),
                "parsing {raw}"
            );
        }
    }

    #[test]
    fn loopback_detection_and_host_rewrite() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("LOCALHOST"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.8.9.10"));
        assert!(is_loopback_host("::1"));
        assert!(!is_loopback_host("proxy.corp.example"));
        assert!(!is_loopback_host("10.0.0.7"));

        assert_eq!(
            replace_proxy_host("http://user@localhost:8118", "localhost", "10.1.2.3"),
            "http://user@10.1.2.3:8118"
        );
        assert_eq!(
            replace_proxy_host("socks5://[::1]:1080", "::1", "10.1.2.3"),
            "socks5://10.1.2.3:1080"
        );
    }

    #[test]
    fn non_loopback_proxy_passes_through_untouched() {
        for raw in [
            "http://proxy.corp.example:3128",
            "http://10.0.0.7:3128",
            "not a url at all",
        ] {
            assert_eq!(resolve_loopback_proxy(raw).unwrap(), raw);
        }
    }

    #[test]
    fn loopback_proxy_with_dead_port_fails_with_guidance() {
        // Nothing listens on this port anywhere; the resolver must refuse the
        // URL up front rather than hand the guest a dead loopback address.
        let err = resolve_loopback_proxy("http://localhost:1").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("reachable from the guest"),
            "error must tell the user what to do, got: {msg}"
        );
    }

    #[test]
    fn loopback_proxy_with_live_listener_is_rewritten() {
        // Bind on all interfaces the way a guest-reachable proxy would.
        let listener = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let resolved = resolve_loopback_proxy(&format!("http://localhost:{port}")).unwrap();
        assert!(
            !resolved.contains("localhost"),
            "loopback host must be rewritten, got: {resolved}"
        );
        assert!(
            resolved.ends_with(&format!(":{port}")),
            "port kept: {resolved}"
        );
    }

    #[test]
    fn explicit_flag_wins_over_env() {
        let opts = ProxyOpts {
            proxy: Some("http://flag:3128".to_string()),
            no_proxy: Some("localhost".to_string()),
        };
        // The flag short-circuits before any env lookup.
        assert_eq!(opts.proxy().as_deref(), Some("http://flag:3128"));
        assert_eq!(opts.no_proxy().as_deref(), Some("localhost"));
    }
}
