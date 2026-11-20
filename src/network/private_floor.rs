//! Hosts a machine was told to reach that `--block-private` keeps closed.
//!
//! `--allow-host` and a credential's host say where a machine should connect,
//! but only `--allow-private` reopens a private range. A name that resolves
//! into one is refused at connect time with nothing to say why, so every start
//! asks here first: the CLI prints the answer, the API and embedded starts log
//! it.

use std::net::IpAddr;

use smolvm_protocol::{CredentialPolicy, EgressRule};

/// A named host whose every address `--block-private` blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedHost {
    /// The name as the machine's configuration spells it.
    pub host: String,
    /// The private addresses it resolved to.
    pub addrs: Vec<IpAddr>,
}

impl BlockedHost {
    /// What to tell the user, with the flag that reopens the host.
    pub fn warning(&self) -> String {
        let addrs: Vec<String> = self.addrs.iter().map(IpAddr::to_string).collect();
        let reopen: Vec<String> = self
            .addrs
            .iter()
            .map(|addr| format!("--allow-private {}", ipnet::IpNet::from(*addr)))
            .collect();
        format!(
            "'{}' resolves to {}, which --block-private blocks, so the machine cannot reach it. \
             Reopen it with {} (Smolfile: [network] allow_private).",
            self.host,
            addrs.join(", "),
            reopen.join(" "),
        )
    }
}

/// The exact names in `allowed_hosts` and `credentials` that the machine can
/// never reach because `block_private` blocks every address they resolve to.
/// A name that does not resolve, or a wildcard, is left to the checks that
/// already cover it.
pub fn hosts_blocked_by_private_floor(
    block_private: Option<&[String]>,
    egress_rules: &[EgressRule],
    allowed_hosts: Option<&[String]>,
    credentials: Option<&CredentialPolicy>,
    resolve: impl Fn(&str) -> Result<Vec<String>, String>,
) -> Vec<BlockedHost> {
    let Some(exceptions) = block_private else {
        return Vec::new();
    };
    // The floor and the rules the launcher will enforce; a rule it would
    // refuse is reported there.
    let Ok(policy) = smolvm_network::EgressPolicy::new(None, None)
        .with_rules(egress_rules)
        .and_then(|policy| policy.with_private_floor(exceptions))
    else {
        return Vec::new();
    };

    let mut names: Vec<&str> = Vec::new();
    let listed = allowed_hosts
        .into_iter()
        .flatten()
        .filter_map(|entry| smolvm_protocol::host_pattern::static_resolution_host(entry));
    let bound = credentials
        .into_iter()
        .flat_map(|policy| &policy.credentials)
        .flat_map(|binding| &binding.allowed_hosts)
        .map(String::as_str)
        .filter(|host| !host.contains('*'));
    for name in listed.chain(bound) {
        if !names.contains(&name) {
            names.push(name);
        }
    }

    names
        .into_iter()
        .filter_map(|host| {
            let addrs: Vec<IpAddr> = resolve(host)
                .ok()?
                .iter()
                .filter_map(|cidr| cidr.split('/').next()?.parse().ok())
                .collect();
            (!addrs.is_empty() && addrs.iter().all(|addr| policy.private_floor_blocks(*addr))).then(
                || BlockedHost {
                    host: host.to_string(),
                    addrs,
                },
            )
        })
        .collect()
}

/// [`hosts_blocked_by_private_floor`] for a stored machine, resolving its
/// names now.
pub fn record_hosts_blocked_by_private_floor(record: &crate::config::VmRecord) -> Vec<BlockedHost> {
    hosts_blocked_by_private_floor(
        record.block_private.as_deref(),
        &record.egress_rules,
        record.dns_filter_hosts.as_deref(),
        record.credential_policy.as_ref(),
        crate::smolfile::resolve_host_to_cidrs,
    )
}

/// Log the warning for each host `record` names that its private floor keeps
/// closed. A start through the API or an embedding program has no terminal to
/// print to, so the log is where its operator finds out.
///
/// Silent on the strict floor `serve` runs with by default: nothing a machine
/// sets reopens a private range there, so the advice would be wrong.
pub fn log_record_hosts_blocked_by_private_floor(name: &str, record: &crate::config::VmRecord) {
    for host in record_hosts_blocked_by_private_floor(record) {
        tracing::warn!(machine = %name, host = %host.host, "{}", host.warning());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resolver(host: &str) -> Result<Vec<String>, String> {
        match host {
            "gateway.example.ts.net" => Ok(vec!["100.81.17.207/32".into()]),
            "v6.example.ts.net" => Ok(vec!["fd7a:115c:a1e0::9/128".into()]),
            "split.example.com" => Ok(vec!["10.0.0.5/32".into(), "203.0.113.5/32".into()]),
            "example.com" => Ok(vec!["203.0.113.7/32".into()]),
            other => Err(format!("failed to resolve '{other}'")),
        }
    }

    fn credential(hosts: &[&str]) -> CredentialPolicy {
        serde_json::from_value(serde_json::json!({
            "credentials": [{
                "name": "x",
                "environment_variable": "PROBE_X",
                "allowed_hosts": hosts,
            }]
        }))
        .unwrap()
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn a_private_host_is_reported_until_allow_private_reopens_it() {
        let hosts = strings(&[
            "gateway.example.ts.net",
            "=v6.example.ts.net",
            "*.example.ts.net",
            "split.example.com",
            "example.com",
            "missing.invalid",
        ]);
        let policy = credential(&["gateway.example.ts.net", "*.example.com"]);
        let blocked = |exceptions: Option<&[String]>| {
            hosts_blocked_by_private_floor(exceptions, &[], Some(&hosts), Some(&policy), resolver)
        };

        assert!(
            blocked(None).is_empty(),
            "nothing is blocked without the flag"
        );

        let found = blocked(Some(&[]));
        let names: Vec<&str> = found.iter().map(|host| host.host.as_str()).collect();
        assert_eq!(names, ["gateway.example.ts.net", "v6.example.ts.net"]);
        let warning = found[0].warning();
        assert!(warning.contains("resolves to 100.81.17.207"), "{warning}");
        assert!(
            warning.contains("--allow-private 100.81.17.207/32"),
            "{warning}"
        );
        assert!(found[1]
            .warning()
            .contains("--allow-private fd7a:115c:a1e0::9/128"));

        let reopened = strings(&["100.81.17.207/32", "fd7a:115c:a1e0::/48"]);
        assert!(blocked(Some(&reopened)).is_empty());
    }

    #[test]
    fn a_credential_host_alone_is_reported() {
        let policy = credential(&["gateway.example.ts.net"]);
        let found = hosts_blocked_by_private_floor(Some(&[]), &[], None, Some(&policy), resolver);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].addrs, ["100.81.17.207".parse::<IpAddr>().unwrap()]);
    }
}
