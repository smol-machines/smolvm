//! Ordered, host-enforced L4 egress rules. The list is deliberately small and
//! non-expressive; application-layer decisions belong in the host decider.

use serde::{Deserialize, Serialize};

/// Guest protocol at the host gateway.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowTransport {
    /// TCP byte stream.
    Tcp,
    /// UDP datagram.
    Udp,
    /// ICMP echo request.
    Icmp,
}

/// First-match action for a guest flow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    /// Connect directly through the VM host.
    Allow,
    /// Refuse before opening any upstream socket.
    Deny,
    /// Send TCP to this launch's host interceptor.
    Redirect,
}

/// Inclusive destination port range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortRange {
    /// First allowed port, from 1 through 65535.
    pub start: u16,
    /// Last allowed port, greater than or equal to `start`.
    pub end: u16,
}

/// One ordered match rule. Omitted match dimensions mean "any".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EgressRule {
    /// TCP, UDP, or ICMP; omitted means all three.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<FlowTransport>,
    /// IPv4 or IPv6 address/CIDR; omitted means any destination address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<String>,
    /// Inclusive TCP/UDP destination ports; omitted means any port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<PortRange>,
    /// Allow, deny, or redirect to this launch's host interceptor.
    pub action: RuleAction,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_shape_is_ordered_rule_data() {
        let rule: EgressRule = serde_json::from_str(
            r#"{"transport":"tcp","cidr":"1.1.1.0/24","ports":{"start":443,"end":443},"action":"redirect"}"#,
        )
        .unwrap();
        assert_eq!(rule.transport, Some(FlowTransport::Tcp));
        assert_eq!(rule.action, RuleAction::Redirect);
        assert!(serde_json::from_str::<EgressRule>(r#"{"action":"allow","unknown":1}"#).is_err());
    }
}
