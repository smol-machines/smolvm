//! The egress decision as a trait the gateway asks. The gateway terminates
//! every guest flow itself, so it is the one place that decides what a guest
//! may reach — and that decision belongs to whoever embeds the gateway, not
//! this crate. The built-in implementation is [`crate::egress::EgressPolicy`],
//! with the `allowed_cidrs` + `--allow-host` semantics libkrun's TSI path
//! uses.

use std::net::IpAddr;
use std::sync::Arc;

/// What the gateway should do with one guest DNS query.
pub enum DnsDecision {
    /// Answer the guest with these raw DNS bytes, no upstream query. A refusal
    /// is an answer too (NXDOMAIN, SERVFAIL).
    Immediate(Vec<u8>),
    /// Forward upstream; `learn` echoes the answer back through
    /// [`Policy::learn`].
    Forward { learn: bool },
}

/// The egress policy the gateway enforces. Every method runs on the gateway's
/// poll thread: keep them cheap and non-blocking, no host I/O.
pub trait Policy: Send + Sync {
    /// Whether an outbound flow to `ip` may be opened, decided before any host
    /// socket exists. `port` is `None` for a portless flow (an ICMP echo),
    /// which only an any-port rule covers.
    fn allows(&self, ip: IpAddr, port: Option<u16>) -> bool;

    /// The address to dial in place of `ip`, for a stand-in this policy
    /// published; `None` (the default) dials `ip`. The guest-facing socket
    /// keeps `ip` either way, and [`Self::allows`] judges that address rather
    /// than the rewrite — publishing a stand-in is what authorizes it.
    fn rewrite(&self, _ip: IpAddr) -> Option<IpAddr> {
        None
    }

    /// What to do with a guest DNS query; the default forwards it.
    fn dns(&self, _query: &[u8]) -> DnsDecision {
        DnsDecision::Forward { learn: false }
    }

    /// An upstream answer to a query [`Self::dns`] asked to learn from. The
    /// answer echoes its question, so the name is recoverable.
    fn learn(&self, _answer: &[u8]) {}

    /// Whether every DNS query must reach [`Self::dns`], even TCP/53 to a
    /// resolver the guest picked. A policy that *answers* names must set it, or
    /// that resolver quietly wins.
    fn intercepts_dns(&self) -> bool {
        false
    }
}

/// A policy the gateway clones into its relay threads. Cloning shares one
/// policy rather than copying it.
pub type PolicyHandle = Arc<dyn Policy>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The least a policy can implement.
    struct AllowAll;

    impl Policy for AllowAll {
        fn allows(&self, _ip: IpAddr, _port: Option<u16>) -> bool {
            true
        }
    }

    /// Saying nothing must not opt a policy into rewriting destinations,
    /// answering DNS, or swallowing the guest's resolver.
    #[test]
    fn the_defaults_add_nothing_a_policy_did_not_ask_for() {
        let p: &dyn Policy = &AllowAll;
        assert_eq!(p.rewrite("1.1.1.1".parse().unwrap()), None);
        assert!(matches!(p.dns(&[]), DnsDecision::Forward { learn: false }));
        assert!(!p.intercepts_dns());
        p.learn(&[]); // must not panic on an answer it never asked for
    }

    /// Every hook, through the handle the gateway holds — so this covers the
    /// dynamic dispatch too.
    #[test]
    fn a_custom_policy_answers_every_hook_through_the_handle() {
        struct Custom;

        const STANDIN: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
        const REAL: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));

        impl Policy for Custom {
            fn allows(&self, ip: IpAddr, port: Option<u16>) -> bool {
                ip == STANDIN && port == Some(5432)
            }

            fn rewrite(&self, ip: IpAddr) -> Option<IpAddr> {
                (ip == STANDIN).then_some(REAL)
            }

            fn dns(&self, _query: &[u8]) -> DnsDecision {
                DnsDecision::Immediate(vec![0xde, 0xad])
            }

            fn intercepts_dns(&self) -> bool {
                true
            }
        }

        let egress: PolicyHandle = Arc::new(Custom);
        let other: IpAddr = "1.1.1.1".parse().unwrap();

        // Per-port grants — what the built-in allow-list has no way to say.
        assert!(egress.allows(STANDIN, Some(5432)));
        assert!(!egress.allows(STANDIN, Some(22)));
        assert!(!egress.allows(STANDIN, None));
        assert!(!egress.allows(other, Some(5432)));

        assert_eq!(egress.rewrite(STANDIN), Some(REAL));
        assert_eq!(egress.rewrite(other), None);
        assert!(matches!(egress.dns(&[]), DnsDecision::Immediate(b) if b == [0xde, 0xad]));
        assert!(egress.intercepts_dns());

        // Cloning shares the policy rather than copying it.
        let cloned = egress.clone();
        assert!(cloned.allows(STANDIN, Some(5432)));
        assert_eq!(Arc::strong_count(&egress), 2);
    }
}
