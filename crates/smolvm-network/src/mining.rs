//! Recognizes DNS names that belong to cryptocurrency mining pools.
//!
//! A machine resolving a pool's hostname is about to connect a miner to it, so
//! a lookup is definitive evidence that heavy CPU use is mining rather than an
//! ordinary workload. The list holds registrable domains that only pools use;
//! a name matches when it is one of them or a subdomain (`rx.unmineable.com`).
//! Generic words like `pool` are deliberately not matched: `pool.ntp.org` is not
//! a mining pool, and a false match here would accuse a customer.

/// Registrable domains operated by mining pools and pool proxies.
const MINING_POOL_DOMAINS: &[&str] = &[
    "2miners.com",
    "antpool.com",
    "c3pool.com",
    "c3pool.org",
    "dxpool.com",
    "emcd.io",
    "ethermine.org",
    "f2pool.com",
    "flexpool.io",
    "hashcity.org",
    "hashvault.pro",
    "herominers.com",
    "hiveon.net",
    "k1pool.com",
    "kryptex.network",
    "minergate.com",
    "minexmr.com",
    "mining-dutch.nl",
    "miningpoolhub.com",
    "moneroocean.stream",
    "monerohash.com",
    "nanopool.org",
    "nicehash.com",
    "p2pool.io",
    "poolin.com",
    "prohashing.com",
    "rplant.xyz",
    "supportxmr.com",
    "unmineable.com",
    "viabtc.com",
    "woolypooly.com",
    "xmrfast.com",
    "xmrpool.eu",
    "zergpool.com",
    "zpool.ca",
];

/// The pool domain `name` belongs to, if any. `name` may carry a trailing dot
/// and any letter case, as it does in a DNS question.
pub fn mining_pool_domain(name: &str) -> Option<&'static str> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    MINING_POOL_DOMAINS.iter().copied().find(|domain| {
        name == *domain
            || name
                .strip_suffix(domain)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pool_hostname_or_any_subdomain_of_it_matches() {
        assert_eq!(
            mining_pool_domain("rx.unmineable.com"),
            Some("unmineable.com")
        );
        assert_eq!(
            mining_pool_domain("RX.UNMINEABLE.COM."),
            Some("unmineable.com")
        );
        assert_eq!(
            mining_pool_domain("pool.supportxmr.com"),
            Some("supportxmr.com")
        );
        assert_eq!(mining_pool_domain("nicehash.com"), Some("nicehash.com"));
    }

    #[test]
    fn lookalikes_and_generic_pool_words_do_not_match() {
        for name in [
            "pool.ntp.org",
            "notunmineable.com",
            "unmineable.com.example.org",
            "github.com",
            "registry-1.docker.io",
            "xmr.example.com",
        ] {
            assert_eq!(mining_pool_domain(name), None, "{name}");
        }
    }
}
