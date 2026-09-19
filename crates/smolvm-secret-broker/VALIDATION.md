# First functional acceptance — 2026-09-19

Scope: local Linux x86_64, real KVM VM, published SmolVM 1.16.2 bundle, new
standalone broker built from this worktree. Synthetic credentials and a local
HTTPS upstream only. No production accounts, cloud deployment, or dotenvx API.

Results:

- `cargo test -p smolvm-secret-broker --locked`: 4/4 unit tests passed.
- `cargo clippy -p smolvm-secret-broker --all-targets -- -D warnings`: passed.
- Package formatting and `git diff --check`: passed.
- Offline acceptance: HTTPS substitution, proxy-auth stripping, wrong capability,
  wrong destination, authority mismatch, wrong placeholder/location, request-size
  limit, upgrade refusal, response-size/encoding/reflection refusal, redirect
  non-following, live credential rotation/removal, and revocation on an existing
  TLS connection passed.
- Omitted private upstream CA: broker returned 502 and the upstream observed no
  credential-bearing HTTP request. The guest trusting the proxy does not relax
  upstream certificate verification.
- Real VM acceptance passed three times after choosing the supported virtio-net
  host-service bridge; the last two runs used the strict egress floor. Final
  test additionally included the untrusted-upstream case above.
- Alpine/curl made an ordinary HTTPS request using a placeholder environment
  variable. The upstream verified the substituted synthetic credential. Removing
  the credential produced curl exit 22 with HTTP 502, not a timeout.
- Strict egress denied a direct connection to the unrelated host upstream even
  with client certificate checking explicitly disabled for that negative probe.
- All test machines and broker processes were cleaned up. Ephemeral certificate,
  credential, and configuration fixtures were removed by the harness.

Initial TSI-to-loopback test failed to connect. It was not counted as a passing
VM test; the harness now uses the existing exact-port virtio-net host bridge.

This is **not production-ready**. Guest-visible proxy capabilities remain
copyable and would be inherited by a checkpoint/branch. Machine-bound identities,
branch/restore reauthorization, automatic attachment/trust setup, public cloud
integration, host-admin separation, enforced gateway-only public egress,
cross-platform acceptance and security review are still outstanding. Existing
secret injection and machine lifecycle semantics have not been changed.
