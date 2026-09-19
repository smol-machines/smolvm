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

## TSI and dotenvx follow-up — 2026-09-19

- Added an optional private Unix broker listener carried over existing
  `--mount-socket`/vsock. A guest-local socat listener accepts ordinary HTTPS
  proxy clients; machine networking remains TSI, not an implicit virtio-net fallback.
- Linux TSI + file-backed credentials: full acceptance passed, including a real
  Alpine guest, unchanged curl, credential substitution and removal.
- Linux TSI + dotenvx 2.28.0: full acceptance passed using an encrypted synthetic
  `.env`, explicit private `.env.keys`, and `dotenvx run` wrapping only the broker.
  The broker config references `secret_env`; no upstream credential is passed to
  Smol or the guest. Access-token removal returns an explicit proxy denial.
- Linux virtio-net + dotenvx 2.28.0: the same encrypted-env acceptance passed,
  including strict-egress refusal of the unrelated host service.
- Dotenvx binary came from its official GitHub v2.28.0 release and matched the
  release's SHA-256 checksum manifest. It was not installed globally.
- `cargo test`: 8/8 tests passed; clippy passed with warnings denied. Socket tests
  cover private permissions, existing paths, cleanup, and replacement preservation.
- One early dotenvx fixture command wrote its synthetic `.env.keys` into the
  worktree rather than the temporary directory. It was removed; the harness now
  explicitly sets both cwd and `-fk` to its private temporary directory. No real
  credentials were used.
- A TSI test incorrectly reused the virtio-net gateway address for an unrelated
  egress probe; the exec exceeded its 15-second harness timeout despite curl's
  two-second timeout. It is not counted as a pass or an egress guarantee. The
  TSI test now validates the socket bridge instead. General TSI egress/timeout
  behavior was not changed by this work.

Remaining limits above still apply. In particular this is not branch-safe
machine identity, cloud integration, or a production-ready security boundary.
