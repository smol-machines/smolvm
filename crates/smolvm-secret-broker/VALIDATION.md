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

## Service and request-lifecycle hardening — 2026-09-19

- Linux TSI and virtio-net real-VM acceptance passed again with dotenvx 2.28.0
  after hardening. TSI additionally verified SIGTERM cleanup and same-socket
  restart. These use the published 1.16.2 runtime and synthetic credentials.
- A slow-body revocation regression returned HTTP 200 with the previous
  dispatch behavior (one control run), then HTTP 403 with the additional
  dispatch-time authorization check. No credential-bearing HTTP reached the
  upstream in the fixed case. This does not cancel operations already dispatched.
- A separate root-authorized transient systemd test passed with DynamicUser,
  private runtime storage, LoadCredential, a 256 MiB memory cap and 96-task cap.
  UID 1000 could not read the source credentials, runtime credentials, TLS key,
  or broker process environment; an authenticated HTTPS request still succeeded.
  The service and fixtures were removed afterwards.
- LoadCredential exposed root-owned 0440 files, which the broker refused.
  The service launcher copies them into its private tmpfs runtime directory as
  0600 files. Credential permission checks were not weakened. Restart is required
  to load changed source credentials in this deployment.
- The service test and real-VM tests are separate: isolated-service plus VM
  attachment, dotenvx under that service identity, and fleet UID attachment have
  not yet been validated together. Host root/sudo can still read secrets.
- Eight unit tests, package formatting and clippy with warnings denied passed.
  Offline synthetic acceptance now runs in the existing native Linux x86_64
  and ARM64 CI jobs; remote CI has not yet been run on this branch.

Reproduce the isolated-service acceptance (Linux/systemd, scoped root access):

```sh
sudo python3 -B crates/smolvm-secret-broker/tests/service_acceptance.py \
  --broker /absolute/path/to/smolvm-secret-broker \
  --observer-uid 1000 --observer-gid 1000
```

At that stage, production readiness was withheld pending machine-bound authorization and
branch/restore policy, integrated isolated deployment, cross-platform validation,
and security review. The above is evidence for individual safeguards, not a
claim that those remaining boundaries are solved.

## Process-bound Linux deployment — 2026-09-19

Default startup now requires Linux Unix-socket process binding. TCP/bearer-only
compatibility mode needs an explicit `allow_bearer_only: true`; it cannot be
combined as an alternate listener for a process-bound broker.

The integrated systemd + real KVM VM + dotenvx 2.28.0 lifecycle passed with:

- Service credentials and dotenvx decryption keys isolated from UID 1000.
- Missing authorization denied, then the explicitly authorized VMM succeeded.
- Child carrying its parent's token denied, including an inherited live TLS
  connection; the parent's live session remained usable.
- Explicit child authorization succeeded, and the old parent grant stopped.
- Restarted child denied until its new process incarnation was authorized.
- Unrelated host process denied; deleting the authorization record denied use.
- Malformed or public-readable authorization records denied; restoring a valid
  private record recovered access without restarting the service.
- Portable checkpoint capture rejected published sockets explicitly, without
  creating an artifact. No portable broker-attachment restore claim is made.

This uses PID, UID, process start ticks and boot ID from the kernel, not headers
or guest labels. Clones share a UID, making UID-only authorization insufficient.
The administrator owns the authorization file outside machine state; changes
are checked at acceptance, each request and after body collection.

Two deployment corrections came from real runs: `--branchable` belongs on
`machine start`, not `create`; dotenvx under DynamicUser requires a private
runtime home. The failed runs were cleaned up and are not counted as passes.

Eleven unit tests pass. The integrated tests use synthetic credentials, Alpine
and curl/Python, not real customer accounts. This is a Linux-admin-managed first
slice, not automated Smol Cloud provisioning, cross-platform process identity or
an independently audited guarantee. The source's existing published-socket
checkpoint guard remains in force.

The lightweight no-VM acceptance also checks Unix process binding, missing and
stale identities, so those checks run in both native Linux CI jobs. Its first
Unix client probe failed because Python's TCP client sets TCP_NODELAY on an
AF_UNIX socket; the test now uses a Unix-specific connection implementation.
This was a test-client error, not a broker authorization failure.
