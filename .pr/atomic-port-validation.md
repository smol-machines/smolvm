# Atomic local port publication

Branch: `fix/atomic-local-port-allocation`.
Base: `b64a23992668620818eaa4237e18ad15a8a3c8a1`.

The engine binds `127.0.0.1:0` and registers that same listener with the shared TCP
acceptor. It returns the allocated port through the local control socket and
saves the mapping under the machine's existing lock. A database update failure
restores the original published set. Both virtio-net and TSI forwarding expose
the operation. Existing complete-set replacement requests retain their response.

The Python SDK contribution in the separate `smol` repository exposes this as
`Machine.publish_atomic(guest)` and `AsyncMachine.publish_atomic(guest)`. The
OpenHands contribution uses it to publish Agent Server without a probe/rebind
race. These changes need a coordinated engine/helper/Python-wheel release.

Validation on Apple Silicon macOS, November 8, 2026:

- `cargo test -p smolvm-network --lib --locked`: 183 passed.
- Engine `cargo test --lib atomic_ --locked`: 4 passed, including the new real
  forwarding test. The engine was linked against the libraries bundled in the
  published `smolmachines==1.32.4` wheel.
- Python SDK tests: 9 passed without virtualization.
- Python SDK opt-in VM test: passed using the locally compiled engine and native
  binding, the published wheel's libraries/rootfs, and a signed local boot helper.
  A published Alpine image booted with outbound networking disabled. Two allocated
  ports stayed bound and served HTTP; deletion removed the exact owned machine.
- `cargo fmt --all --check` and `git diff --check`: passed.

The VM result uses a local build, not a published wheel containing this change.
Linux x86_64 and arm64 live tests remain pending. OpenHands' published-image and
conversation acceptance is recorded in the OpenHands contribution.

Local native validation used this engine's lockfile as the starting point for
the SDK build. The SDK checkout's committed native lock targets engine 1.32.2;
this engine checkout is 1.34.0. Dependency and release bookkeeping belongs in
the coordinated Smol release. No unrelated dependency updates are included here.
