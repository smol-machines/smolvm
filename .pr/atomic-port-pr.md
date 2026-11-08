# fix(network): retain OS-allocated local TCP listeners

Local SDK clients need an allocated host port whose listener stays owned during
publication. Add an atomic loopback allocation operation to the shared TCP
acceptor, expose it through the running machine's control socket, and persist
the returned mapping under the existing machine lock.

The accompanying Python SDK contribution exposes `publish_atomic`. OpenHands can
then start a local Agent Server without selecting and releasing a free port
before binding it.

Validation: 183 network tests and four filtered engine tests passed. A local
build served HTTP through two allocated ports in a real Alpine microVM with
outbound networking disabled, then deleted the owned VM. See
[atomic-port-validation.md](atomic-port-validation.md) for runtime details and
remaining platform/release checks.
