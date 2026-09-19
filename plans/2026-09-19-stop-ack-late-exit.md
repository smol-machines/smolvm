# Stop acknowledgment and late process exit

Decision: Sean's runtime reliability task, delegated by Root to Pasteur on2026-09-19, authorizes this bounded correction. The wh19 child28410 shutdown acknowledgment connection closed; the CLI sampled its process alive and refused. The later retained census found it absent while its database record remained running. These observations do not establish the guest exit cause or successful filesystem synchronization.

Contract: unsuccessful shutdown acknowledgment never authorizes a signal. If the recorded process is still live and its recorded start time matches strictly, reuse the existing process waiter for the existing two-second AGENT_STOP_TIMEOUT. Accept only observed process absence, preserving a warning containing the original shutdown error and explicit synchronization uncertainty. A still-live, replaced, or unverifiable process retains the original refusal. Do not replay shutdown, manufacture an acknowledgment, alter paused-guest behavior, or reset/delete state on uncertainty.

The existing CLI updates stopped state only after manager stop succeeds. Its supported delete command always enables live-state resolution internally; a stale running row with absent process and unreachable agent resolves stopped before deletion. No delete implementation change is needed here.

Verification: tests/test_stop_ack_late_exit.py compiles the actual maintained stop method against controlled transport/process boundaries: late exit, still live, wrong identity, missing start time, PID rebound, already absent, acknowledged stop, and paused stop. A separate test compiles the actual existing waiter and observes a harmless pipe-held cat process: timeout while live, exit after pipe EOF, without signals or VM use. Retained pre-fix test fails the late-exit assertion. No runtime build, VM qualification, DCO assertion, or guest-exit-cause claim is included.

Publication follows the separately owned PR1328 source aff1caa0378fccaaa51659a5ad67aa98fd9fe96b. Resolver and guest signal-receipt changes remain unchanged. Only manager stop, waiter visibility, this note, and the regression are owned here.
