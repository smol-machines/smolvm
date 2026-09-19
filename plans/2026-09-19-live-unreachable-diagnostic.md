# Live but unresponsive VM diagnostics

Decision: Sean’s runtime reliability task, delegated by Root to Pasteur on 2026-09-19, authorizes this diagnostic correction. Adopt the existing process-identity lifecycle contract used by plans/2026-09-19-stop-ack-late-exit.md: failure to contact the agent is not proof that the recorded process stopped.

The hq20 progress probe reported “not running” and advised starting the machine while PID 62942 with its recorded birth remained live. Its heavy job subsequently completed successfully in 774 seconds without recovery or restart. The cause of temporary unresponsiveness is not established.

After an unsuccessful connection probe, preserve frozen guidance and distinguish a recorded live process using the existing PID/start-time liveness method. Report the agent as unresponsive without recommending start. Retain the supported start hint for a stopped process and propagate database failures rather than disguising them as missing machines. No probe timeout, signal, automatic recovery, process-state policy, or VM action changes.

Verification: tests/test_live_unreachable_diagnostic.py compiles and executes the actual CLI function with controlled manager/database boundaries. The retained pre-fix run fails on the live process receiving stopped guidance. Controls cover live named/default machines, stopped/frozen machines, missing records, database failure and successful connection. This is source-level diagnostic coverage, not a runtime qualification or explanation of guest unresponsiveness.

Adjacent best-effort reconciliation now warns with machine identity for config-load failure, missing records and persistence failure; success is logged only after the actual Option<Result<()>> update succeeds. Existing stopped/dead/frozen no-op behavior remains unchanged. A separate extracted-function harness covers all eight logging branches with compiler warnings denied. No full runtime build is claimed.

Review correction: the initial logging draft used a Result-only stub. Inspection of src/config.rs:340 established the real Option<Result<()>> return type; both implementation and harness were corrected before publication, including a missing-update warning control. Root independently reviewed this final signature and reran both harnesses successfully. These extracted-method tests do not substitute for a full module build; upstream CI remains required.
