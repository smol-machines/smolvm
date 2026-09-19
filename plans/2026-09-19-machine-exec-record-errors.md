# Fail machine exec on database errors

Intent authorized by Root's bounded source correction request during CI process-lifecycle RCA; implemented by Dewey. This adopts the documented image-based versus bare-machine execution contract in AGENTS.md (Persistence Model and Important Behaviors), without changing that contract.

`ExecCmd::run` uses the persisted image/workdir/user to choose and configure the execution target. A database open or record-read failure must propagate as an error; silently converting it to an absent record can select bare-VM execution and discard configured defaults. Replace only the two error-discarding conversions with normal Result propagation. A successful image-less record and the existing successful absent-record behavior remain unchanged. Explicit bare-VM commands and all other CLI paths remain untouched.

Causal verification compiles the exact owning record-lookup expression from machine.rs with five controlled database outcomes under rustc -Dwarnings. Original open/get failures incorrectly produce Ok(None); candidate preserves their distinct errors. Image-present, image-none and successful absent-record controls preserve existing semantics. This does not compile or run the entire CLI, boot a VM, or establish that this fallback caused the separate observed Linux zombie. Existing database open/get methods already return the owning smolvm Result, so the implementation uses their ordinary error propagation.

Run locally: `python3 -B -Werror -m unittest discover -s tests -p test_machine_exec_record_errors.py`. Rustc must already be installed; the test builds only a temporary standalone harness with the actual production lookup expression. No dependency installation, framework, runtime artifact update or production rollout.

Actual fleet evidence separately showed an unreaped zombie in old44b generation29, while Root's same-runtime sibling had /usr/bin/sleep as workload PID1. Local Pasteur owns whole-listener-tree subreaping. This source correction is independent; do not conflate it with that lifecycle cause.
