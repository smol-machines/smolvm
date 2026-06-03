#!/usr/bin/env bash
#
# Static guardrails for the host-side secret store.
#
# The whole point of the secret store is that secret *plaintext* is resolved
# on the host at exec time and never persists anywhere a guest, a record, or
# the database can see it. Only opaque *references* (which store/env/file a
# value comes from) are persisted. These greps fail CI the moment a change
# breaks one of those invariants, so a reviewer doesn't have to spot it by eye.
#
# The checks are deliberately conservative: they match on patterns that are
# never legitimate, so a green run means "no known-bad pattern present", not
# "provably correct".

set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
note() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=1; }
ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; }

echo "secrets guardrails:"

# 1. SecretRef must reject unknown fields, so a Smolfile/API typo
#    (`from_stor`) is a hard error instead of a silently-ignored empty ref.
if grep -q 'deny_unknown_fields' crates/smolvm-protocol/src/secrets.rs; then
  ok "SecretRef denies unknown fields"
else
  note "SecretRef is missing #[serde(deny_unknown_fields)] in crates/smolvm-protocol/src/secrets.rs"
fi

# 2. resolve_secret_ref must hand back a Zeroizing buffer so resolved plaintext
#    is scrubbed from memory on drop rather than lingering on the heap.
if grep -A6 'pub fn resolve_secret_ref(' src/secrets.rs | grep -q 'Zeroizing<String>'; then
  ok "resolve_secret_ref returns a Zeroizing buffer"
else
  note "resolve_secret_ref no longer returns Zeroizing<String> — plaintext would not be scrubbed"
fi

# 3. The protocol SecretRef must carry only references, never an inline value.
#    A `value`/`plaintext`/`secret` field would let plaintext ride along into
#    every record and DB row that persists a ref.
if grep -nE '^\s*pub (value|plaintext|secret)\b' crates/smolvm-protocol/src/secrets.rs; then
  note "SecretRef gained an inline plaintext field — refs must stay opaque"
else
  ok "SecretRef carries references only (no inline plaintext field)"
fi

# 4. Resolved plaintext must never be assigned back onto a persisted record's
#    env. Persisted `*.env =` assignments may only come from plain sources
#    (parse_env_list, the request, an override) — never from a resolver.
#    NOTE: this catches the DIRECT case only; multi-hop laundering (resolver ->
#    local -> defaults.env -> persist) is NOT visible to grep and still needs
#    review — the durable fix is a non-Serialize `Secret<String>` newtype.
#    (Earlier this used a literal `**` pathspec + `\s`, which git grep silently
#    matches against nothing, so the check never ran. Use real dir pathspecs and
#    POSIX-ERE ` *`, and scan the pack crate too.)
if git grep -nE '\.env *=' -- src crates \
     | grep -E 'resolve_refs_to_env|record_env_with_secrets|resolve_secret_ref|resolve_secret_refs_for_env'; then
  note "a persisted .env is assigned from a secret resolver — plaintext would reach the DB"
else
  ok "no persisted .env directly assigned from a secret resolver"
fi

# 5. A .smolmachine is a portable, untrusted artifact: its packed secret refs
#    must resolve under the Untrusted scope (from_store only) so a downloaded
#    pack cannot read the running host's env/files via from_env/from_file.
if git grep -nE 'manifest\.secret_refs' -- src/cli/pack_run.rs \
     | grep -qE 'RecordReplay|TrustedLocal'; then
  note "pack_run resolves manifest secret refs under a trusting scope — host env/file exfil risk"
else
  ok "packed secret refs resolve under Untrusted scope"
fi

if [ "$fail" -ne 0 ]; then
  echo "secrets guardrails FAILED" >&2
  exit 1
fi
echo "secrets guardrails passed"
