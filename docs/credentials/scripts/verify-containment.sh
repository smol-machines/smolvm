#!/usr/bin/env bash
# Prove, on this host, that a credentialed machine never holds the value. Run it
# before any untrusted workload runs in the machine: check 2 hands the value to a
# grep inside the guest. Every check here is decided before anything leaves the
# host: no request this script makes carries the placeholder where it would be
# substituted, so the value is never sent anywhere. Seeing the value arrive at
# the API is your own first real call, which this script does not make.
#
# usage: verify-containment.sh --var <HOST_ENV_VAR> --host <api.example.com>
#                              [--name <n>] [--other-host <host>]
#   --other-host  a host no binding names, to show its TLS is passed through
#
# The value is never put on a command line: a command passed to machine exec is
# written to the machine's console log on the host. Both searches read it on
# standard input instead.

set -uo pipefail

VAR=""
HOST=""
NAME="smolskill-cred"
OTHER=""
while [ $# -gt 0 ]; do
    case "$1" in
        --var)        VAR="$2"; shift ;;
        --host)       HOST="$2"; shift ;;
        --name)       NAME="$2"; shift ;;
        --other-host) OTHER="$2"; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
    shift
done
if [ -z "$VAR" ] || [ -z "$HOST" ]; then
    printf 'usage: verify-containment.sh --var <HOST_ENV_VAR> --host <api.example.com> [--name <n>]\n' >&2
    exit 2
fi
SMOLVM="${SMOLVM:-$(command -v smolvm 2>/dev/null)}"
[ -n "$SMOLVM" ] || { printf 'smolvm not found; set SMOLVM to its path\n' >&2; exit 2; }
value="$(printenv "$VAR" 2>/dev/null)"
[ -n "$value" ] || { printf 'result=FAILED %s is not set here, so there is nothing to look for\n' "$VAR"; exit 2; }

fail=0
check() {
    if [ "$2" = "$3" ]; then printf '%s=ok (%s)\n' "$1" "$2"; else printf '%s=FAIL expected=%s actual=%s\n' "$1" "$3" "$2"; fail=1; fi
}
X() { "$SMOLVM" machine exec --name "$NAME" -- "$@" 2>/dev/null; }

# 1. The guest's variable is a placeholder.
seen="$(X sh -c "printenv $VAR")"
case "$seen" in SMOL_PLACEHOLDER_*) check guest_variable placeholder placeholder ;; *) check guest_variable other placeholder ;; esac
[ "$fail" -eq 0 ] || { printf 'result=FAILED the guest variable is not a placeholder, so nothing more was checked or sent\n'; exit 1; }

X sh -c 'command -v openssl >/dev/null && command -v curl >/dev/null || apk add -q openssl curl >/dev/null 2>&1; command -v openssl >/dev/null && command -v curl >/dev/null' >/dev/null \
    || { printf 'result=FAILED the guest has no openssl or curl and apk could not add them\n'; exit 2; }

# 2. The value is nowhere in the guest: every environment, and the writable trees.
# A dropped standard input would read as zero hits, so prove it arrives first.
echo_back="$(printf 'smolskill-stdin-probe\n' | "$SMOLVM" machine exec -i --name "$NAME" -- cat 2>/dev/null)"
[ "$echo_back" = smolskill-stdin-probe ] || { printf 'result=FAILED machine exec -i did not pass standard input through, so the guest search could not read the value\n'; exit 2; }
hits="$(printf '%s\n' "$value" | "$SMOLVM" machine exec -i --name "$NAME" -- sh -c 'grep -rlF -f /dev/stdin /proc/[0-9]*/environ /run /etc /root /tmp /var /home 2>/dev/null | grep -v "^/proc/$$/" | wc -l | tr -d " "' 2>/dev/null)"
check value_in_guest "${hits:-unknown}" 0

# 3. Nor in the machine's directory or smolvm's database on the host.
dir="$("$SMOLVM" machine data-dir --name "$NAME" 2>/dev/null)"
case "$(uname -s)" in
    Darwin) db="$HOME/Library/Application Support/smolvm" ;;
    *) db="${SMOLVM_DATA_DIR:+$SMOLVM_DATA_DIR/.local/share/smolvm}"
       db="${db:-${XDG_DATA_HOME:-$HOME/.local/share}/smolvm}" ;;
esac
# The *.raw disk images are the guest filesystem step 2 searched from inside, and
# grep took about 19 minutes over their 30 GiB of sparse space on macOS.
if [ -d "$dir" ] && [ -d "$db" ]; then
    rec="$( { printf '%s\n' "$value" | grep -rlF --exclude='*.raw' -f /dev/stdin "$dir" "$db" 2>/dev/null || true; } | wc -l | tr -d ' ')"
    check value_in_record "$rec" 0
else
    check value_in_record "not_searched (${dir:-no machine directory}, $db)" 0
fi

# 4. TLS to the bound host is terminated by the machine's own CA: the interceptor
#    is on the path. No request is sent.
issuer="$(X sh -c "echo | openssl s_client -connect $HOST:443 -servername $HOST 2>/dev/null | openssl x509 -noout -issuer")"
case "$issuer" in *"smolvm $NAME credential CA"*) check interception on on ;; *) check interception "off (${issuer:-no answer})" on ;; esac

# 5. A host no binding names keeps its real certificate.
if [ -n "$OTHER" ]; then
    other_issuer="$(X sh -c "echo | openssl s_client -connect $OTHER:443 -servername $OTHER 2>/dev/null | openssl x509 -noout -issuer")"
    case "$other_issuer" in *"credential CA"*) check passthrough intercepted real ;; "") check passthrough no_answer real ;; *) check passthrough real real ;; esac
fi

# 6. The guard: a placeholder in the query string is refused here with a 403 and
#    never forwarded, so nothing leaves the host.
refusal="$(X sh -c "curl -s -w ' [%{http_code}]' \"https://$HOST/?probe=\$$VAR\"")"
case "$refusal" in *"[403]"*) check query_refused 403 403 ;; *) check query_refused "${refusal:-no answer}" 403 ;; esac
printf 'refusal_text=%s\n' "${refusal% \[*}"

if [ "$fail" -eq 0 ]; then printf 'result=contained\n'; else printf 'result=FAILED\n'; exit 1; fi
