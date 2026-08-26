#!/bin/sh
# End-to-end tests for remote volumes (-v s3://bucket[/prefix]:/guest/path).
#
# Fully self-contained: runs a MinIO S3 server inside a smolvm machine and
# verifies every write OUT-OF-BAND from a separate machine via the raw S3 API,
# because reading a write back through the same mount would also pass if the
# data never left the guest.
#
# The mount is performed by the agent itself, so the images under test are
# plain `alpine:latest` and `nginx:alpine` with no tools installed: an image
# that has to `apk add` anything is a regression, not a fixture.
#
# Usage: ./tests/test_remote_volumes.sh [path-to-smolvm]
set -u
S=${1:-smolvm}
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "PASS: $1"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL: $1"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want '$3' got '$2')"; fi; }

CREDS="--env AWS_ACCESS_KEY_ID=smoltest --env AWS_SECRET_ACCESS_KEY=smoltest123 --env AWS_ENDPOINT_URL=http://100.96.0.1:9000"
# The verifier is a test client, not a product dependency: it reads the bucket
# over the S3 API from outside every mount under test.
RCLONE_REMOTE=':s3,provider=Minio,access_key_id=smoltest,secret_access_key=smoltest123,endpoint="http://100.96.0.1:9000"'
NAMES="rv-minio rv-ver rv-rw rv-ro rv-plain rv-badbucket rv-deadendpoint rv-sf rv-api rv-svc rv-x"
cleanup() { for n in $NAMES; do $S machine delete --name "$n" --force >/dev/null 2>&1; done; }
cleanup

# ---- rig: MinIO + out-of-band verifier ------------------------------------
$S machine create --name rv-minio --image minio/minio --net -p 9000:9000 \
  --env MINIO_ROOT_USER=smoltest --env MINIO_ROOT_PASSWORD=smoltest123 \
  -- minio server /data --address :9000 >/dev/null 2>&1
$S machine start --name rv-minio >/dev/null 2>&1
i=0; until curl -s -m 2 http://127.0.0.1:9000/minio/health/live >/dev/null 2>&1; do
  i=$((i+1)); [ $i -gt 30 ] && { echo "ABORT: minio never came up"; cleanup; exit 1; }; sleep 2
done
$S machine create --name rv-ver --image alpine:latest --net --net-backend virtio-net >/dev/null 2>&1
$S machine start --name rv-ver >/dev/null 2>&1
$S machine exec --name rv-ver -- sh -c "apk add -q rclone >/dev/null 2>&1; rclone mkdir '$RCLONE_REMOTE:rv-bucket' 2>/dev/null" >/dev/null 2>&1
# Read an object back OUT-OF-BAND, polling a few seconds: a write is uploaded
# when the guest closes the file, so a read issued immediately after the shell
# returns can still race the upload.
oob() {
  _v=""
  i=0; while [ $i -lt 20 ]; do
    _v=$($S machine exec --name rv-ver -- sh -c "rclone cat '$RCLONE_REMOTE:rv-bucket/$1' 2>/dev/null")
    [ -n "$_v" ] && break
    i=$((i+1)); sleep 1
  done
  echo "$_v"
}

# ---- 1. parse rejections happen at create, with hints ---------------------
OUT=$($S machine create --name rv-x --image alpine:latest --net -v "s3://b:relative" -- sleep infinity 2>&1)
echo "$OUT" | grep -q "must be absolute" && ok "relative guest path rejected" || bad "relative guest path rejected"
OUT=$($S machine create --name rv-x --image alpine:latest --net -v ':http,url="https://h":/mnt/x' -- sleep infinity 2>&1)
echo "$OUT" | grep -q "rclone" && ok "rclone remote rejected as unsupported" || bad "rclone remote rejected as unsupported"
echo "$OUT" | grep -q "s3://" && ok "rclone rejection names the S3 form" || bad "rclone rejection names the S3 form"
OUT=$($S machine create --name rv-x --image alpine:latest -v "s3://b:/mnt/x" -- sleep infinity 2>&1)
echo "$OUT" | grep -q "network" && ok "remote volume without network rejected" || bad "remote volume without network rejected"

# ---- 2. a stock image with NO tools mounts and reads -----------------------
# The headline of the native mount: nothing is installed in the image, and the
# machine is never given an init command.
$S machine create --name rv-plain --image alpine:latest --net --net-backend virtio-net $CREDS \
  -v "s3://rv-bucket:/mnt/q" -- sleep infinity >/dev/null 2>&1
$S machine start --name rv-plain >/dev/null 2>&1
check "stock image mounts with no tools installed" \
  "$($S machine exec --name rv-plain -- sh -c 'grep -c " /mnt/q " /proc/mounts' 2>/dev/null | tr -d '\r\n')" "1"
check "the image really has no rclone" \
  "$($S machine exec --name rv-plain -- sh -c 'command -v rclone >/dev/null && echo yes || echo no' 2>/dev/null | tr -d '\r\n')" "no"
check "the image really has no fusermount3" \
  "$($S machine exec --name rv-plain -- sh -c 'command -v fusermount3 >/dev/null && echo yes || echo no' 2>/dev/null | tr -d '\r\n')" "no"

# ---- 3. an unusable bucket FAILS the start ---------------------------------
# mount(2) on /dev/fuse succeeds without ever contacting S3, so a mount alone
# proves nothing; without a reachability check these would start happily and
# serve an empty directory.
$S machine create --name rv-badbucket --image alpine:latest --net --net-backend virtio-net $CREDS \
  -v "s3://nosuchbucket:/mnt/q" -- sleep infinity >/dev/null 2>&1
OUT=$($S machine start --name rv-badbucket 2>&1)
# Assert the DISCRIMINATING part of the message. "not reachable" alone is also
# what a transport error produces, so grepping only for that would pass when the
# MinIO rig itself is down -- reporting success for the wrong reason while every
# positive case fails.
echo "$OUT" | grep -q "NoSuchBucket" && ok "missing bucket fails the start" || bad "missing bucket fails the start ($OUT)"
echo "$OUT" | grep -qi "nosuchbucket:" && ok "the failure names the bucket" || bad "the failure names the bucket"

$S machine create --name rv-deadendpoint --image alpine:latest --net --net-backend virtio-net \
  --env AWS_ACCESS_KEY_ID=smoltest --env AWS_SECRET_ACCESS_KEY=smoltest123 \
  --env AWS_ENDPOINT_URL=http://127.0.0.1:9999 \
  -v "s3://rv-bucket:/mnt/q" -- sleep infinity >/dev/null 2>&1
OUT=$($S machine start --name rv-deadendpoint 2>&1)
# Here a transport failure IS the expected cause, so match it specifically
# rather than the shared "not reachable" prefix.
echo "$OUT" | grep -q "transport:" && ok "dead endpoint fails the start" || bad "dead endpoint fails the start ($OUT)"

# ---- 4. rw round trip, out-of-band verified -------------------------------
$S machine create --name rv-rw --image alpine:latest --net --net-backend virtio-net $CREDS \
  -v "s3://rv-bucket:/mnt/rw" -- sleep infinity >/dev/null 2>&1
$S machine start --name rv-rw >/dev/null 2>&1
$S machine exec --name rv-rw -- sh -c 'echo rt-1 > /mnt/rw/rt.txt' >/dev/null 2>&1
check "rw write visible out-of-band" "$(oob rt.txt)" "rt-1"

# A directory tree has to survive the round trip: S3 has no directories, so
# these are synthesised from key prefixes.
$S machine exec --name rv-rw -- sh -c 'mkdir -p /mnt/rw/d/e && echo deep > /mnt/rw/d/e/f.txt' >/dev/null 2>&1
check "nested write visible out-of-band" "$(oob d/e/f.txt)" "deep"
check "nested path lists through the mount" \
  "$($S machine exec --name rv-rw -- sh -c 'ls /mnt/rw/d/e' 2>/dev/null | tr -d '\r\n')" "f.txt"

# An object written from outside must appear through the mount.
$S machine exec --name rv-ver -- sh -c "echo outside | rclone rcat '$RCLONE_REMOTE:rv-bucket/ext.txt' 2>/dev/null" >/dev/null 2>&1
check "externally written object is visible" \
  "$($S machine exec --name rv-rw -- sh -c 'cat /mnt/rw/ext.txt' 2>/dev/null | tr -d '\r\n')" "outside"

$S machine exec --name rv-rw -- sh -c 'rm /mnt/rw/rt.txt' >/dev/null 2>&1
check "unlink removes the object" "$(oob rt.txt)" ""

# Rewriting a file with fewer bytes must not leave the old tail behind. This is
# checked out-of-band on purpose: the mount can report the correct short length
# from its own staging state while the stored object is still the long one.
$S machine exec --name rv-rw -- sh -c 'printf AAAAAAAAAA > /mnt/rw/shrink.txt' >/dev/null 2>&1
$S machine exec --name rv-rw -- sh -c 'printf BB > /mnt/rw/shrink.txt' >/dev/null 2>&1
check "rewriting shorter leaves no old tail" "$(oob shrink.txt)" "BB"

# Truncation has to reach the bucket too: unless atomic_o_trunc is negotiated
# the kernel sends O_TRUNC as a size change, which is easy to accept and drop.
$S machine exec --name rv-rw -- sh -c 'printf 0123456789 > /mnt/rw/trunc.txt' >/dev/null 2>&1
$S machine exec --name rv-rw -- sh -c ': > /mnt/rw/trunc.txt' >/dev/null 2>&1
check "truncate to zero is stored" \
  "$($S machine exec --name rv-rw -- sh -c 'wc -c < /mnt/rw/trunc.txt' 2>/dev/null | tr -d ' \r\n')" "0"

# rename(2) keeps the inode, so the renamed file must stay readable through the
# live mount -- not only after a remount.
$S machine exec --name rv-rw -- sh -c 'echo moved > /mnt/rw/from.txt; mv /mnt/rw/from.txt /mnt/rw/to.txt' >/dev/null 2>&1
check "renamed file is readable through the live mount" \
  "$($S machine exec --name rv-rw -- sh -c 'cat /mnt/rw/to.txt' 2>/dev/null | tr -d '\r\n')" "moved"
check "renamed file is in the bucket" "$(oob to.txt)" "moved"

# ---- 5. restart: mount returns, content intact ----------------------------
$S machine exec --name rv-rw -- sh -c 'echo keep > /mnt/rw/keep.txt' >/dev/null 2>&1
$S machine stop --name rv-rw >/dev/null 2>&1
$S machine start --name rv-rw >/dev/null 2>&1
GOT=$($S machine exec --name rv-rw -- sh -c 'cat /mnt/rw/keep.txt 2>/dev/null' 2>/dev/null | tr -d '\r\n')
check "mount returns after restart with content" "$GOT" "keep"

# ---- 6. large-file integrity ----------------------------------------------
H1=$($S machine exec --name rv-rw -- sh -c 'dd if=/dev/urandom of=/tmp/b bs=1M count=8 2>/dev/null; sha256sum /tmp/b | cut -d" " -f1; cp /tmp/b /mnt/rw/b.bin' 2>/dev/null | head -1 | tr -d '\r\n')
H2=$($S machine exec --name rv-ver -- sh -c "rclone cat '$RCLONE_REMOTE:rv-bucket/b.bin' 2>/dev/null | sha256sum | cut -d' ' -f1" 2>/dev/null | tail -1 | tr -d '\r\n')
# Guard the comparison: two empty hashes would otherwise "match" and pass.
if [ ${#H1} -eq 64 ]; then
  check "8MB sha256 integrity out-of-band" "$H2" "$H1"
else
  bad "8MB sha256 integrity out-of-band (no hash from the guest)"
fi

# ---- 7. read-only enforcement ---------------------------------------------
$S machine create --name rv-ro --image alpine:latest --net --net-backend virtio-net $CREDS \
  -v "s3://rv-bucket:/mnt/q:ro" -- sleep infinity >/dev/null 2>&1
$S machine start --name rv-ro >/dev/null 2>&1
check "ro mount is readable" \
  "$($S machine exec --name rv-ro -- sh -c 'cat /mnt/q/keep.txt' 2>/dev/null | tr -d '\r\n')" "keep"
# Keep stderr: `machine exec` forwards the guest's stderr to the host's stderr,
# so discarding it here would throw away the very message being asserted.
OUT=$($S machine exec --name rv-ro -- sh -c 'echo x > /mnt/q/no.txt' 2>&1)
echo "$OUT" | grep -qi "read-only" && ok "ro mount rejects writes" || bad "ro mount rejects writes ($OUT)"
check "the rejected write did not reach the bucket" "$(oob no.txt)" ""

# ---- 8. fork of a remote-volume golden is refused cleanly -----------------
OUT=$($S machine fork --golden rv-ro --name rv-clone 2>&1)
echo "$OUT" | grep -q "cannot be forked yet" && ok "fork refused for remote-volume golden" || bad "fork refused for remote-volume golden"

# ---- 9. Smolfile surface: volumes = ["s3://..."] flows through create -----
TMPD=$(mktemp -d)
cat > "$TMPD/Smolfile" <<'SMOLEOF'
image = "alpine:latest"
net = true
cmd = ["sleep", "infinity"]
env = [
  "AWS_ACCESS_KEY_ID=smoltest",
  "AWS_SECRET_ACCESS_KEY=smoltest123",
  "AWS_ENDPOINT_URL=http://100.96.0.1:9000",
]
volumes = ["s3://rv-bucket:/mnt/sf"]
SMOLEOF
$S machine create --name rv-sf --smolfile "$TMPD/Smolfile" --net-backend virtio-net >/dev/null 2>&1 \
  && $S machine start --name rv-sf >/dev/null 2>&1 \
  && ok "smolfile machine with remote volume starts" || bad "smolfile machine with remote volume starts"
$S machine exec --name rv-sf -- sh -c 'echo sf-1 > /mnt/sf/sf.txt' >/dev/null 2>&1
check "smolfile write visible out-of-band" "$(oob sf.txt)" "sf-1"
rm -rf "$TMPD"

# ---- 10. serve API surface: structured MountSpec with a remote source ------
# Needs its own serve (the guest-rollout ingress port is exclusive) with the
# egress floor lowered so the guest may dial the host-local MinIO; skipped if
# a serve is already running.
if pgrep -f "smolvm.* serve start" >/dev/null 2>&1; then
  echo "SKIP: serve API cases (a serve is already running)"
else
  RVSOCK=$(mktemp -u /tmp/rv-serve.XXXXXX.sock)
  SMOLVM_EGRESS_FLOOR=metadata "$S" serve start --listen "unix://$RVSOCK" >/dev/null 2>&1 &
  SERVE_PID=$!
  i=0; until [ -S "$RVSOCK" ]; do i=$((i+1)); [ $i -gt 20 ] && break; sleep 1; done
  api() { curl -s -m 300 --unix-socket "$RVSOCK" "$@"; }
  BADJSON=$(mktemp)
  CODE=$(api -o /dev/null -w '%{http_code}' -X POST http://localhost/api/v1/machines \
    -H 'Content-Type: application/json' -d '{
    "name": "rv-api", "image": "alpine:latest",
    "network": true, "network_backend": "virtio-net",
    "entrypoint": ["sleep"], "cmd": ["infinity"],
    "env": [
      {"name": "AWS_ACCESS_KEY_ID", "value": "smoltest"},
      {"name": "AWS_SECRET_ACCESS_KEY", "value": "smoltest123"},
      {"name": "AWS_ENDPOINT_URL", "value": "http://100.96.0.1:9000"}
    ],
    "mounts": [{"source": "s3://rv-bucket", "target": "/mnt/api"}]}')
  check "api create accepts remote mount" "$CODE" "200"
  CODE=$(api -o /dev/null -w '%{http_code}' -X POST http://localhost/api/v1/machines/rv-api/start)
  check "api start mounts the volume" "$CODE" "200"
  api -X POST http://localhost/api/v1/machines/rv-api/exec -H 'Content-Type: application/json' \
    -d '{"command":["sh","-c","echo api-1 > /mnt/api/api.txt"]}' >/dev/null 2>&1
  check "api-machine write visible out-of-band" "$(oob api.txt)" "api-1"
  CODE=$(api -o "$BADJSON" -w '%{http_code}' -X POST http://localhost/api/v1/machines \
    -H 'Content-Type: application/json' -d '{
    "name": "rv-api-bad", "image": "alpine:latest", "network": true,
    "mounts": [{"source": ":http,url=\"https://h\"", "target": "/mnt/x"}]}')
  check "api rejects an rclone remote (400)" "$CODE" "400"
  grep -q "rclone" "$BADJSON" 2>/dev/null && ok "api 400 says rclone is unsupported" || bad "api 400 says rclone is unsupported"
  rm -f "$BADJSON"
  api -X DELETE "http://localhost/api/v1/machines/rv-api?force=true" >/dev/null 2>&1
  kill "$SERVE_PID" 2>/dev/null
  rm -f "$RVSOCK"
fi

# ---- 11. ephemeral `machine run` mounts too --------------------------------
# `machine run` never creates the container with `crun create` + `crun start`,
# so it has no window in which to mount; it must establish the container the
# two-step way when a remote volume is present rather than silently skip it.
GOT=$($S machine run --image alpine:latest --net --net-backend virtio-net $CREDS \
  -v "s3://rv-bucket:/mnt/run" -- cat /mnt/run/keep.txt 2>/dev/null | tr -d '\r\n')
check "ephemeral run mounts the volume" "$GOT" "keep"
$S machine run --image alpine:latest --net --net-backend virtio-net $CREDS \
  -v "s3://rv-bucket:/mnt/run" -- sh -c 'echo run-1 > /mnt/run/run.txt' >/dev/null 2>&1
check "ephemeral run write visible out-of-band" "$(oob run.txt)" "run-1"

# A run whose bucket is unusable must fail instead of running the command
# against an empty directory.
OUT=$($S machine run --image alpine:latest --net --net-backend virtio-net $CREDS \
  -v "s3://nosuchbucket:/mnt/run" -- echo SHOULD-NOT-RUN 2>&1)
echo "$OUT" | grep -q "NoSuchBucket" && ok "ephemeral run fails on an unusable bucket" || bad "ephemeral run fails on an unusable bucket"
echo "$OUT" | grep -q "SHOULD-NOT-RUN" && bad "the command must not run without its volume" || ok "the command does not run without its volume"

# ---- 12. service image keeps its own entrypoint AND still mounts -----------
# No `--` command: the image's ENTRYPOINT/CMD is resolved inside the guest and
# must still run. Mounting happens between container create and start, so the
# entrypoint is never rewritten to carry a mount command.
$S machine create --name rv-svc --image nginx:alpine --net --net-backend virtio-net $CREDS \
  -v "s3://rv-bucket:/mnt/svc" >/dev/null 2>&1
$S machine start --name rv-svc >/dev/null 2>&1
GOT=
n=0; while [ $n -lt 15 ]; do
  [ "$($S machine exec --name rv-svc -- sh -c 'cat /proc/1/comm' 2>/dev/null | tr -d '\r\n')" = nginx ] && { GOT=up; break; }
  n=$((n+1)); sleep 1
done
check "service entrypoint runs under a remote volume" "$GOT" "up"
check "service-image mount is live at first instruction" \
  "$($S machine exec --name rv-svc -- sh -c 'cat /mnt/svc/keep.txt' 2>/dev/null | tr -d '\r\n')" "keep"
$S machine exec --name rv-svc -- sh -c 'echo svc-1 > /mnt/svc/svc.txt' >/dev/null 2>&1
check "service-image mount write visible out-of-band" "$(oob svc.txt)" "svc-1"

cleanup
echo ""
echo "remote volumes e2e: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ]
