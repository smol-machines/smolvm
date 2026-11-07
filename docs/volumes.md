# Volumes

Besides host directories (`-v HOST:GUEST[:ro]`), a volume can be an S3 bucket,
a staged copy of a host directory, or a directory on the machine's own disk.

## Disk volumes

`-v GUEST` with no host side, as in `-v /var/lib/docker`, is a directory on the
machine's storage disk instead of its overlay root. It persists across stop and
start. A new one takes the owner and mode the image has at that path, or the
owner of the nearest directory above it; a new top-level path is `root:root`
`0755`.

To choose the owner and mode yourself, add them after the path, as
`machine cp --uid --gid --mode` does for a file:

```sh
smolvm machine create --name app --image alpine -v /data:uid=1000,gid=1000,mode=750
```

Any of `uid`, `gid` and `mode` (octal) can be given, in any order. The agent
applies them to the volume's directory, not its contents, when the volume is
created and again whenever they change, so a `chown` or `chmod` inside the
machine survives a restart, as it does for a volume without them. The ones
left out come from the image as above. `machine update --name app -v
/data:uid=1001` replaces them on a stopped machine and applies them on its next
start, and `-v /data` alone stops setting them.

These options only apply to disk volumes. On a host directory
(`-v ./src:/data:uid=1000`) they are refused: its owner is whatever the host's
file server presents.

## S3 buckets

`-v s3://BUCKET[/PREFIX]:/PATH[:ro]` mounts an S3-compatible bucket in the
machine's container. The agent mounts it itself; the image needs no FUSE
tools. The machine needs `--net`.

Credentials and endpoint come from the machine's `-e`, not the host
environment: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`,
`AWS_REGION` (default `us-east-1`) and `AWS_ENDPOINT_URL` for R2, MinIO and
others. Requests are path-style. Without a key pair the bucket is read
anonymously.

```sh
smolvm machine run --image alpine --net \
  -e AWS_ACCESS_KEY_ID=… -e AWS_SECRET_ACCESS_KEY=… \
  -e AWS_ENDPOINT_URL=https://<account>.r2.cloudflarestorage.com \
  -v s3://my-bucket/datasets:/data:ro -- ls /data
```

A missing bucket or bad credentials fail the start. POSIX gaps and caching are
in [limitations.md](limitations.md#s3-mounts).

## Staged mounts

`-v HOST:GUEST:staged` copies `HOST` to the machine's disk on first boot, and
the workload runs on that copy without a virtiofs round trip per file.
`smolvm machine sync`, `POST /api/v1/machines/{name}/sync`, a graceful stop and
the end of `machine run` write it back.

```sh
smolvm machine create --name dev --image alpine -v ./repo:/work:staged
smolvm machine sync --name dev
```

Sync mirrors the copy onto the host: host files missing from the copy are
deleted, and host edits made after first boot are overwritten. Edit the source
only through the machine. A branch's staged copies do not sync back.
