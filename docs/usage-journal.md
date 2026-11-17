# Usage journal

smolvm keeps a local record of what happens to machines on this host: one JSON line per lifecycle event, appended to

```
<data_local_dir>/smolvm/usage/events.jsonl      # Linux: ~/.local/share/smolvm/usage/
```

`SMOLVM_USAGE_DIR` moves it; an empty value disables it. The file rotates once past 8 MiB and one rotated file is kept.

## What is recorded

Events: `create`, `branch`, `start`, `resume`, `stop`, `pause`, `error`, `resize`, `delete`, `checkpoint`, `restore`. Every engine path that changes a machine record writes one: the `smolvm` and `smol` CLIs, the local HTTP API, and the embedded SDK runtime.

Each line carries the shape of the machine, not its identity:

| field | meaning |
|---|---|
| `install` | random id generated once per install |
| `machine`, `parent` | per-install hash of the machine name and its branch source |
| `depth` | branch hops from the root of the tree (branch events) |
| `branchable`, `cuda`, `gpu`, `network` | flags from the record |
| `image_host`, `image_pinned` | registry host of the image (`docker.io`, `ghcr.io`, `local`), and whether it is digest-pinned; never the repository or tag |
| `cpus`, `mem_mib`, `mounts`, `ports` | sizes and counts |
| `age_secs` | seconds since the record was created |
| `from`, `to` | record state before and after, for transitions |

Not recorded: machine names, commands, arguments, paths, image names, labels, environment, output, host names, user names.

## Reading it

```
smol usage summary          # machines, branches, tree depth, fan-out, lifetimes
smol usage show -n 20       # last 20 lines
smol usage export FILE      # the whole journal as JSON lines
smol usage status           # where it is, and whether recording and sharing are on
```

It is plain JSON lines; `jq` works on it directly.

## Turning it off

```
smol usage off                      # writes [usage] record = false to ~/.config/smolvm/config.toml
SMOLVM_USAGE=0 smolvm machine ...   # for one command
```

## Sharing

Nothing leaves the host unless sharing is turned on:

```
smol usage share on [--endpoint URL]
smol usage share now
smol usage share off
```

With sharing on, the `smol` CLI posts unsent events to the endpoint about once an hour on exit, with a three-second budget and no retries in that run. The default endpoint is `https://usage.smolmachines.com/v1/events`; `[usage] endpoint` in the settings file overrides it. A share offset marks what has been sent. The install id is the only identifier in a batch.
