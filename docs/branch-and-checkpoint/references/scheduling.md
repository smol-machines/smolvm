# Scheduling checkpoints

smolvm has no checkpoint scheduler and no age or count retention. Something outside it has to run
the capture on a timer and delete what is no longer wanted. `scripts/checkpoint.sh` is that one
capture, and this page puts it under a system timer.

## Contents

- The rules a schedule has to follow
- Choosing the interval
- Choosing `--keep` and `--history` together
- cron
- systemd timer
- launchd
- Taking a copy off the host
- What was measured

## The rules a schedule has to follow

These are the engine's own rules for periodic capture, from [incremental checkpoints](../../incremental-checkpoints.md),
and what `checkpoint.sh` does about each.

| rule | what the script does |
|---|---|
| the same store and a **unique output** each time | names each capture `<machine>-<label>-<UTC time>.smolcheckpoint`; an output is never overwritten |
| **one capture at a time per source** | takes a lock beside the store; a run that finds a live capture exits 3 with `result=skipped` |
| the interval comes from **complete capture time**, not source pause time | prints `capture_s=`; `schedule.sh` warns when a capture took as long as the interval |
| keep the previous checkpoint **until the new one is published** | reads `checkpoint-log` back and deletes nothing unless the new capture lists as `(this checkpoint)` |
| delete expired directories, **then** `checkpoint-prune` | removes whole directories beyond `--keep`, then prunes the store |
| capture and prune failures are **logged and alerted** by the scheduler | exits non-zero with `result=FAILED` and the reason; wire the exit status to your alerting |

## Choosing the interval

Run a few captures by hand first and read `capture_s`, or run
`scripts/schedule.sh --every <s> --times 3` and read `longest_capture_s`. On v1.18.2 a 1 GiB alpine
machine took 1 to 5 s per capture on both hosts while the source paused for 0.027 to 0.163 s. The
pause is what the workload feels; the capture time is what the schedule has to fit. A capture that
takes longer than the interval does not run twice at once, because of the lock, but it does skip
the next slot.

## Choosing `--keep` and `--history` together

A stored checkpoint **retains** earlier generations so any of them can be restored from it alone,
32 by default. So `--keep K` deleting old directories does not free their data while a kept
checkpoint still retains it. Measured on v1.18.2 with `--keep 2 --history 2`, four captures: the
store went 59, 76, 95, 114 MB, still growing, because each kept checkpoint retained two earlier
generations. The generations you can restore are those within `--history` of a kept checkpoint.

A rule that works: decide how far back a rollback must reach, in captures, and set `--history` to
that and `--keep` to 1 or 2. Keep more directories only when you want several independent entry
points, for example one per day.

## cron

```cron
# every 10 minutes; the lock makes an overlapping run skip rather than pile up
*/10 * * * * cd /srv/ckpt && /path/to/scripts/checkpoint.sh --name smolskill-src --store ./store --keep 2 --history 12 >> capture.log 2>&1 || logger -t smolvm-checkpoint "capture failed, see /srv/ckpt/capture.log"
```

cron runs with a minimal environment. `smolvm` must be on its `PATH` or named by `SMOLVM=`, and
`HOME` must be the one the machine was created under, since smolvm's state is found through it.

## systemd timer

```ini
# ~/.config/systemd/user/smolvm-checkpoint.service
[Service]
Type=oneshot
WorkingDirectory=/srv/ckpt
Environment=SMOLVM=%h/.local/bin/smolvm
ExecStart=/path/to/scripts/checkpoint.sh --name smolskill-src --store ./store --keep 2 --history 12

# ~/.config/systemd/user/smolvm-checkpoint.timer
[Timer]
OnActiveSec=10min
OnUnitInactiveSec=10min
[Install]
WantedBy=timers.target
```

```bash
systemctl --user enable --now smolvm-checkpoint.timer
journalctl --user -u smolvm-checkpoint.service     # every capture's key=value lines
```

`OnUnitInactiveSec` measures from the end of the previous run, so a slow capture moves the next one
back instead of overlapping it. `OnActiveSec=` starts the first run, which `OnUnitInactiveSec=`
alone never would: on Ubuntu 24.04 on 2026-10-03, with a stand-in service, `systemctl --user
list-timers` after `enable --now` showed the next run 9 minutes out with `OnActiveSec=` and none
without it. `OnFailure=` on the service is where an alert goes.

## launchd

```xml
<!-- ~/Library/LaunchAgents/com.example.smolvm-checkpoint.plist -->
<plist version="1.0"><dict>
  <key>Label</key><string>com.example.smolvm-checkpoint</string>
  <key>ProgramArguments</key><array>
    <string>/path/to/scripts/checkpoint.sh</string>
    <string>--name</string><string>smolskill-src</string>
    <string>--store</string><string>/Users/you/ckpt/store</string>
    <string>--keep</string><string>2</string>
    <string>--history</string><string>12</string>
  </array>
  <key>EnvironmentVariables</key><dict>
    <key>SMOLVM</key><string>/Users/you/.local/bin/smolvm</string>
  </dict>
  <key>StartInterval</key><integer>600</integer>
  <key>StandardOutPath</key><string>/Users/you/ckpt/capture.log</string>
  <key>StandardErrorPath</key><string>/Users/you/ckpt/capture.log</string>
</dict></plist>
```

```bash
launchctl load ~/Library/LaunchAgents/com.example.smolvm-checkpoint.plist
```

On macOS the machine must have been started `--branchable`, or every scheduled capture fails with
`deferred durable save requires file-backed guest RAM` on v1.22.2, `guest RAM has no file-backed
regions` before v1.20.0; `checkpoint.sh` names the cause when it sees either text.

## Taking a copy off the host

A store protects against a bad change, not against losing the host. Export the newest checkpoint as
one file, which carries its retained history, and copy that elsewhere:

```bash
smolvm machine checkpoint --export-from ./smolskill-src-ckpt-<time>.smolcheckpoint --output ./offhost.smolcheckpoint
```

On v1.18.2 that wrote `Exported checkpoint to ... (94 MiB, carrying 2 earlier generation(s))`, and
`--at '~1'` restored from the exported file. Through v1.22.2 it restores only on a host with the
same platform, CPU and devices. From v1.23.0 a checkpoint from an arm64 Mac also restores on arm64
Linux; [Moving a running machine from a Mac to Linux](../../mac-to-linux.md) has the requirements,
and `SKILL.md` the run.

## What was measured

On v1.18.2, 2026-09-24, on macOS arm64 and Lima aarch64: `schedule.sh` with four captures ten
seconds apart, `--keep 2 --history 2`, both hosts `captures_ok=4`; the overlap refusal; the
restores. **The cron, systemd and launchd forms above were not run with `checkpoint.sh`**; they are
the standard forms around a command that was. Only the systemd timer's first trigger was checked,
on Ubuntu 24.04 on 2026-10-03 with a stand-in service.
