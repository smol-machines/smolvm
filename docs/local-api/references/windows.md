# The local API on Windows

**Re-run on 2026-10-03 against smolvm v1.22.2** on Windows 11 Home build 10.0.26200 UBR 9457 x86_64 (Intel Core Ultra 9 185H,
31.6 GB), in an elevated session; the section "On v1.22.2" has what changed. The rest of this page
is the **2026-09-11 run against v1.14.6** on UBR 9445.

The whole lifecycle works, over **loopback TCP only**. Two v1.22.2 results differ from the v1.14.6
record below, both of them about a request stopped before it reaches a machine.

## On v1.22.2

- The lifecycle passed: create, a file PUT before start, start, `exec` with `exitCode` 0 and a
  failing one with `exitCode` 3 on HTTP 200, the file round trip, stop, delete, and
  `{"machines":[]}`. The file PUT before start survived the start again.
- **A bodiless POST to `start` returns 200**, from v1.21.0, where the section below records 415.
- **Error bodies are there.** `curl.exe` read the 422's text,
  `Failed to deserialize the JSON body into the target type: memory: unknown field ...`, and a
  missing machine's 404 as `{"error":"machine 'nope' not found","code":"NOT_FOUND"}`. Only the 404
  for a path without `/api/v1/` has no body. PowerShell 5.1's `Invoke-WebRequest` returned an
  empty string for all of them, which is what the earlier runs below recorded as empty bodies.
- `--listen unix://...` is refused: `parse listen address: invalid address ...: expected
  ADDR:PORT`.
- `serve openapi` wrote 174089 bytes, `info.version` still `0.5.2`.
- A `serve` started with `Start-Process` from a PowerShell process that then exited normally was
  still answering `/health` 12 s later.

## Starting the server

`machine start` on the CLI never returns to a caller that captures its output. The HTTP API is a
clean way to drive smolvm from PowerShell precisely because it avoids that, but the server itself
still has to be launched without capturing:

```powershell
Start-Process -FilePath $exe -ArgumentList @('serve','start','--listen','127.0.0.1:18899') `
  -RedirectStandardOutput serve.out -RedirectStandardError serve.err -WindowStyle Hidden -PassThru
```

## What was observed

On v1.14.6, against routes under `/api/v1/`:

```
openapi info.version : 0.5.2
health         : {"status":"ok","version":"1.14.6","machines":{"total":1,"running":0},"uptime_seconds":6}
POST machines  : {"name":"wapi","state":"created","cpus":2,"memoryMb":2048,...,"network":true,...}
POST start     : {"name":"wapi","state":"running","pid":21368,...,"rssMb":167,...}
POST exec      : {"exitCode":0,"stdout":"WIN_API_OK\nLinux x86_64\n","stderr":"",...}
PUT  files     : {"path":"/root/w.txt","size":10}
GET  files     : WINPAYLOAD
POST stop      : {"name":"wapi","state":"stopped",...}
DELETE machine : ok
GET  machines  : {"machines":[{"name":"wd",...}]}
http://127.0.0.1:18899/api/v1/machines/nope -> 404 body ''
```

`serve openapi -o spec.json` wrote 157345 bytes on v1.14.6, and 153291 on v1.14.2.

## Two ways a request fails before it reaches a machine

Both were found by getting them wrong. Neither produces a body you can read.

- **The routes are under `/api/v1/`.** A bare `POST /machines` returns **404** with an empty body,
  which reads exactly like a missing machine rather than a missing prefix. `serve openapi` is
  where the full route list comes from.
- **A bodiless POST needs an explicit content type.** `POST /api/v1/machines/{name}/start` with no
  body returns **415 Unsupported Media Type**. It succeeds with an empty JSON body and the header
  set:

  ```powershell
  Invoke-RestMethod -Method Post -Uri "$base/api/v1/machines/wapi/start" `
    -Body '{}' -ContentType 'application/json'
  ```

  The same applies to `stop`.

## Four Windows differences that change how you write a client

- **The Unix socket transport is not available.** `--listen unix://...` is refused with `expected
  ADDR:PORT`. Loopback is therefore the only boundary you have, and there is no
  authentication, so treat the port as equivalent to a shell on the host.
- **The create field is `network`, not `net`.** The same as everywhere, but it matters more here
  because of the next point.
- **PowerShell 5.1's `Invoke-WebRequest` drops error bodies.** The server sends
  `{"error":"...","code":"..."}` as on macOS and Linux, and `curl.exe` reads it; the earlier runs
  here recorded the bodies as empty for that reason.
- **`serve openapi` reports `info.version "0.5.2"`** while `/health` on the same server reports
  the binary's version, on v1.22.2 as on v1.14.6, and on macOS too.

## One result that differs from Linux, and does not clear it

**A file PUT before `start` survived the start on this host**, on v1.14.2 and again on v1.22.2. On Linux the same sequence lost the
file. That does not lift the ordering rule in `references/traps.md`: the rule costs nothing, the
loss is real on Linux, and the Windows result is one run. Upload after a successful `exec`.

## Everything else about Windows

State cannot be relocated and reached 30 GB in one session, `machine list` is not read-only, and
PowerShell renders the exe's stderr as error records on a fully successful run. Those are in the
`install` and `teardown` packets.
