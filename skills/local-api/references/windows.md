# The local API on Windows

**Re-run on 2026-09-11 against smolvm v1.14.6** on Windows 11 Home build 10.0.26200.0 UBR 9445
x86_64 (Intel Core Ultra 9 185H, 31.6 GB), in an elevated session.

The whole lifecycle works, over **loopback TCP only**. The re-run also corrected two things this
page had wrong, both of which stop a request before it reaches a machine.

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

- **The Unix socket transport is not applicable.** The default listen address on Unix is
  `unix://$XDG_RUNTIME_DIR/smolvm.sock`; this run used loopback TCP only and no `--listen unix://`
  form was attempted. Loopback is therefore the only boundary you have, and there is no
  authentication, so treat the port as equivalent to a shell on the host.
- **The create field is `network`, not `net`.** The same as everywhere, but it matters more here
  because of the next point.
- **400 and 404 return empty bodies**, still true on v1.14.6. A wrong field name gets no
  diagnostic at all. On macOS and Linux the same requests come back with
  `{"error":"...","code":"..."}`, so a client that reads the error text works there and goes
  silent here. Export the spec and read `components.schemas.CreateMachineRequest` before writing a
  body.
- **`serve openapi` reports `info.version "0.5.2"`** while `/health` on the same server reports
  `1.14.6`. The mismatch survived the version bump. Also true on macOS, so it is not a Windows
  quirk, but it was found here.

## One result that differs from Linux, and does not clear it

**A file PUT before `start` survived the start on this host**, on the v1.14.2 run; the v1.14.6
run uploaded after `exec` and did not test the ordering again. On Linux the same sequence lost the
file. That does not lift the ordering rule in `references/traps.md`: the rule costs nothing, the
loss is real on Linux, and the Windows result is one run. Upload after a successful `exec`.

## Everything else about Windows

State cannot be relocated and reached 30 GB in one session, `machine list` is not read-only, and
PowerShell renders the exe's stderr as error records on a fully successful run. Those are in the
`install` and `teardown` packets.
