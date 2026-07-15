# smolvm MCP server

Give any MCP-compatible AI agent **its own isolated computer**: a real
per-workload microVM it can run code in, install packages, and read/write files
— booting in well under a second, on macOS, Linux, or Windows.

This is a [Model Context Protocol](https://modelcontextprotocol.io) server that
exposes [smolvm](https://github.com/smol-machines/smolvm) sandboxes as tools. It
shells out to the `smolvm` CLI, so it works with **any** smolvm install
(Homebrew / apt / dnf / pacman / Nix / the install script) — no daemon, no
container engine, no extra SDK.

Unlike cloud sandbox services, sandboxes run **locally** with real microVM
isolation (libkrun: Hypervisor.framework on macOS, KVM on Linux, WHP on
Windows) — no account, no per-run cost, and the same OCI image runs identically
on your laptop and in prod.

## Tools

| tool | what it does |
| --- | --- |
| `start_sandbox` | Boot a microVM from an OCI image; returns its name |
| `run_command` | Run a shell command; returns stdout, stderr, exit code |
| `write_file` | Write text to a file in the sandbox |
| `read_file` | Read a file from the sandbox |
| `list_sandboxes` | List running/stopped sandboxes |
| `stop_sandbox` | Stop and (by default) delete a sandbox |

Filesystem changes and installed packages **persist** across `run_command`
calls until the sandbox is stopped.

## Prerequisite

Install smolvm and make sure `smolvm` is on your `PATH`:

```sh
curl -sSL https://smolmachines.com/install.sh | bash   # or brew/apt/dnf/pacman/nix — see the install docs
smolvm machine run --net --image alpine -- echo ok      # sanity check
```

## Configure your MCP client

Once published, clients run it with `npx` — no manual install:

**Claude Desktop** / **Claude Code** / **Cursor** (`mcpServers` block):

```json
{
  "mcpServers": {
    "smolvm": {
      "command": "npx",
      "args": ["-y", "smolvm-mcp"]
    }
  }
}
```

- Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS).
- Cursor: `.cursor/mcp.json` in your project (or global settings).
- Cline / Continue / other MCP clients: use the same `command` + `args`.

Optional environment:

```json
"env": {
  "SMOLVM_BIN": "/opt/homebrew/bin/smolvm",
  "SMOLVM_MCP_DEFAULT_IMAGE": "python:3.12-slim"
}
```

- `SMOLVM_BIN` — path to the smolvm binary (default: `smolvm` on `PATH`).
- `SMOLVM_MCP_DEFAULT_IMAGE` — image used when `start_sandbox` gets no `image`.

## Run from source (before it's on npm)

```sh
cd integrations/mcp
npm install && npm run build
node dist/index.js        # speaks MCP over stdio
```

Point your client's `command`/`args` at `node` + the absolute `dist/index.js`
path. A manual smoke test that drives the server against real microVMs lives in
`test-e2e.mjs` (`node test-e2e.mjs`).

## Example

> "Spin up a Python sandbox, write a script that computes the 20th Fibonacci
> number, and run it."

The agent calls `start_sandbox` → `write_file` → `run_command`, and reports the
output — all inside a throwaway microVM it then `stop_sandbox`es.

## License

Apache-2.0.
