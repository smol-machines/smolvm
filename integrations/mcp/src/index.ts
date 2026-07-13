#!/usr/bin/env node
/**
 * smolvm MCP server — gives an AI agent its own isolated microVM.
 *
 * Exposes smolvm as Model Context Protocol tools (start/stop a sandbox, run
 * shell commands, read/write files, list sandboxes). It shells out to the
 * `smolvm` CLI, so it works with any smolvm install (brew / apt / dnf / pacman /
 * nix / curl) — no daemon, no extra SDK. Each sandbox is a real per-workload
 * microVM (libkrun: Hypervisor.framework on macOS, KVM on Linux, WHP on
 * Windows) that boots in well under a second.
 */
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const SMOLVM_BIN = process.env.SMOLVM_BIN || "smolvm";
const DEFAULT_IMAGE = process.env.SMOLVM_MCP_DEFAULT_IMAGE || "python:3.12-slim";
const MAX_OUTPUT = 100_000; // cap stdout/stderr returned to the model (chars)
const MAX_WRITE = 512 * 1024; // cap file-write payload (bytes, pre-base64)

// Prefer bash (agents emit bashisms: `&>`, pipefail, ...) but fall back to sh on
// minimal images that ship no bash. The user's command runs as "$1".
const SHELL_WRAPPER =
  'if command -v bash >/dev/null 2>&1; then exec bash -c "$1"; else exec sh -c "$1"; fi';

interface Ran {
  stdout: string;
  stderr: string;
  code: number;
  spawnError?: string;
}

/** Run the smolvm CLI. Never rejects — CLI/exec failures come back as fields. */
function smol(args: string[], opts: { timeoutMs?: number } = {}): Promise<Ran> {
  return new Promise((resolve) => {
    execFile(
      SMOLVM_BIN,
      args,
      { timeout: opts.timeoutMs ?? 0, maxBuffer: 64 * 1024 * 1024, encoding: "utf8" },
      (err, stdout, stderr) => {
        const e = err as (NodeJS.ErrnoException & { code?: number | string }) | null;
        if (e && (e.code === "ENOENT" || e.code === "EACCES")) {
          resolve({
            stdout: "",
            stderr: "",
            code: -1,
            spawnError: `Could not run '${SMOLVM_BIN}'. Install smolvm (https://github.com/smol-machines/smolvm) or set SMOLVM_BIN.`,
          });
          return;
        }
        // execFile sets err on non-zero exit; the numeric exit code is on err.code.
        const code = e && typeof e.code === "number" ? e.code : err ? 1 : 0;
        resolve({ stdout: stdout ?? "", stderr: stderr ?? "", code });
      },
    );
  });
}

/** DNS-safe machine name: lower, non-alnum -> single hyphen, no leading/trailing. */
function safeName(input?: string): string {
  const base = input && input.trim() ? input : `mcp-${randomBytes(4).toString("hex")}`;
  let s = base
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 60);
  if (!s) s = `mcp-${randomBytes(4).toString("hex")}`;
  return s;
}

function clip(s: string): string {
  if (s.length <= MAX_OUTPUT) return s;
  return s.slice(0, MAX_OUTPUT) + `\n… [truncated ${s.length - MAX_OUTPUT} chars]`;
}

const ok = (text: string) => ({ content: [{ type: "text" as const, text }] });
const fail = (text: string) => ({ content: [{ type: "text" as const, text }], isError: true });

const server = new McpServer({ name: "smolvm", version: "0.1.0" });

server.tool(
  "start_sandbox",
  "Start an isolated microVM sandbox from an OCI image and return its name. Filesystem changes and installed packages persist across run_command calls until the sandbox is stopped. Use this before run_command / write_file / read_file.",
  {
    image: z
      .string()
      .optional()
      .describe(`OCI image to boot, e.g. "python:3.12-slim", "ubuntu:24.04", "node:22". Default: ${DEFAULT_IMAGE}`),
    name: z
      .string()
      .optional()
      .describe("Optional sandbox name; auto-generated if omitted. Reuse it in later calls."),
  },
  async ({ image, name }) => {
    const img = image?.trim() || DEFAULT_IMAGE;
    const n = safeName(name);
    const created = await smol(["machine", "create", "--net", "--image", img, "--name", n]);
    if (created.spawnError) return fail(created.spawnError);
    if (created.code !== 0) return fail(`Failed to create sandbox '${n}':\n${created.stderr || created.stdout}`);
    const started = await smol(["machine", "start", "--name", n]);
    if (started.code !== 0) {
      await smol(["machine", "delete", "--name", n, "--force"]);
      return fail(`Failed to start sandbox '${n}':\n${started.stderr || started.stdout}`);
    }
    return ok(`Sandbox '${n}' is running (image ${img}). Use run_command with sandbox="${n}".`);
  },
);

server.tool(
  "run_command",
  "Run a shell command inside a sandbox and return stdout, stderr, and the exit code. The command runs under bash when available (falls back to sh). State persists between calls.",
  {
    sandbox: z.string().describe("Sandbox name returned by start_sandbox."),
    command: z.string().describe('Shell command, e.g. "python3 app.py" or "pip install requests && python3 -c \'import requests\'".'),
    workdir: z.string().optional().describe("Working directory inside the sandbox."),
    env: z.record(z.string()).optional().describe("Extra environment variables."),
    timeout_seconds: z.number().int().positive().optional().describe("Kill the command after this many seconds."),
  },
  async ({ sandbox, command, workdir, env, timeout_seconds }) => {
    const args = ["machine", "exec", "--name", safeName(sandbox)];
    if (workdir) args.push("-w", workdir);
    for (const [k, v] of Object.entries(env ?? {})) args.push("-e", `${k}=${v}`);
    if (timeout_seconds) args.push("--timeout", `${timeout_seconds}s`);
    args.push("--", "/bin/sh", "-c", SHELL_WRAPPER, "sh", command);
    const r = await smol(args, { timeoutMs: timeout_seconds ? (timeout_seconds + 15) * 1000 : 0 });
    if (r.spawnError) return fail(r.spawnError);
    const body =
      `exit code: ${r.code}\n` +
      `--- stdout ---\n${clip(r.stdout) || "(empty)"}\n` +
      `--- stderr ---\n${clip(r.stderr) || "(empty)"}`;
    return { content: [{ type: "text" as const, text: body }], isError: r.code !== 0 };
  },
);

server.tool(
  "write_file",
  "Write text content to a file inside the sandbox (creating parent directories). The file is visible to run_command.",
  {
    sandbox: z.string().describe("Sandbox name."),
    path: z.string().describe("Absolute path inside the sandbox, e.g. /root/app.py."),
    content: z.string().describe("File content (UTF-8 text)."),
  },
  async ({ sandbox, path, content }) => {
    const bytes = Buffer.byteLength(content, "utf8");
    if (bytes > MAX_WRITE) return fail(`Content too large (${bytes} bytes; limit ${MAX_WRITE}). Split the write or fetch the data inside the sandbox.`);
    const b64 = Buffer.from(content, "utf8").toString("base64");
    // base64 passed as argv ($1); path as $2. Decoded in the same filesystem exec sees.
    const script = 'mkdir -p "$(dirname "$2")" && printf %s "$1" | base64 -d > "$2"';
    const r = await smol(["machine", "exec", "--name", safeName(sandbox), "--", "/bin/sh", "-c", script, "sh", b64, path]);
    if (r.spawnError) return fail(r.spawnError);
    if (r.code !== 0) return fail(`write_file failed:\n${r.stderr || r.stdout}`);
    return ok(`Wrote ${bytes} bytes to ${path} in '${sandbox}'.`);
  },
);

server.tool(
  "read_file",
  "Read a text file from inside the sandbox and return its content.",
  {
    sandbox: z.string().describe("Sandbox name."),
    path: z.string().describe("Absolute path inside the sandbox."),
  },
  async ({ sandbox, path }) => {
    const r = await smol(["machine", "exec", "--name", safeName(sandbox), "--", "/bin/sh", "-c", 'base64 < "$1"', "sh", path]);
    if (r.spawnError) return fail(r.spawnError);
    if (r.code !== 0) return fail(`read_file failed (does ${path} exist?):\n${r.stderr || r.stdout}`);
    const decoded = Buffer.from(r.stdout, "base64").toString("utf8");
    return ok(clip(decoded));
  },
);

server.tool(
  "list_sandboxes",
  "List all smolvm sandboxes on this machine with their state.",
  {},
  async () => {
    const r = await smol(["machine", "ls", "--json"]);
    if (r.spawnError) return fail(r.spawnError);
    if (r.code !== 0) return fail(`list failed:\n${r.stderr || r.stdout}`);
    try {
      const parsed = JSON.parse(r.stdout);
      const rows = (Array.isArray(parsed) ? parsed : parsed.machines ?? []).map((m: any) => ({
        name: m.name,
        state: m.state ?? m.status,
        image: m.image,
      }));
      return ok(rows.length ? JSON.stringify(rows, null, 2) : "No sandboxes.");
    } catch {
      return ok(r.stdout.trim() || "No sandboxes.");
    }
  },
);

server.tool(
  "stop_sandbox",
  "Stop a sandbox and (by default) delete it, freeing its resources. Set keep=true to only stop it so it can be restarted later.",
  {
    sandbox: z.string().describe("Sandbox name."),
    keep: z.boolean().optional().describe("If true, stop but do not delete (can be restarted). Default false: delete."),
  },
  async ({ sandbox, keep }) => {
    const n = safeName(sandbox);
    await smol(["machine", "stop", "--name", n]);
    if (keep) return ok(`Sandbox '${n}' stopped (kept; restart with start_sandbox-equivalent or the CLI).`);
    const del = await smol(["machine", "delete", "--name", n, "--force"]);
    if (del.spawnError) return fail(del.spawnError);
    if (del.code !== 0) return fail(`Stopped but delete failed:\n${del.stderr || del.stdout}`);
    return ok(`Sandbox '${n}' stopped and deleted.`);
  },
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // stderr is safe for logs (stdout is the MCP channel).
  process.stderr.write("smolvm MCP server ready (stdio).\n");
}

main().catch((e) => {
  process.stderr.write(`smolvm MCP server fatal: ${e?.stack || e}\n`);
  process.exit(1);
});
