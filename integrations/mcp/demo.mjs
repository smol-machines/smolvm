// Show-HN demo: an agent gets a real, isolated computer via the smolvm MCP server.
// Drives the server exactly like an MCP client (Claude Desktop / Cursor) would.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const SB = "demo";
const client = new Client({ name: "demo", version: "1.0.0" }, { capabilities: {} });
await client.connect(new StdioClientTransport({
  command: "node", args: ["dist/index.js"], env: { ...process.env },
}));

const t = (r) => r.content.map((c) => c.text).join("\n");
async function tool(narrate, name, args) {
  process.stdout.write(`\n\x1b[1;36m${narrate}\x1b[0m\n\x1b[2m  → ${name}(${JSON.stringify(args)})\x1b[0m\n`);
  const r = await client.callTool({ name, arguments: args });
  process.stdout.write(t(r).split("\n").map((l) => "    " + l).join("\n") + "\n");
  return r;
}

const SCRIPT = `import json, urllib.request
top = json.load(urllib.request.urlopen("https://hacker-news.firebaseio.com/v0/topstories.json"))[:5]
for i, id in enumerate(top, 1):
    s = json.load(urllib.request.urlopen(f"https://hacker-news.firebaseio.com/v0/item/{id}.json"))
    print(f"{i}. [{s.get('score','?'):>4}] {s['title']}")
`;

process.stdout.write("\x1b[1m🖥️  smolvm MCP — give an AI agent its own computer\x1b[0m\n");
try {
  await tool("Spin up a fresh, isolated microVM (sub-second boot)", "start_sandbox", { image: "python:3.12-alpine", name: SB });
  await tool("Install a package — it persists across calls", "run_command", { sandbox: SB, command: "pip install --quiet --break-system-packages requests >/dev/null 2>&1; echo installed requests $(python -c 'import requests;print(requests.__version__)')" });
  await tool("Write a program into the sandbox", "write_file", { sandbox: SB, path: "/root/top.py", content: SCRIPT });
  await tool("Run it — real network egress from inside the VM", "run_command", { sandbox: SB, command: "python /root/top.py" });
  await tool("State persists: the file & package are still here", "run_command", { sandbox: SB, command: "ls -1 /root/top.py && python -c 'import requests; print(\"requests\", requests.__version__)'" });
  await tool("Throw the whole computer away", "stop_sandbox", { sandbox: SB });
  process.stdout.write("\n\x1b[1;32m✓ Done — one config line, a real isolated computer, gone without a trace.\x1b[0m\n");
} finally {
  await client.close();
}
