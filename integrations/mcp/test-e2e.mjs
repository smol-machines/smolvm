import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const SB = "mcp-e2e";
const transport = new StdioClientTransport({
  command: "node",
  args: ["dist/index.js"],
  env: { ...process.env }, // inherit PATH so the server finds `smolvm`
});
const client = new Client({ name: "e2e", version: "1.0.0" }, { capabilities: {} });

const text = (r) => r.content.map((c) => c.text).join("\n");
const call = async (name, args = {}) => {
  const r = await client.callTool({ name, arguments: args });
  console.log(`\n### ${name}(${JSON.stringify(args)})  isError=${!!r.isError}`);
  console.log(text(r));
  return r;
};

await client.connect(transport);
try {
  const tools = await client.listTools();
  console.log("TOOLS:", tools.tools.map((t) => t.name).join(", "));

  await call("start_sandbox", { image: "alpine", name: SB });
  await call("run_command", { sandbox: SB, command: "echo hello-mcp && uname -s && exit 3" });
  await call("write_file", { sandbox: SB, path: "/root/note.txt", content: "written by mcp\nsecond line\n" });
  await call("read_file", { sandbox: SB, path: "/root/note.txt" });
  // prove write is visible to exec (same filesystem) and persistence works:
  await call("run_command", { sandbox: SB, command: "wc -l /root/note.txt && apk add --no-cache jq >/dev/null 2>&1 && jq --version" });
  await call("run_command", { sandbox: SB, command: "which jq" }); // persisted install
  await call("list_sandboxes", {});
  await call("read_file", { sandbox: SB, path: "/root/does-not-exist" }); // expect isError
  await call("stop_sandbox", { sandbox: SB });
  console.log("\nE2E COMPLETE");
} finally {
  await client.close();
}
