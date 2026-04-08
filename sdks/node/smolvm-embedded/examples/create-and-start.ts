/**
 * Create and start a named microVM from the embedded Node SDK.
 *
 * Run with: npx tsx examples/create-and-start.ts
 *
 * This intentionally does not delete the VM. It leaves `created-by-node`
 * running so it can be inspected from the smolvm CLI.
 */

import { Machine } from "../src/index";

async function main() {
  const machine = await Machine.create({
    name: "created-by-node",
    persistent: true,
  });

  console.log(`created machine: ${machine.name}`);
  console.log(`state before start: ${machine.state}`);

  await machine.start();

  console.log(`state after start: ${machine.state}`);
  console.log(`is running: ${machine.isRunning}`);
  console.log(`pid: ${machine.pid ?? "unknown"}`);
  console.log("");
  console.log("VM was not deleted.");
  console.log("Inspect it with:");
  console.log("  smolvm machine status --name created-by-node");
  console.log("  smolvm machine ls");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
