/**
 * Basic usage example for smolvm-embedded.
 *
 * Run with: npx tsx examples/basic.ts
 */

import {
  Sandbox,
  withSandbox,
  quickExec,
  quickRun,
} from "../src/index";

async function main() {
  console.log("=== smolvm-embedded examples ===\n");

  // 1. Quick one-liner execution
  console.log("1. quickExec — run a command in a temporary VM:");
  const hello = await quickExec(["echo", "Hello from a microVM!"]);
  console.log(`   stdout: ${hello.stdout.trim()}`);
  console.log(`   exit code: ${hello.exitCode}\n`);

  // 2. Quick container execution
  console.log("2. quickRun — run a command in an Alpine container:");
  const alpine = await quickRun("alpine:latest", [
    "cat",
    "/etc/os-release",
  ], {
    resources: { network: true },
  });
  console.log(`   stdout (first line): ${alpine.stdout.split("\n")[0]}`);
  console.log(`   exit code: ${alpine.exitCode}\n`);

  // 3. Managed sandbox lifecycle
  console.log("3. withSandbox — managed lifecycle:");
  await withSandbox({ name: "example-sandbox" }, async (sb) => {
    console.log(`   sandbox "${sb.name}" state: ${sb.state}`);

    const date = await sb.exec(["date", "+%Y-%m-%d"]);
    console.log(`   date: ${date.stdout.trim()}`);

    const uname = await sb.exec(["uname", "-a"]);
    console.log(`   uname: ${uname.stdout.trim()}`);
  });
  console.log("   sandbox cleaned up.\n");

  // 4. Full control
  console.log("4. Full control — create, use, delete:");
  const sb = await Sandbox.create({
    name: "example-full-control",
    resources: {
      cpus: 2,
      memoryMb: 1024,
      network: true,
    },
  });

  try {
    const nproc = await sb.exec(["nproc"]);
    console.log(`   vCPUs: ${nproc.stdout.trim()}`);

    // Pull an image and run in it
    const info = await sb.pullImage("alpine:latest");
    console.log(
      `   pulled: ${info.reference} (${(info.size / 1024 / 1024).toFixed(1)} MB)`
    );

    const result = await sb.run("alpine:latest", [
      "sh",
      "-c",
      "echo Running in Alpine on $(uname -m)",
    ]);
    console.log(`   container output: ${result.stdout.trim()}`);
  } finally {
    await sb.delete();
    console.log("   sandbox deleted.\n");
  }

  console.log("=== All examples completed ===");
}

main().catch(console.error);
