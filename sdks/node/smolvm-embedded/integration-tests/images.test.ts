import { describe, expect, it } from "vitest";

import {
  quickExec,
  quickRun,
  withMachine,
} from "../src/index.js";

import { uniqueName } from "./helpers.js";

describe("embedded sdk one-shot and image workflows", () => {
  it("quickExec runs one-shot commands in a temporary VM", async () => {
    const result = await quickExec(["sh", "-lc", "echo quick && uname -s"]);

    expect(result.assertSuccess().stdout).toContain("quick");
  });

  it("pulls, lists, and runs OCI images with env and workdir", async () => {
    await withMachine(
      {
        name: uniqueName("images"),
        resources: { network: true },
      },
      async (machine) => {
        const image = await machine.pullImage("alpine:latest");
        expect(image.reference).toContain("alpine");
        expect(image.digest).toMatch(/^sha256:/);
        expect(image.size).toBeGreaterThan(0);

        const images = await machine.listImages();
        expect(images.some((entry) => entry.reference.includes("alpine"))).toBe(
          true
        );

        const result = await machine.run(
          "alpine:latest",
          [
            "sh",
            "-lc",
            'echo "$RUN_VALUE" && pwd && grep "^NAME=" /etc/os-release',
          ],
          {
            env: { RUN_VALUE: "from-run" },
            workdir: "/tmp",
          }
        );

        expect(result.exitCode).toBe(0);
        expect(result.stdout).toContain("from-run");
        expect(result.stdout).toContain("/tmp");
        expect(result.stdout).toContain("Alpine");
      }
    );
  });

  it("quickRun executes container commands without explicit lifecycle management", async () => {
    const result = await quickRun(
      "alpine:latest",
      [
        "sh",
        "-lc",
        'echo quick-run && grep "^NAME=" /etc/os-release',
      ],
      {
        resources: { network: true },
      }
    );

    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain("quick-run");
    expect(result.stdout).toContain("Alpine");
  });
});
