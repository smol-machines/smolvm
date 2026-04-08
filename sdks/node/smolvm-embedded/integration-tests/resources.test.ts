import { describe, expect, it } from "vitest";

import { withMachine } from "../src/index.js";

import { uniqueName } from "./helpers.js";

describe("embedded sdk resource configuration", () => {
  it("applies cpu, memory, and overlay sizing", async () => {
    await withMachine(
      {
        name: uniqueName("res"),
        resources: {
          cpus: 2,
          memoryMb: 1024,
          overlayGib: 4,
        },
      },
      async (machine) => {
        const cpuResult = await machine.exec(["nproc"]);
        expect(cpuResult.exitCode).toBe(0);
        expect(Number.parseInt(cpuResult.stdout.trim(), 10)).toBe(2);

        const memResult = await machine.exec([
          "sh",
          "-lc",
          "awk '/MemTotal/ { print $2 }' /proc/meminfo",
        ]);
        expect(memResult.exitCode).toBe(0);
        expect(Number.parseInt(memResult.stdout.trim(), 10)).toBeGreaterThan(
          900_000
        );

        const overlayResult = await machine.exec([
          "sh",
          "-lc",
          "df -m / | tail -1 | awk '{print $2}'",
        ]);
        expect(overlayResult.exitCode).toBe(0);
        expect(
          Number.parseInt(overlayResult.stdout.trim(), 10)
        ).toBeGreaterThan(3_000);
      }
    );
  });
});
