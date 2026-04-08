import { describe, expect, it } from "vitest";

import {
  Machine,
  NotFoundError,
  withMachine,
} from "../src/index.js";

import { uniqueName } from "./helpers.js";

describe("embedded sdk lifecycle", () => {
  it("supports persistent create, start, reconnect, stop, and restart", async () => {
    const name = uniqueName("persist");
    const machine = await Machine.create({ name, persistent: true });

    try {
      expect(machine.isStarted).toBe(false);
      expect(machine.isRunning).toBe(false);
      expect(machine.state).toBe("stopped");
      expect(machine.pid).toBeNull();

      await machine.start();

      expect(machine.isStarted).toBe(true);
      expect(machine.isRunning).toBe(true);
      expect(machine.state).toBe("running");
      expect(machine.pid).toEqual(expect.any(Number));

      const connected = await Machine.connect(name);
      expect(connected.name).toBe(name);
      expect(connected.isRunning).toBe(true);

      const result = await connected.exec(["echo", "connected"]);
      expect(result.stdout.trim()).toBe("connected");

      await machine.stop();

      expect(machine.isStarted).toBe(false);
      expect(machine.isRunning).toBe(false);
      expect(machine.state).toBe("stopped");
      expect(machine.pid).toBeNull();

      await machine.start();
      expect(machine.state).toBe("running");
    } finally {
      await machine.delete().catch(() => {
        // Best-effort cleanup for persistent machines.
      });
    }
  });

  it("withMachine cleans up ephemeral machines after the callback exits", async () => {
    const name = uniqueName("cleanup");

    const result = await withMachine({ name }, async (machine) => {
      expect(machine.state).toBe("running");
      return machine.exec(["echo", "ephemeral"]);
    });

    expect(result.stdout.trim()).toBe("ephemeral");
    await expect(Machine.connect(name)).rejects.toBeInstanceOf(NotFoundError);
  });
});
