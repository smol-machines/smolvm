/**
 * Runtime path setup for bundled embedded SDK assets.
 *
 * The addon itself can load `libkrun` via rpath, but the Rust runtime still
 * needs explicit package-relative paths for bundled assets such as
 * `libkrunfw`. Configure those paths directly in Rust instead of mutating
 * process-global environment variables.
 */

import { existsSync } from "node:fs";
import { resolve } from "node:path";

import { getPlatformPackageRoot } from "./platform-package.js";

export function configureNativeRuntime(binding: any): void {
  if (typeof binding?.configureEmbeddedPaths !== "function") {
    return;
  }

  const packageRoot = getPlatformPackageRoot();
  const bundledLibDir = resolve(packageRoot, "lib");

  binding.configureEmbeddedPaths({
    libDir: existsSync(bundledLibDir) ? bundledLibDir : undefined,
  });
}
