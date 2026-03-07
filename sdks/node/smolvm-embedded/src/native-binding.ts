import { getPlatformPackageName } from "./platform-package.js";
import { getPlatformPackageRoot } from "./platform-package.js";
import { prepareNativeRuntime } from "./runtime-env.js";
import { resolve } from "node:path";

let nativeBinding: any;

export function loadNativeBinding(): any {
  if (nativeBinding) {
    return nativeBinding;
  }

  const packageName = getPlatformPackageName();
  const packageRoot = getPlatformPackageRoot();
  prepareNativeRuntime();

  try {
    nativeBinding = require(resolve(packageRoot, "native/index.js"));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Failed to load smolvm-embedded native binding from '${packageName}'. ` +
        `Original error: ${message}`
    );
  }

  return nativeBinding;
}
