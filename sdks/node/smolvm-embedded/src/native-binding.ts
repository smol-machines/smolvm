import { getPlatformPackageName } from "./platform-package.js";
import { prepareNativeRuntime } from "./runtime-env.js";

let nativeBinding: any;

export function loadNativeBinding(): any {
  if (nativeBinding) {
    return nativeBinding;
  }

  const packageName = getPlatformPackageName();
  prepareNativeRuntime();

  try {
    nativeBinding = require(`${packageName}/native/index.js`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Failed to load smolvm-embedded native binding from '${packageName}'. ` +
        `Original error: ${message}`
    );
  }

  return nativeBinding;
}
