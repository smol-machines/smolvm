# SmolVM Embedded SDKs

## Overview

This directory holds language bindings that embed `smolvm` directly into the
host process instead of talking to the API server.

Layout convention:

- `sdks/scripts/` contains shared helpers used by all embedded SDKs.
- `sdks/node/` contains the Node.js embedded SDK and its internal platform
  packages.
- Future embedded SDKs should live in sibling directories such as `sdks/go/`, and `sdks/c/`.

Bundled native library rule:

- Embedded SDKs ship package-local copies of `libkrun` and `libkrunfw`.
- Those libraries are always staged from the `smolvm` repo's bundled `./lib`
  directory, not from Homebrew or other system locations.
- Shared helpers in `sdks/scripts/` should be used to copy the current host's
  libraries into each SDK package's `lib/` directory.

Current status:

- **The embedded SDK currently creates a machine without involving the DB storage.  
This means machines created via the embedded SDK are not visible via the smolvm CLI.  
This is a bug, and we are actively working on a fix.**

## Hint

This directory contains the **embedded SDKs** explicitly:  
That means those that run in the same process as smolvm itself. 
There is no external daemon to run, making it easier and safer to script. 

For the currently only other SDK - that follows the traditional approach with a separate process - see [here.](https://github.com/smol-machines/smolvm-sdk) 

## Development

### Build

Install the Node workspace dependencies, then run the repo-level embedded SDK
build. That flow compiles `smolvm-napi`, stages the bundled `libkrun` and
`libkrunfw` libraries into the current-host platform package, and builds the
public `smolvm-embedded` package.

```bash
cd sdks/node
npm install

cd ../..
./scripts/build-embedded-node.sh
```

If you are already inside `sdks/node`, `npm run build` rebuilds the current-host
platform package plus the public package without leaving the workspace.

### Test

Use the Node workspace for the main verification flow:

```bash
cd sdks/node
npm test
npm run --workspace smolvm-embedded test:integration
npm run smoke
npm exec --workspace smolvm-embedded tsx examples/basic.ts
npm exec --workspace smolvm-embedded tsx examples/create-and-start.ts
```

- `npm test` rebuilds the current platform package and runs the
  `smolvm-embedded` Vitest suite.
- `npm run --workspace smolvm-embedded test:integration` runs only the embedded
  SDK integration tests under `sdks/node/smolvm-embedded/integration-tests/`.
- `npm run smoke` performs the fresh-install validation from the PR by packing
  the public package plus the host platform package, installing them into a
  temporary project, and checking that the native binding loads correctly.
- `npm exec --workspace smolvm-embedded tsx examples/basic.ts` runs the local
  integration example that exercises `quickExec`, container execution, managed
  machine lifecycle, and explicit machine cleanup.
- `npm exec --workspace smolvm-embedded tsx examples/create-and-start.ts`
  creates `created-by-node`, explicitly starts it, and intentionally leaves it
  running so it can be inspected with `smolvm machine status --name
  created-by-node` or `smolvm machine ls`.

### Manual Fresh-Install Check

If you want to test from a freshly installed
`smolvm-embedded` Node SDK" flow by hand, pack both the public package and the
current-host platform package, then install them into a throwaway project.

Supported platform package directories:

- `smolvm-embedded-darwin-arm64`
- `smolvm-embedded-darwin-x64`
- `smolvm-embedded-linux-arm64-gnu`
- `smolvm-embedded-linux-x64-gnu`

Example using the current-host package name in `PLATFORM_PKG`:

```bash
TMP_PACK_DIR="$(mktemp -d /tmp/smolvm-embedded-pack.XXXXXX)"
TMP_PROJECT_DIR="$(mktemp -d /tmp/smolvm-embedded-project.XXXXXX)"
PLATFORM_PKG="smolvm-embedded-darwin-arm64"

cd sdks/node/"$PLATFORM_PKG"
npm pack --pack-destination "$TMP_PACK_DIR"

cd ../smolvm-embedded
npm pack --pack-destination "$TMP_PACK_DIR"

cd "$TMP_PROJECT_DIR"
npm init -y
npm install typescript tsx @types/node
npm install \
  "$TMP_PACK_DIR"/smolvm-embedded-0.1.0.tgz \
  "$TMP_PACK_DIR"/"$PLATFORM_PKG"-0.1.0.tgz
```

Create `index.ts` in the temporary project:

```ts
import { quickExec, withMachine } from "smolvm-embedded";

async function main() {
  const hello = await quickExec(["echo", "hello from smolvm-embedded"]);
  console.log("quickExec stdout:", hello.stdout.trim());
  console.log("quickExec exitCode:", hello.exitCode);

  await withMachine({ name: "demo-machine" }, async (sb) => {
    const result = await sb.exec(["uname", "-a"]);
    console.log("machine uname:", result.stdout.trim());
  });
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
```

Run the smoke program:

```bash
cd "$TMP_PROJECT_DIR"
npx tsx index.ts
```

Alternative `index.ts` that does not use `quickExec` and does not delete the VM:

```ts
import { Machine } from "smolvm-embedded";

async function main() {
  const machine = await Machine.create({
    name: "created-by-node",
    persistent: true,
  });

  console.log("created machine:", machine.name);
  console.log("state before start:", machine.state);

  await machine.start();

  console.log("state after start:", machine.state);
  console.log("is running:", machine.isRunning);
  console.log("pid:", machine.pid ?? "unknown");
  console.log("VM was not deleted.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
```
